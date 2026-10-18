/**
 * 逆向模式 · 控制台（Host 半侧）
 *
 * 为浏览器半侧提供一条 Package 私有的 HTTP 桥接 `POST /reverse/api`：
 *   · 样本库 / 结论 / 证据链 / 报告的 op 转交 `ctx.reverse`；
 *   · 技能目录 op 直接读 `ctx.skills`（技能由 DSH 原生 skill 体系管理，控制台只浏览）；
 *   · 工具链探测 op 在本机真实探测 PATH（与 reverse_preflight 同一份逻辑）。
 *
 * 为什么走 webServer 而不是 typert：本包与 store 都刻意零外部依赖
 * （profile 下解析不到 node_modules），具名路由是最小且稳定的接缝。
 * 跨源请求由 Origin/Host 校验挡住（同源 POST 才放行）。
 */
import { join } from 'node:path'
import { homedir } from 'node:os'
import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dispatch, dispatchAsync } from './dispatch.js'
import { ROLE_TITLES, PHASE_ORDER, PHASE_TITLES, PLATFORM_TITLES } from './store-core.js'

/** Cordis 插件名。 */
export const name = 'dsh-purge-reverse-ui'

/** 需要 webServer（路由）与 reverse（数据服务）。与红队 ui 的 inject 对齐。 */
export const inject = ['reverse', 'webServer']

/** 路由前缀。 */
const API_PATH = '/reverse/api'

function dshHomeOf() {
  if (process.env.DSH_HOME) return process.env.DSH_HOME
  return join(homedir(), '.dsh')
}

/** 本包自带技能目录候选（符号链接 / 空格路径下多路探测）。 */
function bundledSkillRoots() {
  const roots = []
  const push = (p) => {
    if (!p) return
    try { if (existsSync(p) && !roots.includes(p)) roots.push(p) } catch { /* 忽略 */ }
  }
  try {
    push(new URL('../../skills/reverse', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'))
  } catch { /* 忽略 */ }
  push(join(dshHomeOf(), 'reverse', 'skills'))
  push(join(dshHomeOf(), 'skills'))
  return roots
}

/** 读一个 SKILL.md 的 frontmatter（name / description）。 */
function readSkillMeta(path) {
  try {
    const raw = readFileSync(path, 'utf8')
    const m = /^---\s*\n([\s\S]*?)\n---/.exec(raw)
    const meta = { name: '', description: '', enabled: null }
    if (m) {
      for (const line of m[1].split('\n')) {
        const kv = /^([A-Za-z_]+):\s*(.*)$/.exec(line)
        if (!kv) continue
        const [, k, v] = kv
        if (k === 'name') meta.name = v.trim()
        else if (k === 'description') meta.description = v.trim()
        else if (k === 'enabled') meta.enabled = v.trim() !== 'false'
      }
    }
    if (!meta.name) {
      const title = /^#\s+(.+)$/m.exec(raw)
      meta.name = title ? title[1].trim() : path
    }
    meta.bytes = Buffer.byteLength(raw)
    return meta
  } catch {
    return null
  }
}

/** 技能目录（跨所有候选根聚合，同名取先出现的）。 */
function skillCatalog() {
  const seen = new Map()
  for (const root of bundledSkillRoots()) {
    let entries = []
    try { entries = readdirSync(root, { withFileTypes: true }) } catch { continue }
    for (const e of entries) {
      if (!e.isDirectory()) continue
      if (seen.has(e.name)) continue
      const skillMd = join(root, e.name, 'SKILL.md')
      if (!existsSync(skillMd)) continue
      const meta = readSkillMeta(skillMd)
      if (!meta) continue
      seen.set(e.name, {
        dir: e.name,
        name: meta.name,
        description: meta.description,
        enabled: meta.enabled !== false,
        bytes: meta.bytes,
        path: skillMd,
        root,
      })
    }
  }
  return Array.from(seen.values()).sort((a, b) => a.dir.localeCompare(b.dir))
}

/** 工具链快速探测（只查关键几项，面板刷新不跑全量）。 */
function quickToolchain() {
  const which = (bin) => {
    for (const dir of String(process.env.PATH || '').split(process.platform === 'win32' ? ';' : ':')) {
      if (!dir) continue
      for (const cand of [bin, bin + '.exe', bin + '.bat']) {
        const full = join(dir, cand)
        try { if (existsSync(full)) return full } catch { /* 忽略 */ }
      }
    }
    return null
  }
  const probes = [
    ['java', 'Java 运行时'],
    ['python', 'Python'],
    ['jadx', 'APK 反编译'],
    ['apktool', 'APK 拆包'],
    ['frida', '动态 Hook'],
    ['adb', 'Android 设备'],
    ['ghidraRun', 'Ghidra'],
    ['r2', 'radare2'],
    ['ida64', 'IDA Pro'],
    ['x64dbg', 'Windows 调试'],
    ['diec', 'Detect It Easy'],
    ['upx', 'UPX 脱壳'],
    ['mitmproxy', 'HTTPS 抓包'],
  ]
  return probes.map(([bin, label]) => ({ tool: bin, label, path: which(bin) }))
}

/** 同源校验：只放行同源 POST。 */
function sameOrigin(req) {
  const origin = req.headers?.origin
  if (!origin) return true
  try {
    const o = new URL(origin)
    const host = req.headers?.host
    return !host || o.host === host
  } catch {
    return false
  }
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(payload),
  })
  res.end(payload)
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = []
    let size = 0
    req.on('data', (c) => {
      size += c.length
      if (size > 8 * 1024 * 1024) {
        reject(new Error('请求体过大'))
        try { req.destroy() } catch { /* 忽略 */ }
        return
      }
      chunks.push(c)
    })
    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf8')
      if (!raw.trim()) return resolve({})
      try { resolve(JSON.parse(raw)) } catch (e) { reject(new Error('JSON 解析失败: ' + e.message)) }
    })
    req.on('error', reject)
  })
}

/**
 * @param ctx - 插件上下文。
 */
export function apply(ctx) {
  let store
  try { store = ctx.reverse } catch { store = undefined }
  if (!store) {
    try { store = ctx.get('reverse') } catch { store = undefined }
  }

  const handler = async (req, res) => {
    if (!sameOrigin(req)) {
      sendJson(res, 403, { ok: false, error: '跨源请求被拒绝' })
      return
    }
    if (req.method !== 'POST') {
      sendJson(res, 405, { ok: false, error: '只接受 POST' })
      return
    }
    if (!store) {
      sendJson(res, 503, { ok: false, error: 'ctx.reverse 不可用（reverse/store 未加载）' })
      return
    }

    let body
    try { body = await readBody(req) } catch (e) {
      sendJson(res, 400, { ok: false, error: e.message })
      return
    }

    const op = String(body.op || 'digest')
    try {
      /* 面板专属 op 在这里处理，其余转交 dispatch */
      if (op === 'console') {
        const digest = dispatch(store, 'digest')
        sendJson(res, 200, {
          ...digest,
          skills: skillCatalog(),
          toolchain: quickToolchain(),
          plugin: store.plugin || null,
          roles: Object.entries(ROLE_TITLES).map(([code, title]) => ({ code, title })),
          phases: PHASE_ORDER.map((code) => ({ code, title: PHASE_TITLES[code] })),
          platforms: Object.entries(PLATFORM_TITLES).map(([code, title]) => ({ code, title })),
          root: store.root,
        })
        return
      }

      if (op === 'skill_read') {
        const dir = String(body.dir || '')
        if (!dir || dir.includes('..') || dir.includes('/') || dir.includes('\\')) {
          sendJson(res, 400, { ok: false, error: '技能名非法' })
          return
        }
        const hit = skillCatalog().find((s) => s.dir === dir)
        if (!hit) {
          sendJson(res, 404, { ok: false, error: '技能不存在: ' + dir })
          return
        }
        const text = readFileSync(hit.path, 'utf8')
        sendJson(res, 200, { ok: true, dir: hit.dir, path: hit.path, text })
        return
      }

      if (op === 'toolchain') {
        sendJson(res, 200, { ok: true, toolchain: quickToolchain(), host: { platform: process.platform, arch: process.arch } })
        return
      }

      if (op === 'platform_info') {
        let mac = ''
        try {
          const out = execFileSync(
            process.platform === 'win32' ? 'powershell' : 'sh',
            process.platform === 'win32'
              ? ['-NoProfile', '-Command', '(Get-CimInstance Win32_Processor).Name']
              : ['-c', 'uname -m'],
            { timeout: 8000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
          )
          mac = String(out).trim().slice(0, 120)
        } catch { /* 取不到不算错 */ }
        sendJson(res, 200, {
          ok: true,
          host: { platform: process.platform, arch: process.arch, cpu: mac, node: process.version },
        })
        return
      }

      const result = await dispatchAsync(store, op, body)
      sendJson(res, 200, result)
    } catch (error) {
      sendJson(res, 500, {
        ok: false,
        error: error?.message || String(error),
        op,
      })
    }
  }

  /* webServer 的注册方式随版本变化：具名路由优先，退回通用中间件。 */
  try {
    if (typeof ctx.webServer?.route === 'function') {
      ctx.effect(() => ctx.webServer.route(API_PATH, handler))
    } else if (typeof ctx.webServer?.use === 'function') {
      ctx.effect(() => ctx.webServer.use((req, res, next) => {
        const url = String(req.url || '')
        if (!url.startsWith(API_PATH)) {
          if (typeof next === 'function') next()
          return
        }
        handler(req, res)
      }))
    } else {
      ctx.logger?.warn?.('[dsh-purge/reverse/ui] webServer 无可用注册接口，控制台桥接未挂上')
    }
  } catch (error) {
    ctx.logger?.warn?.('[dsh-purge/reverse/ui] 路由注册失败：' + (error?.message || String(error)))
  }
}

export { dispatch, dispatchAsync }
