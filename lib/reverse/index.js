/**
 * 逆向模式 · 自举（host 半侧）
 *
 * 负责：
 *   1. 首次把 `presets/reverse` 落到 `$DSH_HOME/.agent-presets/reverse/`
 *   2. 随包技能落到 `$DSH_HOME/reverse/skills`（预设用 dshHomePath 指向它）
 *   3. 角色稿落到 `$DSH_HOME/reverse/agents`（子会话按 reverseRole 读取）
 *   4. 已有用户预设时只补缺，不整份覆盖
 *   5. **把预设动态声明进 `agentPresets` registry**（模式下拉只认 register()，
 *      扫磁盘 `.agent-presets` 不会出现在下拉里 —— 这是"装了但看不到模式"的根因）
 */
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, copyFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { readPresetDefinition } from './preset-composition.js'

/** Cordis 插件名。 */
export const name = 'dsh-purge-reverse'

/** 与红队一致：不硬依赖 agentPresets，就绪后软取并声明。 */
export const inject = []

/** 模式下拉里的预设 id（目录名 / registry id）。 */
export const REVERSE_PRESET_ID = 'reverse'

/** 插件根目录（lib/reverse → 上两级）。 */
export function packagePaths() {
  const root = fileURLToPath(new URL('../..', import.meta.url))
  return {
    root,
    presets: join(root, 'presets'),
    presetDir: join(root, 'presets', 'reverse'),
    skills: join(root, 'skills', 'reverse'),
    agents: join(root, 'agents'),
  }
}

/** DSH_HOME。 */
function dshHome() {
  return process.env.DSH_HOME || join(homedir(), '.dsh')
}

/** 逆向数据目录。 */
export function reverseDataDir() {
  return join(dshHome(), 'reverse')
}

/** 用户预设根。 */
export function userPresetRoot() {
  return join(dshHome(), '.agent-presets', REVERSE_PRESET_ID)
}

/** 递归复制（目标已存在且较新时跳过，除非 force）。 */
function copyDirOver(src, dst, { force = false } = {}) {
  mkdirSync(dst, { recursive: true })
  let copied = 0
  for (const entry of readdirSync(src, { withFileTypes: true })) {
    const s = join(src, entry.name)
    const d = join(dst, entry.name)
    if (entry.isDirectory()) {
      copied += copyDirOver(s, d, { force })
      continue
    }
    if (!entry.isFile()) continue
    if (!force && existsSync(d)) continue
    copyFileSync(s, d)
    copied += 1
  }
  return copied
}

/** 把随包技能落到 $DSH_HOME/reverse/skills（用户改过的不覆盖）。 */
export function installBundledSkills({ force = false } = {}) {
  const p = packagePaths()
  if (!existsSync(p.skills)) return { ok: false, copied: 0, target: null, reason: '包内没有 skills/reverse' }
  const target = join(reverseDataDir(), 'skills')
  try {
    const copied = copyDirOver(p.skills, target, { force })
    return { ok: true, copied, target }
  } catch (error) {
    return { ok: false, copied: 0, target, reason: error?.message || String(error) }
  }
}

/** 把角色稿落到 $DSH_HOME/reverse/agents（子会话按 reverseRole 读）。 */
export function installRoleFiles({ force = false } = {}) {
  const p = packagePaths()
  if (!existsSync(p.agents)) return { ok: false, copied: 0, target: null, reason: '包内没有 agents/' }
  const target = join(reverseDataDir(), 'agents')
  try {
    const copied = copyDirOver(p.agents, target, { force })
    return { ok: true, copied, target }
  } catch (error) {
    return { ok: false, copied: 0, target, reason: error?.message || String(error) }
  }
}

/**
 * 把 presets/reverse 落到 $DSH_HOME/.agent-presets/reverse/。
 *
 * 已有同名目录时**只补缺文件**：用户在 preset 里调过的工具路径 / 并发上限
 * 不能被升级覆盖掉。`force: true` 才整份刷新（升级 agent.cordis.yml 时用）。
 */
export function installPreset({ force = false } = {}) {
  const p = packagePaths()
  if (!existsSync(p.presetDir)) {
    return { ok: false, target: null, copied: 0, reason: '包内没有 presets/reverse' }
  }
  const need = ['preset.yml', 'agent.cordis.yml']
  for (const f of need) {
    if (!existsSync(join(p.presetDir, f))) {
      return { ok: false, target: null, copied: 0, reason: `presets/reverse 缺 ${f}（包不完整）` }
    }
  }

  const target = userPresetRoot()
  try {
    mkdirSync(target, { recursive: true })
    let copied = 0
    for (const entry of readdirSync(p.presetDir, { withFileTypes: true })) {
      const s = join(p.presetDir, entry.name)
      const d = join(target, entry.name)
      if (entry.isDirectory()) {
        copied += copyDirOver(s, d, { force })
        continue
      }
      if (!entry.isFile()) continue
      if (!force && existsSync(d)) continue
      copyFileSync(s, d)
      copied += 1
    }
    /* anchor-gate.mjs 需要可执行位（POSIX）；Windows 上 chmod 是 no-op。 */
    const gate = join(target, 'anchor-gate.mjs')
    if (existsSync(gate)) {
      try { chmodSync(gate, 0o755) } catch { /* Windows 不报 */ }
    }
    return { ok: true, target, copied }
  } catch (error) {
    return { ok: false, target, copied: 0, reason: error?.message || String(error) }
  }
}

/** 一次性把三样都装好。 */
export function installAll({ force = false } = {}) {
  const preset = installPreset({ force })
  const skills = installBundledSkills({ force })
  const agents = installRoleFiles({ force })
  return { preset, skills, agents }
}

/**
 * 插件入口。
 *
 * 自举失败**不抛**：抛了整份「逆向模式」会被模式下拉过滤掉，
 * 用户看到的现象是"模式不见了"而不知道原因。这里记录 warn，让模式仍在，
 * 由 `reverse_preflight` 把问题摆到用户面前。
 */
export function apply(ctx) {
  const result = installAll()
  const bad = []
  if (!result.preset.ok) bad.push(`preset: ${result.preset.reason}`)
  if (!result.skills.ok) bad.push(`skills: ${result.skills.reason}`)
  if (!result.agents.ok) bad.push(`agents: ${result.agents.reason}`)
  if (bad.length) {
    ctx.logger?.warn?.(`[dsh-purge/reverse] 自举未完全成功 → ${bad.join(' | ')}`)
  } else {
    ctx.logger?.info?.(
      `[dsh-purge/reverse] preset→${result.preset.copied} 技能→${result.skills.copied} `
      + `角色→${result.agents.copied}`,
    )
  }
  try {
    globalThis.__dshPurgeReverseBoot = {
      ...result,
      at: new Date().toISOString(),
    }
  } catch { /* 只读全局时忽略 */ }

  declarePreset(ctx, result)
}

/* ────────────────────────── registry 声明 ───────────────────────────────
 *
 * Web 0.1.7+ 的模式下拉只认 `ctx.agentPresets.register()`：把预设目录写到
 * `.dsh/.agent-presets/reverse/` 并不会被扫到。少这一步，插件装得再完整，
 * 模式选择器里也永远只有别的模式 —— 必须显式声明。
 *
 * 每一步落 `$DSH_HOME/reverse/preset-declare.json`，装完直接看这个文件即可
 * 判断是 registered 还是 broken（失败不抛，避免连坐整份模式）。
 */
function declarePreset(ctx, bootResult) {
  const statusFile = join(reverseDataDir(), 'preset-declare.json')
  const writeStatus = (patch) => {
    try {
      mkdirSync(reverseDataDir(), { recursive: true })
      let prev = {}
      try { prev = JSON.parse(readFileSync(statusFile, 'utf8')) } catch { /* first */ }
      writeFileSync(
        statusFile,
        JSON.stringify({ ...prev, ...patch, at: new Date().toISOString() }, null, 2),
        'utf8',
      )
    } catch { /* 状态文件写不了不影响注册 */ }
  }

  writeStatus({
    ok: false,
    phase: 'apply-start',
    skillsDir: bootResult.skills.target,
    presetDir: bootResult.preset.target,
  })

  /** 软取 registry：先 ctx.agentPresets，再 ctx.get('agentPresets')。 */
  const softRegistry = () => {
    try {
      const reg = ctx.agentPresets
      if (reg && typeof reg.register === 'function') return reg
    } catch { /* 未声明 inject 时取不到 */ }
    try {
      const reg = ctx.get('agentPresets')
      if (reg && typeof reg.register === 'function') return reg
    } catch { /* 服务还没起来 */ }
    return null
  }

  /** 读 preset 定义：优先用户目录，回落到包内。 */
  const buildDefinition = () => {
    const fromDisk = userPresetRoot()
    let readyDir = fromDisk
    if (!existsSync(join(fromDisk, 'agent.cordis.yml'))) {
      installPreset({ force: false })
      const p = packagePaths()
      readyDir = existsSync(join(fromDisk, 'agent.cordis.yml')) ? fromDisk : p.presetDir
    }
    return readPresetDefinition(REVERSE_PRESET_ID, readyDir)
  }

  let releaseDeclared
  let closed = false
  let timer
  let stopTimer

  const undeclare = async () => {
    const dispose = releaseDeclared
    releaseDeclared = undefined
    if (!dispose) return
    try { await dispose() } catch (error) {
      ctx.logger?.warn?.(`[dsh-purge/reverse] undeclare failed: ${error?.message || String(error)}`)
    }
  }

  const registerOnce = (registry) => {
    let definition
    try {
      definition = buildDefinition()
    } catch (error) {
      writeStatus({ ok: false, phase: 'read-failed', error: error?.message || String(error) })
      ctx.logger?.warn?.(`[dsh-purge/reverse] 读取预设失败: ${error?.message || String(error)}`)
      return
    }
    writeStatus({
      ok: false,
      phase: 'registering',
      id: definition.id,
      name: definition.name,
      plugins: Array.isArray(definition.plugins) ? definition.plugins.length : -1,
    })
    Promise.resolve()
      .then(async () => {
        await undeclare()
        releaseDeclared = await registry.register(definition)
        let broken = null
        try {
          const rows = await registry.list()
          const row = (rows || []).find((p) => p && p.id === REVERSE_PRESET_ID)
          broken = row?.broken || null
        } catch { /* list 不可用不算失败 */ }
        writeStatus({
          ok: !broken,
          phase: broken ? 'registered-broken' : 'registered',
          id: definition.id,
          name: definition.name,
          plugins: Array.isArray(definition.plugins) ? definition.plugins.length : -1,
          broken,
        })
        if (broken) {
          ctx.logger?.warn?.(`[dsh-purge/reverse] 已声明但挂载失败: ${broken}`)
        } else {
          ctx.logger?.info?.(`[dsh-purge/reverse] 已声明进模式下拉: ${definition.name || REVERSE_PRESET_ID}`)
        }
      })
      .catch((error) => {
        writeStatus({ ok: false, phase: 'register-failed', error: error?.message || String(error) })
        ctx.logger?.warn?.(`[dsh-purge/reverse] 声明失败: ${error?.message || String(error)}`)
      })
  }

  ctx.effect(() => {
    let tries = 0
    const tick = () => {
      if (closed) return true
      tries += 1
      const registry = softRegistry()
      if (!registry) {
        writeStatus({ ok: false, phase: 'waiting-registry', tries })
        return false
      }
      registerOnce(registry)
      return true
    }
    if (!tick()) {
      /* registry 是别的行发布的，可能比本行晚就绪：轮询直到出现或超时。 */
      timer = setInterval(() => {
        if (tick()) {
          clearInterval(timer)
          timer = undefined
          if (stopTimer) clearTimeout(stopTimer)
        }
      }, 400)
      stopTimer = setTimeout(() => {
        if (timer) { clearInterval(timer); timer = undefined }
        writeStatus({ ok: false, phase: 'registry-timeout', tries })
        ctx.logger?.warn?.('[dsh-purge/reverse] 等待 agentPresets 服务超时，模式未能声明')
      }, 20000)
    }
    return () => {
      closed = true
      if (timer) { clearInterval(timer); timer = undefined }
      if (stopTimer) { clearTimeout(stopTimer); stopTimer = undefined }
      undeclare()
    }
  })
}
