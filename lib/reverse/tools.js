/**
 * 逆向模式 · 角色工具集（preset 平面）
 *
 * 这些行只向 `tools` 注册模型可见工具，自身不发布服务，故不需要 isolate realm；
 * 它们解析的是 host 平面的 `ctx.reverse`（reverse/store 发布的进程级实例）。
 *
 * 设计约定：
 *   · 写入一律走工具，智能体不直接碰 SQL；
 *   · **样本按根会话隔离**：绑定键是会话的根祖先 id，子智能体顺着
 *     `session.header.parentSession` 继承父会话的样本 —— 多会话并行时互不串写；
 *   · 并发硬约束：`reverse_agent_slot` 用 `ctx.subagents.listChildren` 的真实运行数
 *     卡住"同一样本最多 3 个执行智能体"，超了直接拒绝，不靠提示词自觉。
 */
import { createRequire } from 'node:module'
import { existsSync, realpathSync, readFileSync as readFileSyncNode } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  ROLE_TITLES, PLANNER_ROLE, ROLE_ORDER, PHASE_ORDER, PHASE_TITLES,
  PLATFORM_TITLES, FINDING_KINDS, KNOWN_PROTECTIONS,
} from './store-core.js'

/* ── 从宿主解析 defineTool ─────────────────────────────────────────────────
 * 源码包不在 profile node_modules 树内，静态 import `@deepseek-ai/dsh-tools`
 * 会解析失败 → 预设行 fiber 为 undefined（never started）→ 整份「逆向模式」
 * 被下拉过滤。这里从运行中的 dsh / profile 路径 createRequire。
 */

function addCandidate(list, pkg) {
  if (!pkg) return
  const norm = String(pkg).replace(/\\/g, '/')
  if (!list.includes(norm)) list.push(norm)
}

function considerBin(list, bin) {
  if (!bin) return
  let text = String(bin).replace(/\\/g, '/')
  try { text = realpathSync(bin).replace(/\\/g, '/') } catch { /* 用原路径 */ }
  const needle = '/node_modules/@deepseek-ai/dsh/'
  const at = text.lastIndexOf(needle)
  if (at >= 0) addCandidate(list, text.slice(0, at + needle.length - 1) + '/package.json')
  const nm = text.lastIndexOf('/node_modules/')
  if (nm >= 0) addCandidate(list, join(text.slice(0, nm), 'node_modules', '@deepseek-ai', 'dsh', 'package.json'))
  const dir = dirname(text)
  addCandidate(list, join(dir, '..', 'lib', 'node_modules', '@deepseek-ai', 'dsh', 'package.json'))
  addCandidate(list, join(dir, '..', 'node_modules', '@deepseek-ai', 'dsh', 'package.json'))
}

function loadDefineTool() {
  const candidates = []
  try { considerBin(candidates, process.argv[1]) } catch { /* ignore */ }
  const homes = [process.env.DSH_HOME, join(homedir(), '.dsh')].filter(Boolean)
  for (const home of homes) {
    addCandidate(candidates, join(home, 'package.json'))
    for (const profile of ['web', 'desktop', 'headless', 'default']) {
      addCandidate(candidates, join(home, 'profiles', profile, 'package.json'))
      addCandidate(candidates, join(home, 'profiles', profile, 'node_modules', '@deepseek-ai', 'dsh', 'package.json'))
    }
  }
  addCandidate(candidates, join(process.cwd(), 'package.json'))
  addCandidate(candidates, join('D:', 'DeepSeek Harness', 'npm-global', 'node_modules', '@deepseek-ai', 'dsh', 'package.json'))
  for (const pkg of candidates) {
    try {
      if (!pkg || !existsSync(pkg)) continue
      const mod = createRequire(pkg)('@deepseek-ai/dsh-tools')
      const fn = mod && (mod.defineTool || (mod.default && mod.default.defineTool))
      if (typeof fn === 'function') return fn
    } catch { /* try next */ }
  }
  return null
}

/**
 * 解析失败时返回 null，**绝不在模块顶层抛错**。
 *
 * 这条行一旦 import 失败，`auditRows` 会把它读成 "never started"，
 * `mountPreset` 随即抛错拒绝整份 preset —— 表现就是「模式选择器里看不到逆向模式」，
 * 而且没有任何提示。宁可工具缺席（apply 里只打一行 warn），也不能连累模式消失。
 */
const defineTool = (() => {
  try {
    return loadDefineTool()
  } catch {
    return null
  }
})()

/** Cordis 插件名。 */
export const name = 'dsh-purge-reverse-tools'

/** 硬依赖工具注册表；`reverse` 在 host 平面由 store 发布，域内软取。 */
export const inject = ['tools']

/** 根会话 id → sampleId 绑定。 */
const bindings = new Map()

/** 并发闸门：根会话 id → Map(子智能体键 → 预留时间戳)。 */
const reservations = new Map()

const BINDINGS_CAP = 500
const RESERVATIONS_CAP = 500
function capMap(m, cap) {
  const origSet = m.set.bind(m)
  m.set = (k, v) => {
    if (!m.has(k) && m.size >= cap) {
      const first = m.keys().next().value
      if (first !== undefined) m.delete(first)
    }
    return origSet(k, v)
  }
}
capMap(bindings, BINDINGS_CAP)
capMap(reservations, RESERVATIONS_CAP)

const text = (value) => [{ type: 'text', text: typeof value === 'string' ? value : JSON.stringify(value, null, 2) }]

const ROLE_HINT = '角色 code：' + ROLE_ORDER.map((r) => '`' + r + '`（' + ROLE_TITLES[r] + '）').join('、')
const PHASE_HINT = '阶段 code：' + PHASE_ORDER.map((p) => '`' + p + '`（' + PHASE_TITLES[p] + '）').join('、')

/** 一次调用的会话解析结果。 */
function sessionInfoOf(exec) {
  const agent = exec && exec.agent
  const session = agent && agent.session
  if (session === undefined || session === null) return {}
  const id = session.id === undefined ? undefined : String(session.id)
  let parentId
  try {
    const header = session.header
    parentId = header && header.parentSession !== undefined && header.parentSession !== null
      ? String(header.parentSession)
      : undefined
  } catch { parentId = undefined }
  return { id, parentId, session }
}

/** 沿 parentSession 一路走到根会话。 */
function resolveRootSession(session) {
  const chain = []
  let cur = session
  let guard = 0
  while (cur !== undefined && cur !== null && guard < 64) {
    const info = sessionInfoOf({ agent: { session: cur } })
    if (info.id === undefined) break
    chain.push(info.id)
    if (!info.parentId) break
    let parent
    try {
      const st = cur.store
      parent = st && typeof st.get === 'function' ? st.get(info.parentId) : undefined
    } catch { parent = undefined }
    if (!parent) return { rootId: info.parentId, chain: chain.concat([info.parentId]) }
    cur = parent
    guard += 1
  }
  return { rootId: chain.length > 0 ? chain[chain.length - 1] : undefined, chain }
}

function bindingKeyOf(exec) {
  const info = sessionInfoOf(exec)
  if (info.id === undefined) return { rootId: undefined, sessionId: undefined, chain: [] }
  const resolved = resolveRootSession(info.session)
  const rootId = resolved.rootId === undefined ? info.id : resolved.rootId
  return { rootId, sessionId: info.id, chain: resolved.chain }
}

function bindKeysOf(exec) {
  const { rootId, sessionId, chain } = bindingKeyOf(exec)
  return Array.from(new Set([rootId, sessionId, ...chain].filter(Boolean)))
}

/**
 * 解析本次调用应作用在哪个样本上。
 *
 * 顺序：① 显式传入 → ② 本会话/父链绑定 → ③ 全局 current 指针
 * （仅当没被别的会话占用）。挑错的后果是把 A 样本的结论写进 B 的库，
 * 所以这里**抛错而不是随便挑一个**。
 */
function resolveSample(store, exec, explicit) {
  if (typeof explicit === 'string' && explicit.length > 0) return explicit
  const keys = bindKeysOf(exec)
  for (const key of keys) {
    const bound = bindings.get(key)
    if (typeof bound === 'string' && bound.length > 0) return bound
  }
  if (typeof store.activeSampleId === 'function') {
    const active = store.activeSampleId()
    if (active !== undefined) {
      const holder = Array.from(bindings.entries()).find(([k, v]) => v === active && !keys.includes(k))
      if (holder !== undefined) {
        throw new Error(
          '本会话尚未绑定样本，而全局「当前样本」' + active + ' 已被另一个会话占用；'
          + '为避免多会话串写同一个样本库，请显式绑定：reverse_engagement_open（新建/打开）'
          + ' 或 reverse_session_bind（绑定到已有样本）。',
        )
      }
      for (const key of keys) bindings.set(key, active)
      return active
    }
  }
  const list = store.listSamples()
  if (list.length === 1) {
    for (const key of keys) bindings.set(key, list[0].id)
    return list[0].id
  }
  throw new Error('尚未绑定样本：请先调用 reverse_engagement_open 传入样本名称')
}

function bindingViewOf(exec) {
  const info = sessionInfoOf(exec)
  const { rootId, chain } = bindingKeyOf(exec)
  return {
    session_id: info.id ?? null,
    parent_session: info.parentId ?? null,
    root_session: rootId ?? null,
    session_chain: chain,
    is_subagent: info.parentId !== undefined,
    bound_sample: rootId !== undefined ? (bindings.get(rootId) ?? null) : null,
  }
}

/** 实时并发占用：读 subagents 注册表里真正在跑的直接子会话数。 */
async function liveRunningChildren(ctx, rootSessionId) {
  let subagents
  try { subagents = ctx.get('subagents') } catch { subagents = null }
  if (!subagents || typeof subagents.listChildren !== 'function') {
    return { available: false, running: 0, error: 'subagents 注册表不可用（只能按预留计数）' }
  }
  try {
    const entries = await subagents.listChildren(rootSessionId)
    const rows = Array.isArray(entries) ? entries : []
    const running = rows.filter((e) => e && e.kind === 'child' && e.activity === 'running')
    return {
      available: true,
      running: running.length,
      running_labels: running.map((e) => e.label || e.id).slice(0, 20),
      total_children: rows.filter((e) => e && e.kind === 'child').length,
    }
  } catch (error) {
    return { available: false, running: 0, error: '列子会话失败：' + (error?.message || String(error)) }
  }
}

function reservationList(rootId) {
  const map = reservations.get(rootId)
  if (map === undefined) return []
  return Array.from(map, ([key, at]) => ({ key, at }))
}

function addReservation(rootId, key) {
  if (!reservations.has(rootId)) reservations.set(rootId, new Map())
  reservations.get(rootId).set(key, Date.now())
}

function dropReservation(rootId, key) {
  const map = reservations.get(rootId)
  if (map === undefined) return false
  if (key === undefined) {
    let oldestKey = null
    let oldestAt = Infinity
    for (const [k, at] of map) { if (at < oldestAt) { oldestAt = at; oldestKey = k } }
    return oldestKey !== null ? map.delete(oldestKey) : false
  }
  return map.delete(key)
}

/** 并发上限：settings.json → DSH_REVERSE_MAX_AGENTS → 默认 3。 */
const DEFAULT_MAX_AGENTS = 3
const MAX_AGENTS_LIMIT = 8

function maxAgentsNow(store) {
  const clamp = (n) => {
    const num = Number(n)
    if (!Number.isFinite(num) || num < 1) return DEFAULT_MAX_AGENTS
    return Math.min(Math.max(Math.floor(num), 1), MAX_AGENTS_LIMIT)
  }
  try {
    const path = join(store.root, 'settings.json')
    if (existsSync(path)) {
      const cfg = JSON.parse(readFileSyncNode(path, 'utf8'))
      if (cfg && cfg.maxAgents !== undefined) return clamp(cfg.maxAgents)
    }
  } catch { /* 读不到走环境变量 */ }
  if (process.env.DSH_REVERSE_MAX_AGENTS) return clamp(process.env.DSH_REVERSE_MAX_AGENTS)
  return DEFAULT_MAX_AGENTS
}

/** 产出这条记录的角色：显式传的优先，否则按主会话记账。 */
function agentOf(args) {
  const raw = typeof args.agent === 'string' ? args.agent.trim() : ''
  return raw !== '' ? raw : PLANNER_ROLE
}

const AGENT_PARAM = {
  type: 'string',
  description: '【建议填】产出这条记录的角色 —— ' + ROLE_HINT
    + '。报告里按它标注"这一步是谁做的"，不填按主会话记账。',
}

const SAMPLE_PARAM = {
  type: 'string',
  description: '样本 id（省略则用本会话绑定的样本）。',
}

/** store 层异常统一收敛成结构化失败返回。 */
function withStructuredErrors(tool) {
  const inner = tool.execute
  if (typeof inner !== 'function') return tool
  return Object.assign({}, tool, {
    async execute(args, exec) {
      try {
        return await inner(args, exec)
      } catch (error) {
        const message = error && error.message ? error.message : String(error)
        const kind = /非法|invalid|required|不能为空|not found|不存在/i.test(message) ? 'bad_input' : 'failed'
        return JSON.stringify({
          ok: false,
          error: message,
          error_kind: kind,
          hint: kind === 'bad_input'
            ? '这是参数或对象标识的问题：核对参数名与取值（可用 reverse_samples / reverse_sample_query 先看实际 id），修正后重试。'
            : '工具执行失败，错误原文见 error 字段；不要静默跳过，先向用户或指挥者说明卡点。',
        }, null, 2)
      }
    },
  })
}

export function apply(ctx) {
  let store
  try { store = ctx.reverse } catch { store = undefined }
  if (!store) {
    try { store = ctx.get('reverse') } catch { store = undefined }
  }
  if (!store) {
    ctx.logger?.warn?.('reverse-tools: host ctx.reverse unavailable — tools will report store_missing')
    store = {
      root: join(homedir(), '.dsh', 'reverse'),
      openSample: () => { throw new Error('reverse store unavailable') },
      listSamples: () => [],
      stats: () => ({}),
    }
  }

  /* defineTool 解析不到时，**不能抛**：抛了这行就是 never started，
     整份 preset 会被 auditRows 拒绝，模式从选择器消失。
     这里只打一行 warn，让模式照常出现（工具缺席比模式消失好得多）。 */
  if (typeof defineTool !== 'function') {
    ctx.logger?.warn?.(
      '[dsh-purge/reverse/tools] 未能解析 @deepseek-ai/dsh-tools，reverse_* 工具本次未注册；'
      + '模式本身不受影响。检查 dsh 安装路径是否可读。',
    )
    return
  }

  /* ── 子智能体结束时自动释放并发名额 ─────────────────────────────────── */
  ctx.effect(() => {
    let disposer = null
    try {
      disposer = ctx.on('subagent/end', (info, parent) => {
        const parentSession = parent && parent.session
        const { rootId } = bindingKeyOf({ agent: { session: parentSession } })
        const childId = info && info.id !== undefined ? String(info.id) : undefined
        if (rootId === undefined) return
        if (childId !== undefined && dropReservation(rootId, childId)) return
        const map = reservations.get(rootId)
        if (map === undefined || map.size === 0) return
        let oldestKey
        let oldestAt = Number.POSITIVE_INFINITY
        for (const [key, at] of map) { if (at < oldestAt) { oldestAt = at; oldestKey = key } }
        if (oldestKey !== undefined) map.delete(oldestKey)
      })
    } catch { /* 事件不可用时只影响自动释放 */ }
    return () => { try { if (typeof disposer === 'function') disposer() } catch { /* ignore */ } }
  })

  /* ── 开样本 / 绑样本 / 会话信息 ─────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_engagement_open',
    description: '打开或创建一次逆向分析样本工作区（按样本名称/文件名），并把**当前会话**绑定到该样本（子智能体会自动继承）。后续所有工具默认作用于它。若样本已存在则复用其结论库。写入的是本会话的绑定，不会改动其它会话正在用的样本。',
    parameters: {
      target: { type: 'string', required: true, description: '样本名称，例如「com.example.app v1.2.3」或文件名 `target.apk`' },
      platform: { type: 'string', enum: ['android', 'ios', 'windows', 'linux', 'cross'], description: '平台（省略则按扩展名/名称猜）' },
      note: { type: 'string', description: '备注（授权来源、样本来源、已知保护等）' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const sample = store.openSample(args.target, { platform: args.platform, note: args.note })
      const keys = bindKeysOf(exec)
      for (const key of keys) bindings.set(key, sample.id)
      const view = bindingViewOf(exec)
      return JSON.stringify({
        ok: true,
        sample: { id: sample.id, name: sample.name, platform: sample.platform, dir: sample.dir },
        stats: store.stats(sample.id),
        progress: store.phaseProgress(sample.id),
        session: view,
        note: '已绑定到本会话（会话隔离：其它会话的绑定不受影响）；子智能体会继承本样本。'
          + (view.is_subagent ? ' 注意：本会话是子智能体，通常不需要再 open，直接继承父会话样本即可。' : ''),
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_session_bind',
    description: '把一个**已经存在**的样本绑定到当前会话（多会话并行时用：每个会话绑自己的样本，互不串写）。可用样本 id 或名称，省略则列出可绑定的样本。',
    parameters: {
      engagement: { type: 'string', description: '样本 id 或名称；省略则列出' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const list = store.listSamples()
      const wanted = typeof args.engagement === 'string' ? args.engagement.trim() : ''
      if (!wanted) {
        return JSON.stringify({
          ok: true,
          candidates: list.map((s) => ({ id: s.id, name: s.name, platform: s.platform, findings: s.n_findings })),
          note: '传入 id 或名称完成绑定。',
        }, null, 2)
      }
      const hit = list.find((s) => s.id === wanted)
        || list.find((s) => s.name === wanted)
        || list.find((s) => s.name.includes(wanted))
      if (!hit) throw new Error('找不到样本: ' + wanted)
      const keys = bindKeysOf(exec)
      for (const key of keys) bindings.set(key, hit.id)
      store.setActiveSample(hit.id)
      return JSON.stringify({
        ok: true,
        bound: hit.id,
        name: hit.name,
        stats: store.stats(hit.id),
        session: bindingViewOf(exec),
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_session_info',
    description: '查看**当前会话绑定的是哪个样本**（会话 id、父会话、根会话、绑定链）。多会话同时开工时先跑它，确认自己没串到别人的样本上。',
    parameters: {},
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(_args, exec) {
      const view = bindingViewOf(exec)
      const stats = view.bound_sample !== null ? store.stats(view.bound_sample) : null
      return JSON.stringify({
        ok: true,
        session: view,
        stats,
        bindings_now: Array.from(bindings, ([k, v]) => ({ session: k, sample: v })),
        note: '绑定是进程内状态：dsh 重启后各会话需重新绑定（reverse_engagement_open / reverse_session_bind）。',
      }, null, 2)
    },
  })))

  /* ── 并发闸门 ──────────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_agent_slot',
    description: '【主会话派活前后用】执行智能体的并发闸门：同一样本**最多同时 3 个**在跑（可用 settings.json 的 maxAgents 或 DSH_REVERSE_MAX_AGENTS 配置）。action=status 看还剩几个名额与谁在跑；action=acquire 占一个名额（满了直接拒绝，**不要重试硬塞**）；action=release 释放（子智能体结束时服务端也会自动释放）。',
    parameters: {
      action: { type: 'string', required: true, enum: ['status', 'acquire', 'release'], description: 'status 查看 / acquire 占用 / release 释放' },
      label: { type: 'string', description: 'acquire 时的任务标签，例如「静态分析：APK 结构与加固识别」' },
      key: { type: 'string', description: 'release 时指定要释放的键（省略则释放最早的一个预留）' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const { rootId, sessionId } = bindingKeyOf(exec)
      const owner = rootId ?? sessionId
      if (owner === undefined) {
        return JSON.stringify({ ok: false, error: '取不到会话 id：无法统计并发（请确认工具调用带着 agent 上下文）。' }, null, 2)
      }
      const live = await liveRunningChildren(ctx, owner)
      const reserved = reservationList(owner)
      const used = Math.max(live.running, reserved.length)
      const cap = maxAgentsNow(store)
      const free = Math.max(cap - used, 0)
      const base = {
        ok: true, max: cap, used, free,
        running_from_registry: live.running,
        running_labels: live.running_labels || [],
        reservations: reserved,
        registry: live.available ? 'ok' : live.error,
      }

      if (args.action === 'status') {
        return JSON.stringify({
          ...base,
          note: free > 0 ? `还能派 ${free} 个` : '名额已满：等现有智能体回报后再派，不要重试硬塞。',
        }, null, 2)
      }

      if (args.action === 'acquire') {
        if (free <= 0) {
          return JSON.stringify({
            ...base,
            ok: false,
            error: '并发名额已满（' + used + '/' + cap + '）',
            hint: '不要重试硬塞。等现有子智能体回报（reverse_agent_slot action=status 复查）再派下一个。',
          }, null, 2)
        }
        const key = 'r-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7)
        addReservation(owner, key)
        return JSON.stringify({
          ...base, ok: true, acquired: key,
          label: args.label || '',
          used: used + 1, free: free - 1,
          note: '已占位。子智能体结束时自动释放；也可 action=release key=' + key + ' 手动释放。',
        }, null, 2)
      }

      const dropped = dropReservation(owner, args.key)
      return JSON.stringify({
        ...base,
        ok: true,
        released: dropped,
        note: dropped ? '已释放一个名额。' : '没有可释放的预留（可能子智能体已结束并由服务端释放）。',
      }, null, 2)
    },
  })))

  /* ── 样本 / 二进制 ─────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_samples',
    description: '列出所有逆向样本工作区（id / 名称 / 平台 / 二进制数 / 结论数 / 更新时间）。',
    parameters: {},
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute() {
      const list = store.listSamples()
      return JSON.stringify({
        ok: true,
        count: list.length,
        samples: list.map((s) => ({
          id: s.id, name: s.name,
          platform: s.platform, platform_title: PLATFORM_TITLES[s.platform] || s.platform,
          binaries: s.n_binaries, findings: s.n_findings, updated_at: s.updated_at,
        })),
        current: store.activeSampleId() ?? null,
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_sample_query',
    description: '查一个样本的完整事实：二进制清单（含 SHA256/架构/熵/保护）、结论、产物、证据链、阶段进度。指挥核对子智能体回报时用。',
    parameters: { sample: SAMPLE_PARAM },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const s = store.getSample(id)
      if (!s) throw new Error('样本不存在: ' + id)
      return JSON.stringify({
        ok: true,
        sample: { id: s.id, name: s.name, platform: s.platform, dir: s.dir, note: s.note },
        binaries: s.binaries.map((b) => ({
          id: b.id, file: b.file_name, role: b.role,
          arch: [b.arch, b.bits].filter(Boolean).join(' '),
          sha256: b.sha256, size: b.size, entropy: b.entropy, protection: b.protection,
        })),
        findings: s.findings.map((f) => ({
          id: f.id, phase: f.phase, role: f.role, kind: f.kind,
          title: f.title, confidence: f.confidence, verified: !!f.verified,
        })),
        artifacts: s.artifacts.map((a) => ({ id: a.id, kind: a.kind, title: a.title, sha256: a.sha256, path: a.path })),
        chain_steps: s.chain.length,
        stats: store.stats(id),
        progress: store.phaseProgress(id),
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_sample_stats',
    description: '样本得分/进度快照：各阶段结论数与步骤数、已验证数、产物数、当前所处阶段。',
    parameters: { sample: SAMPLE_PARAM },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      return JSON.stringify({
        ok: true,
        sample: id,
        stats: store.stats(id),
        progress: store.phaseProgress(id),
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_binary_add',
    description: '登记一个待分析的二进制文件（自动算 SHA256 与大小）。同一份样本的所有结论都挂在它的哈希下面，不同版本不能混。',
    parameters: {
      path: { type: 'string', required: true, description: '文件的绝对路径（也可以是相对 $DSH_HOME/reverse 的路径）' },
      role: { type: 'string', description: '这个文件在样本里的角色：primary / lib / dex / driver / payload / dump（省略按 primary）' },
      arch: { type: 'string', description: '架构，例如 arm64 / x86 / x86_64 / armv7' },
      bits: { type: 'string', description: '位数：32 / 64' },
      entropy: { type: 'number', description: '整文件熵值（>7.0 通常有保护层）' },
      protection: { type: 'string', description: '保护方案（' + KNOWN_PROTECTIONS.slice(0, 12).join('/') + ' …，未知填 custom）' },
      note: { type: 'string', description: '备注' },
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const b = store.addBinary(id, args.path, {
        role: args.role, arch: args.arch, bits: args.bits,
        entropy: args.entropy, protection: args.protection, note: args.note,
      })
      return JSON.stringify({ ok: true, binary: b }, null, 2)
    },
  })))

  /* ── 结论 ──────────────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_findings',
    description: '读取已落库的逆向结论（可按阶段过滤）。核对子智能体回报时用：**没落库的结论 = 没发生**。',
    parameters: {
      phase: { type: 'string', enum: PHASE_ORDER, description: '只看这个阶段' },
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const rows = store.listFindings(id, args.phase)
      return JSON.stringify({
        ok: true,
        sample: id,
        phase: args.phase || 'all',
        count: rows.length,
        findings: rows.map((f) => ({
          id: f.id, phase: f.phase, phase_title: PHASE_TITLES[f.phase] || f.phase,
          role: f.role, role_title: ROLE_TITLES[f.role] || f.role,
          kind: f.kind, title: f.title, detail: f.detail, evidence: f.evidence,
          confidence: f.confidence, verified: !!f.verified, created_at: f.created_at,
        })),
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_finding_add',
    description: '落一条逆向结论（必须带证据：文件+偏移 / Hook 日志 / 解出的明文 / 产物路径）。**没落库的结论 = 没发生**，报告只收录这里的东西。',
    parameters: {
      title: { type: 'string', required: true, description: '一句话结论，例如「使用 360 加固（libjiagu.so）」' },
      detail: { type: 'string', description: '展开说明：怎么得出、影响了什么、下一步' },
      evidence: { type: 'string', description: '证据引用：路径:行号 / 命令输出 / 日志片段 / 产物哈希' },
      phase: { type: 'string', enum: PHASE_ORDER, description: PHASE_HINT },
      kind: { type: 'string', enum: FINDING_KINDS, description: '结构 / 保护 / 算法 / 协议 / 行为 / 脱壳 / 绕过 / 其它' },
      confidence: { type: 'string', enum: ['low', 'medium', 'high'], description: '置信度（推测标 low，别硬说 high）' },
      verified: { type: 'boolean', description: '是否已通过 L2 验收（有独立复现证据）' },
      binary_id: { type: 'string', description: '结论针对哪个二进制（reverse_binary_add 返回的 id）' },
      agent: AGENT_PARAM,
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const f = store.addFinding(id, {
        title: args.title, detail: args.detail, evidence: args.evidence,
        phase: args.phase, kind: args.kind, confidence: args.confidence,
        verified: args.verified, role: agentOf(args), binaryId: args.binary_id,
      })
      return JSON.stringify({ ok: true, finding: f, stats: store.stats(id) }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_finding_verify',
    description: '标记一条结论的验收结果（L2：结果对）。没通过的也要记，并写明差在哪 —— 谎报"已验证"比失败更糟。',
    parameters: {
      id: { type: 'string', required: true, description: '结论 id（F-xxxx）' },
      passed: { type: 'boolean', required: true, description: '是否通过' },
      detail: { type: 'string', description: '验收说明：用了什么样本、差在哪、产物路径' },
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args) {
      const r = store.verifyFinding(args.id, !!args.passed, args.detail)
      return JSON.stringify({ ok: true, ...r }, null, 2)
    },
  })))

  /* ── 产物 ──────────────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_artifact_add',
    description: '登记一个中间产物（脱壳后的 dex/so、dump 出来的内存、还原的算法脚本、抓包 pcap）。文件会复制进样本产物目录并记录 SHA256。',
    parameters: {
      title: { type: 'string', required: true, description: '产物标题，例如「BlackDex 脱壳 classes.dex」' },
      path: { type: 'string', description: '产物路径（存在的文件会被复制入库并计算哈希）' },
      kind: { type: 'string', description: 'unpacked / dump / algorithm / capture / script / file（省略 file）' },
      sha256: { type: 'string', description: '已有哈希时直接给（文件不在本机的情况）' },
      note: { type: 'string', description: '备注：怎么产出的、验证结果' },
      agent: AGENT_PARAM,
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const a = store.addArtifact(id, {
        title: args.title, path: args.path, kind: args.kind,
        sha256: args.sha256, note: args.note,
      })
      return JSON.stringify({ ok: true, artifact: a }, null, 2)
    },
  })))

  /* ── 证据链 ────────────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_chain_add',
    description: '记一步分析动作（做什么 / 用什么工具 / 什么命令 / 什么结果）。**报告里"壳怎么脱的、算法怎么还原的"全靠这里**，缺了报告交不出去。',
    parameters: {
      title: { type: 'string', required: true, description: '这一步做什么，例如「BlackDex 对应 App 脱壳」' },
      phase: { type: 'string', enum: PHASE_ORDER, description: PHASE_HINT },
      tool: { type: 'string', description: '用的工具：jadx / frida / BlackDex / ida / ghidra / x64dbg / mitmproxy …' },
      command: { type: 'string', description: '实际执行的命令或脚本（原样贴，不要改写）' },
      result: { type: 'string', description: '结果：拿到了什么、产物路径、是否成功' },
      agent: AGENT_PARAM,
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const s = store.addChainStep(id, {
        title: args.title, phase: args.phase, tool: args.tool,
        command: args.command, result: args.result, role: agentOf(args),
      })
      return JSON.stringify({ ok: true, step: s }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_chain',
    description: '读样本的完整证据链（按序号），并给出阶段推进情况。报告前必须看一遍：有没有"结论在、步骤缺"的洞。',
    parameters: { sample: SAMPLE_PARAM },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const chain = store.listChain(id)
      return JSON.stringify({
        ok: true,
        sample: id,
        steps: chain.length,
        progress: store.phaseProgress(id),
        chain: chain.map((s) => ({
          seq: s.seq,
          phase: s.phase, phase_title: PHASE_TITLES[s.phase] || s.phase,
          role: s.role, role_title: ROLE_TITLES[s.role] || s.role,
          title: s.title, tool: s.tool, command: s.command, result: s.result,
          at: s.created_at,
        })),
      }, null, 2)
    },
  })))

  /* ── 评分 / 角色 ───────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_score_list',
    description: '按五阶段列当前得分与缺口：每阶段各有几条结论、几步证据、几条已验证，缺什么补什么。指挥汇报进度用。',
    parameters: { sample: SAMPLE_PARAM },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      const st = store.stats(id)
      const progress = store.phaseProgress(id)
      const rows = progress.map((p) => ({
        seq: p.seq,
        phase: p.code,
        title: p.title,
        findings: p.findings,
        steps: p.steps,
        status: p.done ? 'done' : 'pending',
        gap: p.done ? null
          : (p.steps === 0 ? '没有任何步骤记录' : '有步骤但没落结论'),
      }))
      return JSON.stringify({
        ok: true,
        sample: id,
        current_phase: st.current_phase,
        current_phase_title: PHASE_TITLES[st.current_phase] || st.current_phase,
        totals: {
          findings: st.findings, verified: st.verified,
          artifacts: st.artifacts, steps: st.steps,
          checks: st.checks, checks_pass: st.checks_pass,
        },
        phases: rows,
      }, null, 2)
    },
  })))

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_roles',
    description: '列出逆向模式的五个执行角色与五个阶段（code → 中文名），派活时按它写 reverseRole。',
    parameters: {},
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute() {
      return JSON.stringify({
        ok: true,
        planner: { code: PLANNER_ROLE, title: ROLE_TITLES[PLANNER_ROLE] },
        roles: ROLE_ORDER.map((code, i) => ({ seq: i + 1, code, title: ROLE_TITLES[code] })),
        phases: PHASE_ORDER.map((code, i) => ({ seq: i + 1, code, title: PHASE_TITLES[code] })),
        platforms: Object.entries(PLATFORM_TITLES).map(([code, title]) => ({ code, title })),
        rule: 'subagent 的 prompt 第一行必须是 `reverseRole: <code>`，code 只能取上面 roles 里的值。',
      }, null, 2)
    },
  })))

  /* ── 报告 ──────────────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_report',
    description: '生成样本的逆向分析报告（按五阶段组织：结论 + 证据 + 分析步骤 + 产物 + 验收）。可直接返回 JSON，也可写盘成 markdown。',
    parameters: {
      write: { type: 'boolean', description: 'true 则写成 markdown 文件' },
      path: { type: 'string', description: '写盘路径（省略则写 $DSH_HOME/reverse/reports/<样本>.md）' },
      sample: SAMPLE_PARAM,
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args, exec) {
      const id = resolveSample(store, exec, args.sample)
      if (args.write) {
        const r = store.writeReport(id, args.path)
        return JSON.stringify({ ok: true, written: r, note: '报告已落盘。' }, null, 2)
      }
      const r = store.report(id)
      return JSON.stringify({
        ok: true,
        sample: r.sample,
        stats: r.stats,
        progress: r.progress,
        by_kind: r.by_kind,
        findings: r.findings.map((f) => ({
          id: f.id, phase: f.phase, role: f.role, kind: f.kind,
          title: f.title, detail: f.detail, evidence: f.evidence,
          confidence: f.confidence, verified: !!f.verified,
        })),
        artifacts: r.artifacts,
        chain: r.chain.map((s) => ({
          seq: s.seq, phase: s.phase, role: s.role, title: s.title,
          tool: s.tool, command: s.command, result: s.result,
        })),
        verify: r.verify,
        hint: '想让报告写盘就再调一次带 write: true。',
      }, null, 2)
    },
  })))

  /* ── 开工前自检 ────────────────────────────────────────────────────── */

  ctx.tools.register(withStructuredErrors(defineTool({
    name: 'reverse_preflight',
    description: '【开工前必须跑一次】逆向工具链与资源自检：检查 jadx / apktool / baksmali / dex2jar / frida / objection / ghidra / radare2 / IDA / x64dbg / WinDbg / lldb / otool / class-dump / Hopper / DIE / upx / binwalk / adb / python3 等工具的可用性，本机架构、Linux 子系统与常见逆向数据目录。返回 available / broken 清单与每个缺项的"怎么补"。**缺工具就直接向用户要，或给出降级方案（IDA 不可用 → Ghidra + r2），不要假装能跑。**',
    parameters: {
      include: { type: 'string', description: '只检查这些（逗号分隔的工具名）；省略则检查全部' },
    },
    output: { schema: { type: 'string' }, render: (_a, v) => text(v) },
    async execute(args) {
      const path = await import('node:path')
      const fs = await import('node:fs')
      const { execFileSync } = await import('node:child_process')

      /* 常见位置探测：PATH 之外的 Windows 安装目录也要认。 */
      const HOME = process.env.USERPROFILE || process.env.HOME || ''
      const extraDirs = [
        process.env.LOCALAPPDATA && path.join(process.env.LOCALAPPDATA, 'Programs'),
        'C:\\Program Files', 'C:\\Program Files (x86)',
        HOME && path.join(HOME, 'scoop', 'shims'),
        HOME && path.join(HOME, 'AppData', 'Local', 'Android', 'Sdk', 'platform-tools'),
        '/usr/local/bin', '/opt/homebrew/bin', '/usr/bin',
      ].filter(Boolean)

      const CATALOG = [
        { name: 'java', bins: ['java'], why: 'jadx / apktool / dex2jar 的运行时', fix: '装 JDK 17+，配 JAVA_HOME' },
        { name: 'python3', bins: ['python3', 'python'], why: '脚本与分析工具宿主', fix: '装 Python 3.8+' },
        { name: 'jadx', bins: ['jadx', 'jadx.bat', 'jadx-gui'], why: 'APK/DEX 反编译（最常用）', fix: '下载 jadx release 解压后把 bin 加进 PATH' },
        { name: 'apktool', bins: ['apktool', 'apktool.bat'], why: 'APK 拆包与回包', fix: '下载 apktool.jar + 包装脚本' },
        { name: 'baksmali', bins: ['baksmali', 'baksmali.jar', 'baksmali.bat'], why: 'DEX ↔ smali', fix: '下载 baksmali.jar（配 JAVA）' },
        { name: 'dex2jar', bins: ['d2j-dex2jar', 'd2j-dex2jar.sh', 'd2j-dex2jar.bat'], why: 'DEX → jar', fix: '下载 dex2jar release 解压' },
        { name: 'frida', bins: ['frida', 'frida-ps'], why: '跨平台动态 Hook（核心）', fix: 'pip install frida-tools；设备端要装同版本 frida-server' },
        { name: 'objection', bins: ['objection'], why: '一键探索 / 绕 pinning', fix: 'pip install objection' },
        { name: 'adb', bins: ['adb', 'adb.exe'], why: 'Android 设备交互', fix: '装 Android platform-tools 并加进 PATH' },
        { name: 'ghidra', bins: ['ghidraRun', 'analyzeHeadless'], why: 'IDA 的开源替代', fix: '下载 Ghidra release，加进 PATH 或配 analyzeHeadless 路径' },
        { name: 'radare2', bins: ['r2', 'radare2'], why: '命令行反汇编 / 打补丁', fix: '装 radare2（或 rizin）' },
        { name: 'rizin', bins: ['rizin', 'cutter'], why: 'r2 的现代分支 / 图形化', fix: '装 rizin + cutter' },
        { name: 'ida', bins: ['ida64', 'ida', 'idat64', 'idat'], why: '商业反编译器（效果最好）', fix: '装 IDA Pro 并配 idat/ida64 路径' },
        { name: 'x64dbg', bins: ['x64dbg', 'x32dbg'], why: 'Windows 用户态调试', fix: '下载 x64dbg 解压，配路径（snapshot 版）' },
        { name: 'windbg', bins: ['windbg', 'windbgx', 'cdb'], why: 'Windows 内核调试', fix: '装 WinDbg（Store 版）或 Windows SDK 的 Debugging Tools' },
        { name: 'lldb', bins: ['lldb'], why: 'iOS / macOS 调试', fix: '装 Xcode command line tools 或 LLVM' },
        { name: 'otool', bins: ['otool', 'llvm-otool'], why: 'Mach-O 解析', fix: 'macOS 自带；其它平台用 llvm-objdump 替代' },
        { name: 'class-dump', bins: ['class-dump'], why: 'ObjC 类与方法导出', fix: '下载 class-dump 二进制放 /usr/local/bin' },
        { name: 'Hopper', bins: ['hopper', 'Hopper'], why: 'macOS/iOS 反汇编 GUI', fix: '装 Hopper Disassembler' },
        { name: 'die', bins: ['diec', 'die', 'DIE'], why: 'Detect It Easy，判壳最快', fix: '下载 DIE 解压，把 diec 加进 PATH' },
        { name: 'upx', bins: ['upx'], why: 'UPX 一键脱壳', fix: '下载 upx release' },
        { name: 'binwalk', bins: ['binwalk'], why: '固件/嵌套镜像切分', fix: 'pip install binwalk' },
        { name: 'strings', bins: ['strings'], why: '字符串提取', fix: '装 binutils（Windows 用 Sysinternals strings）' },
        { name: 'readelf', bins: ['readelf', 'llvm-readelf'], why: 'ELF 结构解析', fix: '装 binutils / LLVM' },
        { name: 'objdump', bins: ['objdump', 'llvm-objdump'], why: '反汇编 / 段信息', fix: '装 binutils / LLVM' },
        { name: 'nm', bins: ['nm', 'llvm-nm'], why: '符号表', fix: '装 binutils / LLVM' },
        { name: 'mitmproxy', bins: ['mitmproxy', 'mitmdump', 'mitmweb'], why: 'HTTPS 抓包', fix: 'pip install mitmproxy' },
        { name: 'wireshark', bins: ['wireshark', 'tshark'], why: '原始流量分析', fix: '装 Wireshark（tshark 随包）' },
        { name: 'node', bins: ['node'], why: '前端 / WASM / Electron 逆向', fix: '装 Node 18+' },
        { name: 'git', bins: ['git'], why: '拉工具与脚本', fix: '装 git' },
      ]

      const which = (bin) => {
        for (const dir of String(process.env.PATH || '').split(path.delimiter)) {
          if (!dir) continue
          const full = path.join(dir, bin)
          try { if (fs.existsSync(full)) return full } catch { /* 忽略 */ }
          try {
            const fullExe = full + '.exe'
            if (fs.existsSync(fullExe)) return fullExe
          } catch { /* 忽略 */ }
        }
        for (const dir of extraDirs) {
          const full = path.join(dir, bin)
          try { if (fs.existsSync(full)) return full } catch { /* 忽略 */ }
          try {
            if (fs.existsSync(full + '.exe')) return full + '.exe'
          } catch { /* 忽略 */ }
        }
        return null
      }

      const wanted = args.include
        ? new Set(String(args.include).split(/[,，\s]+/).map((x) => x.trim().toLowerCase()).filter(Boolean))
        : null

      const available = []
      const broken = []
      for (const item of CATALOG) {
        if (wanted && !wanted.has(item.name.toLowerCase())) continue
        let found = null
        for (const b of item.bins) {
          found = which(b)
          if (found) break
        }
        if (found) {
          let version = ''
          try {
            const out = execFileSync(found, ['--version'], { timeout: 8000, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
            version = String(out).split('\n')[0].trim().slice(0, 80)
          } catch { /* 版本取不到不算不可用 */ }
          available.push({ tool: item.name, path: found, version })
        } else {
          broken.push({ tool: item.name, why: item.why, fix: item.fix })
        }
      }

      const platform = process.platform
      const arch = process.arch
      return JSON.stringify({
        ok: true,
        host: { platform, arch, node: process.version, python: '见 available 里的 python3' },
        available_count: available.length,
        broken_count: broken.length,
        available,
        broken,
        degrade_plan: broken.length === 0 ? null : {
          ida: broken.some((b) => b.tool === 'ida') ? 'IDA 不可用 → 用 Ghidra + radare2/rizin 替代' : undefined,
          frida: broken.some((b) => b.tool === 'frida') ? 'Frida 不可用 → 只能静态分析 + 内存 dump 脚本，动态 hook 做不了' : undefined,
          die: broken.some((b) => b.tool === 'die') ? 'DIE 不可用 → 用 pefile/pyelftools 手工算熵与节区名判壳' : undefined,
          jadx: broken.some((b) => b.tool === 'jadx') ? 'jadx 不可用 → 用 apktool + baksmali 看 smali，或 dex2jar + jd-gui' : undefined,
        },
        note: broken.length
          ? '缺项要么向用户要（一次性列清"要什么、为什么、给到哪"），要么走 degrade_plan。不要假装能跑。'
          : '工具链齐全，可以开工。',
      }, null, 2)
    },
  })))
}

export { ROLE_ORDER, ROLE_TITLES, PHASE_ORDER, PHASE_TITLES, PLANNER_ROLE }
