/**
 * 逆向模式 · 子会话角色稿注入
 *
 * 指挥派活时在任务**第一行**写 `reverseRole: <code>`。
 * 子会话领到这条用户消息时记下角色，组装系统提示词时把
 * `$DSH_HOME/reverse/agents/<code>.md` 原样插入。
 *
 * 与红队 redteamRole 同构，只是角色集合换成逆向的五个。
 */
import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { ROLE_ORDER } from './store-core.js'

/** 段名：用 dshpg- 前缀，和插件的 dsh-purge* 段区分开（宿主过滤器不会挪它）。 */
export const REVERSE_ROLE_SECTION = 'dshpg-reverse-role'

const ROLE_TAG = new RegExp(
  `^[ \\t]*reverseRole:[ \\t]*(${ROLE_ORDER.join('|')})[ \\t]*$`,
  'im',
)

/** 会话 id → 角色 code。 */
const roleBySession = new Map()
const ROLE_SESSION_CAP = 400
const ROLE_SESSION_EVICT = 100

function evictIfOverflow() {
  if (roleBySession.size < ROLE_SESSION_CAP) return
  let i = 0
  for (const k of roleBySession.keys()) {
    if (i >= ROLE_SESSION_EVICT) break
    roleBySession.delete(k)
    i += 1
  }
}

/** 从任务文本里解析角色 code；没有就是空串（不猜）。 */
export function parseReverseRole(text) {
  const matched = String(text || '').match(ROLE_TAG)
  return matched ? matched[1].toLowerCase() : ''
}

/** 取消息正文（兼容 string / content blocks）。 */
export function textOfMessage(message) {
  if (!message) return ''
  if (typeof message === 'string') return message
  const content = message.content ?? message.text
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content.map((block) => (typeof block?.text === 'string' ? block.text : '')).join('\n')
}

function remember(agent, role) {
  const ids = [agent?.session?.id, agent?.id].filter((id) => id !== undefined && id !== null)
  if (ids.length) evictIfOverflow()
  for (const id of ids) roleBySession.set(String(id), role)
}

/** 逆向数据根。 */
function reverseRoot() {
  if (process.env.DSH_REVERSE_HOME) return process.env.DSH_REVERSE_HOME
  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  return join(home, 'reverse')
}

function isReverseChild(session) {
  const header = session?.header
  if (!header) return false
  return header.origin === 'subagent' || (header.delegationDepth ?? 0) > 0
}

/** 领消息事件：记下这个子会话的角色。 */
export function noteClaimedMessage(payload) {
  const agent = payload?.agent
  const session = agent?.session
  if (!isReverseChild(session)) return
  const role = parseReverseRole(textOfMessage(payload?.message))
  if (!role) return
  remember(agent, role)
}

/** 从会话历史里兜底找角色（领消息事件没赶上时）。 */
function roleFromSessionEvents(session) {
  const events = []
  try {
    if (typeof session?.snapshotEvents === 'function') {
      const got = session.snapshotEvents()
      if (Array.isArray(got)) events.push(...got)
    }
  } catch { /* 读不到历史就只用已记下的角色 */ }
  if (Array.isArray(session?.events)) events.push(...session.events)
  let found = ''
  for (const event of events) {
    if (!event || event.type !== 'user/message') continue
    const data = event.data
    const role = parseReverseRole(textOfMessage(data?.message || data))
    if (role) found = role
  }
  return found
}

/** 当前样本 id（决定从哪个样本目录读角色稿）。 */
function currentSampleId() {
  try {
    const id = readFileSync(join(reverseRoot(), 'current'), 'utf8').trim()
    if (!id || id.includes('..') || id.includes('/') || id.includes('\\')) return ''
    return id
  } catch { return '' }
}

/** 读角色稿：优先样本目录（用户可改），再退到共享 agents 根。 */
function readRoleFile(role) {
  if (!parseReverseRole('reverseRole: ' + role)) return ''
  const candidates = []
  const sid = currentSampleId()
  if (sid) candidates.push(join(reverseRoot(), 'samples', sid, 'agents', role + '.md'))
  candidates.push(join(reverseRoot(), 'agents', role + '.md'))
  for (const p of candidates) {
    try {
      if (existsSync(p)) return readFileSync(p, 'utf8').trim()
    } catch { /* 换下一个 */ }
  }
  return ''
}

/** 给当前子会话组装角色稿正文；不是逆向子会话就给空串。 */
export function resolveSubagentRoleText(context) {
  try {
    const agent = context?.agent
    const session = agent?.session || context?.session
    if (!isReverseChild(session)) return ''
    const sessionId = session?.id ?? agent?.id
    let role = sessionId !== undefined && sessionId !== null
      ? roleBySession.get(String(sessionId)) || ''
      : ''
    if (!role) {
      role = roleFromSessionEvents(session)
      if (role) remember(agent || { session }, role)
    }
    if (!role) return ''
    return readRoleFile(role)
  } catch {
    return ''
  }
}

/** 挂上「领消息」捕获。 */
export function installSubagentRoleCapture(ctx) {
  if (!ctx || typeof ctx.on !== 'function') return
  if (ctx.__dshPurgeReverseRoleCapture) return
  ctx.__dshPurgeReverseRoleCapture = true

  const hook = (payload) => {
    try { noteClaimedMessage(payload) } catch { /* 记角色失败不阻断领消息 */ }
  }

  const effect = ctx.effect
  if (typeof effect === 'function') {
    effect.call(ctx, () => {
      let installed = false
      let disposer = null
      const install = () => {
        if (installed) return
        try {
          disposer = ctx.on('agent/inbox/claimed', hook, { global: true, prepend: true })
          installed = true
        } catch { /* ignore */ }
      }
      install()
      queueMicrotask(install)
      const timer = setTimeout(install, 800)
      return () => {
        clearTimeout(timer)
        try { if (typeof disposer === 'function') disposer() } catch { /* ignore */ }
        delete ctx.__dshPurgeReverseRoleCapture
      }
    })
    return
  }

  let installed = false
  const install = () => {
    if (installed) return
    try { ctx.on('agent/inbox/claimed', hook, { global: true, prepend: true }); installed = true } catch { /* ignore */ }
  }
  install()
  queueMicrotask(install)
  setTimeout(install, 800)
}

/**
 * 把角色稿插进 sections。
 * 位置：紧跟 dsh-purge / capability 段之后，保持"身份在前、角色在后"的次序。
 */
export function insertRoleSection(sections, roleText, order = -99999) {
  const body = typeof roleText === 'string' ? roleText.trim() : ''
  if (!body) return sections
  const list = Array.isArray(sections) ? sections : []
  if (list.some((s) => String(s?.text || '').includes(body))) return list
  const section = { name: REVERSE_ROLE_SECTION, text: body, order, interpolate: false }
  const at = list.findIndex((s) => String(s?.name || '').startsWith('dsh-capability'))
  const next = list.slice()
  next.splice(at >= 0 ? at + 1 : 0, 0, section)
  return next
}
