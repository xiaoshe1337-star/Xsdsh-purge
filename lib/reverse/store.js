/**
 * 逆向模式 · Store 的 Cordis host 插件壳
 *
 * 把 {@link ReverseStore} 发布为进程级服务 `ctx.reverse`，
 * 供 · 界面（经 reverse/ui 的 HTTP 桥接）
 *    · 角色工具行（preset 平面，软取 ctx.reverse）
 * 共用同一份 SQLite 事实库。
 *
 * 平面归属：host。同一样本的分析结论要跨会话被后续角色共享，
 * 服务实例必须进程级唯一。
 */
import { join } from 'node:path'
import { homedir } from 'node:os'
import { readFileSync } from 'node:fs'
import { ReverseStore } from './store-core.js'

/** Cordis 插件名。 */
export const name = 'reverse-store'

/** 无硬依赖：数据层不依赖其它服务即可激活。 */
export const inject = []

/** 解析数据根：显式配置 > DSH_REVERSE_HOME > $DSH_HOME/reverse。 */
function resolveRoot(config) {
  if (config && typeof config.root === 'string' && config.root.length > 0) return config.root
  if (process.env.DSH_REVERSE_HOME) return process.env.DSH_REVERSE_HOME
  const home = process.env.DSH_HOME || join(homedir(), '.dsh')
  return join(home, 'reverse')
}

/** 包身份（界面显示版本用）；读不到就返回 null，不影响功能。 */
function readSelfPackage() {
  for (const rel of ['../package.json', '../../package.json']) {
    try {
      const pkg = JSON.parse(readFileSync(new URL(rel, import.meta.url), 'utf8'))
      if (pkg && typeof pkg.name === 'string' && typeof pkg.version === 'string') {
        return {
          name: pkg.name,
          version: pkg.version,
          description: typeof pkg.description === 'string' ? pkg.description : '',
        }
      }
    } catch { /* 换下一个候选 */ }
  }
  return null
}

/**
 * @param ctx - 插件上下文。
 * @param config - `{ root?: string }`。
 */
export function apply(ctx, config = {}) {
  const root = resolveRoot(config)
  const store = new ReverseStore(root)

  const self = readSelfPackage()
  if (self !== null) {
    try { store.plugin = Object.freeze(self) } catch { /* 忽略 */ }
  }

  /* 服务随 fiber 卸载而关闭：SQLite 句柄在同一处释放。 */
  ctx.effect(() => () => store.close())

  ctx.provide('reverse', store)
}

export { ReverseStore }
