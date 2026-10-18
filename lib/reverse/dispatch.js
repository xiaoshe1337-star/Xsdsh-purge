/**
 * 逆向模式 · 统一 dispatch 层
 *
 * 界面（ui.js 的 HTTP 桥接）与命令行共用同一份实现，
 * 保证「面板看到的」和「智能体写入的」是同一份事实库。
 */
import { ROLE_TITLES, PHASE_TITLES, PHASE_ORDER, PLATFORM_TITLES } from './store-core.js'

/** 面板首页摘要。 */
function digest(st, store) {
  const samples = store.listSamples()
  const activeId = store.activeSampleId()
  const active = activeId ? store.getSample(activeId) : null
  return {
    ok: true,
    samples: samples.map((s) => ({
      id: s.id,
      name: s.name,
      platform: s.platform,
      platform_title: PLATFORM_TITLES[s.platform] || s.platform,
      n_binaries: s.n_binaries,
      n_findings: s.n_findings,
      updated_at: s.updated_at,
    })),
    active: activeId || null,
    stats: active ? store.stats(activeId) : null,
    progress: active ? store.phaseProgress(activeId) : [],
    roles: Object.entries(ROLE_TITLES).map(([code, title]) => ({ code, title })),
    phases: PHASE_ORDER.map((code) => ({ code, title: PHASE_TITLES[code] })),
    root: store.root,
  }
}

/**
 * 处理一条界面请求。
 * @param store - ReverseStore 实例
 * @param op - 操作名
 * @param payload - 参数
 */
export function dispatch(store, op, payload = {}) {
  const a = payload || {}
  switch (String(op || '')) {
    case 'digest':
      return digest(null, store)

    case 'samples':
      return { ok: true, samples: store.listSamples() }

    case 'sample': {
      const id = a.id || store.activeSampleId()
      if (!id) return { ok: false, error: '未打开任何样本' }
      const s = store.getSample(id)
      if (!s) return { ok: false, error: '样本不存在: ' + id }
      return { ok: true, sample: s, stats: store.stats(id), progress: store.phaseProgress(id) }
    }

    case 'open': {
      const s = store.openSample(a.name, { platform: a.platform, note: a.note })
      return { ok: true, sample: s, stats: store.stats(s.id) }
    }

    case 'bind': {
      const id = store.setActiveSample(a.id)
      return { ok: true, active: id, stats: store.stats(id) }
    }

    case 'binary_add': {
      const sid = a.sample || store.activeSampleId()
      if (!sid) return { ok: false, error: '先打开一个样本' }
      const b = store.addBinary(sid, a.path, {
        role: a.role, arch: a.arch, bits: a.bits,
        entropy: typeof a.entropy === 'number' ? a.entropy : undefined,
        protection: a.protection, note: a.note,
      })
      return { ok: true, binary: b }
    }

    case 'finding_add': {
      const sid = a.sample || store.activeSampleId()
      if (!sid) return { ok: false, error: '先打开一个样本' }
      const f = store.addFinding(sid, a)
      return { ok: true, finding: f, stats: store.stats(sid) }
    }

    case 'finding_verify': {
      return { ok: true, ...store.verifyFinding(a.id, !!a.passed, a.detail) }
    }

    case 'artifact_add': {
      const sid = a.sample || store.activeSampleId()
      if (!sid) return { ok: false, error: '先打开一个样本' }
      const art = store.addArtifact(sid, a)
      return { ok: true, artifact: art }
    }

    case 'chain_add': {
      const sid = a.sample || store.activeSampleId()
      if (!sid) return { ok: false, error: '先打开一个样本' }
      const s = store.addChainStep(sid, a)
      return { ok: true, step: s }
    }

    case 'report': {
      const sid = a.sample || store.activeSampleId()
      if (!sid) return { ok: false, error: '先打开一个样本' }
      return { ok: true, report: store.report(sid) }
    }

    case 'report_write': {
      const sid = a.sample || store.activeSampleId()
      if (!sid) return { ok: false, error: '先打开一个样本' }
      return { ok: true, ...store.writeReport(sid, a.path) }
    }

    case 'roles': {
      return {
        ok: true,
        roles: Object.entries(ROLE_TITLES).map(([code, title]) => ({ code, title })),
        phases: PHASE_ORDER.map((code) => ({ code, title: PHASE_TITLES[code] })),
      }
    }

    default:
      return { ok: false, error: '未知操作: ' + op }
  }
}

/** 异步版本（当前实现全同步，保留签名给将来的网络探测类 op）。 */
export async function dispatchAsync(store, op, payload = {}) {
  return dispatch(store, op, payload)
}
