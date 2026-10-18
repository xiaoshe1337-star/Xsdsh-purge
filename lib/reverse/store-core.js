/**
 * 逆向模式 · 数据层核心（无 Cordis 依赖）
 *
 * 与红队的 RedteamStore 是同构设计：一个样本库 + 事实表 + 证据链 + 评分。
 * 差异点（按逆向的语义重命名）：
 *   engagement  → sample（"本次分析的样本 / 目标"）
 *   asset       → finding（"一条逆向结论"）
 *   vuln        → artifact（"一个中间产物 / 导出件"）
 *   stage       → phase（逆向五阶段）
 *
 * 依赖：node:sqlite（Node 22+ 内置，DSH 运行时自带），零外部依赖。
 */
import { DatabaseSync } from 'node:sqlite'
import { createHash } from 'node:crypto'
import { homedir } from 'node:os'
import {
  mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync, rmSync,
  statSync, copyFileSync, unlinkSync,
} from 'node:fs'
import { join, basename, isAbsolute, dirname } from 'node:path'

/* ── 角色与阶段 ──────────────────────────────────────────────────────────── */

/** 执行角色（顺序即默认派活顺序）。 */
export const ROLE_ORDER = ['static', 'dynamic', 'unpack', 'protocol', 'protect']

/** 指挥自身。 */
export const PLANNER_ROLE = 'plan'

/** 角色中文名。 */
export const ROLE_TITLES = {
  plan: '指挥',
  static: '静态分析',
  dynamic: '动态调试',
  unpack: '脱壳解混淆',
  protocol: '协议还原',
  protect: '保护对抗',
}

/** 逆向五阶段。 */
export const PHASE_ORDER = ['baseline', 'protect', 'dynamic', 'unpack', 'protocol']

/** 阶段中文名。 */
export const PHASE_TITLES = {
  baseline: '① 静态基线',
  protect: '② 保护识别与对抗',
  dynamic: '③ 动态调试',
  unpack: '④ 脱壳解混淆',
  protocol: '⑤ 协议与算法还原',
}

/** 阶段有效 code。 */
export const VALID_PHASE_CODES = PHASE_ORDER.slice()

/** 平台。 */
export const PLATFORM_ORDER = ['android', 'ios', 'windows', 'linux', 'cross']

export const PLATFORM_TITLES = {
  android: 'Android',
  ios: 'iOS',
  windows: 'Windows',
  linux: 'Linux / ELF',
  cross: '跨平台 / 其它',
}

/** 结论类型（决定报告里怎么归类）。 */
export const FINDING_KINDS = [
  'structure',   // 文件结构 / 架构 / 入口
  'protection',  // 保护方案识别
  'crypto',      // 算法与密钥
  'protocol',    // 协议字段与状态机
  'behavior',    // 运行时行为
  'unpack',      // 脱壳产物
  'bypass',      // 保护绕过
  'other',
]

/** 保护的常见取值（只是提示，不限制自由填）。 */
export const KNOWN_PROTECTIONS = [
  'none', 'upx', 'aspack', 'mpress', 'vmprotect', 'themida', 'enigma', 'petite',
  'ollvm', 'hikari', 'jiagu360', 'tencent-legu', 'bangbang', 'ali-jiaagu',
  'netease-yidun', 'ijiami', 'naga', 'kiwi', 'baidu', 'nqshield',
  'fairplay', 'play-integrity', 'safetynet', 'ace', 'battleye', 'eac',
  'nprotect', 'tenprotect', 'vanguard', 'xigncode', 'custom',
]

/* ── 工具 ────────────────────────────────────────────────────────────────── */

function nowIso() {
  return new Date().toISOString()
}

function ensureDir(dir) {
  mkdirSync(dir, { recursive: true })
  return dir
}

function safeName(text, max = 120) {
  const raw = String(text || '').trim()
  if (!raw) return ''
  const cleaned = raw.replace(/[\\/:*?"<>|\x00-\x1f]/g, '_').replace(/\s+/g, ' ').trim()
  return cleaned.length > max ? cleaned.slice(0, max) : cleaned
}

function sha256File(path) {
  const buf = readFileSync(path)
  return createHash('sha256').update(buf).digest('hex')
}

function sha256Text(text) {
  return createHash('sha256').update(String(text || ''), 'utf8').digest('hex')
}

function fileSize(path) {
  try { return statSync(path).size } catch { return null }
}

/** 逗号/空白分隔 → 去重数组。 */
export function splitList(value) {
  return String(value || '')
    .split(/[,，;\s]+/)
    .map((x) => x.trim())
    .filter(Boolean)
}

/** 猜平台：按扩展名 / magic 提示，判不出来给 cross。 */
export function guessPlatform(name, note) {
  const text = `${name || ''} ${note || ''}`.toLowerCase()
  if (/\.(apk|aab|xapk|apks|dex)$/.test(text) || text.includes('android')) return 'android'
  if (/\.(ipa|dylib|macho)$/.test(text) || text.includes('mach-o') || text.includes('ios')) return 'ios'
  if (/\.(exe|dll|sys|scr|ocx|msi)$/.test(text) || text.includes('pe32') || text.includes('windows')) return 'windows'
  if (/\.(so|elf|ko|o)$/.test(text) || text.includes('elf') || text.includes('linux')) return 'linux'
  return 'cross'
}

/* ── 主类 ────────────────────────────────────────────────────────────────── */

export class ReverseStore {
  /** @param root - 数据根目录（$DSH_HOME/reverse）。 */
  constructor(root) {
    this.root = root
    this.samplesDir = join(root, 'samples')
    this.dbPath = join(root, 'reverse.db')
    this.artifactsDir = join(root, 'artifacts')
    this.reportsDir = join(root, 'reports')

    ensureDir(this.root)
    ensureDir(this.samplesDir)
    ensureDir(this.artifactsDir)
    ensureDir(this.reportsDir)

    this._db = new DatabaseSync(this.dbPath)
    this._db.exec('PRAGMA journal_mode = WAL;')
    this._db.exec('PRAGMA foreign_keys = ON;')
    this._migrate()
  }

  get db() { return this._db }

  close() {
    try { this._db.close() } catch { /* 已关闭 */ }
  }

  /* ── schema ───────────────────────────────────────────────────────────── */

  _migrate() {
    this._db.exec(`
      CREATE TABLE IF NOT EXISTS samples (
        id           TEXT PRIMARY KEY,
        name         TEXT NOT NULL,
        platform     TEXT NOT NULL DEFAULT 'cross',
        note         TEXT DEFAULT '',
        dir          TEXT NOT NULL,
        created_at   TEXT NOT NULL,
        updated_at   TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS binaries (
        id           TEXT PRIMARY KEY,
        sample_id    TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
        role         TEXT NOT NULL DEFAULT 'primary',
        file_name    TEXT NOT NULL,
        path         TEXT NOT NULL,
        sha256       TEXT,
        size         INTEGER,
        arch         TEXT DEFAULT '',
        bits         TEXT DEFAULT '',
        entropy      REAL,
        protection   TEXT DEFAULT 'none',
        note         TEXT DEFAULT '',
        added_at     TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_binaries_sample ON binaries(sample_id);
      CREATE INDEX IF NOT EXISTS idx_binaries_sha ON binaries(sha256);

      CREATE TABLE IF NOT EXISTS findings (
        id           TEXT PRIMARY KEY,
        sample_id    TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
        phase        TEXT NOT NULL DEFAULT 'baseline',
        role         TEXT NOT NULL DEFAULT 'plan',
        kind         TEXT NOT NULL DEFAULT 'other',
        title        TEXT NOT NULL,
        detail       TEXT DEFAULT '',
        evidence     TEXT DEFAULT '',
        confidence   TEXT DEFAULT 'medium',
        verified     INTEGER NOT NULL DEFAULT 0,
        binary_id    TEXT,
        created_at   TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_findings_sample ON findings(sample_id, phase);

      CREATE TABLE IF NOT EXISTS artifacts (
        id           TEXT PRIMARY KEY,
        sample_id    TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
        kind         TEXT NOT NULL DEFAULT 'file',
        title        TEXT NOT NULL,
        path         TEXT DEFAULT '',
        sha256       TEXT DEFAULT '',
        size         INTEGER,
        note         TEXT DEFAULT '',
        created_at   TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_artifacts_sample ON artifacts(sample_id);

      CREATE TABLE IF NOT EXISTS chain (
        id           TEXT PRIMARY KEY,
        sample_id    TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
        seq          INTEGER NOT NULL,
        phase        TEXT NOT NULL,
        role         TEXT NOT NULL,
        title        TEXT NOT NULL,
        tool         TEXT DEFAULT '',
        command      TEXT DEFAULT '',
        result       TEXT DEFAULT '',
        created_at   TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_chain_sample ON chain(sample_id, seq);

      CREATE TABLE IF NOT EXISTS verify (
        id           TEXT PRIMARY KEY,
        sample_id    TEXT NOT NULL REFERENCES samples(id) ON DELETE CASCADE,
        target       TEXT NOT NULL,
        level        TEXT NOT NULL DEFAULT 'L1',
        passed       INTEGER NOT NULL DEFAULT 0,
        detail       TEXT DEFAULT '',
        created_at   TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_verify_sample ON verify(sample_id);
    `)
  }

  /* ── samples ──────────────────────────────────────────────────────────── */

  listSamples() {
    const rows = this._db.prepare(
      `SELECT s.*, 
              (SELECT COUNT(*) FROM binaries b WHERE b.sample_id = s.id) AS n_binaries,
              (SELECT COUNT(*) FROM findings f WHERE f.sample_id = s.id) AS n_findings
         FROM samples s ORDER BY s.updated_at DESC`,
    ).all()
    return rows
  }

  getSample(id) {
    const row = this._db.prepare('SELECT * FROM samples WHERE id = ?').get(String(id))
    if (!row) return null
    return {
      ...row,
      binaries: this.listBinaries(row.id),
      findings: this.listFindings(row.id),
      artifacts: this.listArtifacts(row.id),
      chain: this.listChain(row.id),
    }
  }

  /**
   * 打开或创建样本工作区。
   * @param name - 样本 / 目标名称。
   * @param opts - `{ platform?, note?, id? }`
   */
  openSample(name, opts = {}) {
    const clean = safeName(name)
    if (!clean) throw new Error('样本名称不能为空')
    const id = safeName(opts.id || clean, 80) || sha256Text(clean).slice(0, 16)
    const platform = PLATFORM_TITLES[opts.platform] ? opts.platform : guessPlatform(clean, opts.note)
    const dir = join(this.samplesDir, id)
    ensureDir(dir)
    ensureDir(join(dir, 'agents'))
    const ts = nowIso()

    const existing = this._db.prepare('SELECT * FROM samples WHERE id = ?').get(id)
    if (existing) {
      this._db.prepare('UPDATE samples SET note = ?, platform = ?, updated_at = ? WHERE id = ?')
        .run(opts.note ?? existing.note, platform, ts, id)
      this.setActiveSample(id)
      return this.getSample(id)
    }

    this._db.prepare(
      'INSERT INTO samples (id, name, platform, note, dir, created_at, updated_at) VALUES (?,?,?,?,?,?,?)',
    ).run(id, clean, platform, opts.note || '', dir, ts, ts)
    this.setActiveSample(id)

    /* 角色稿随样本落地：指挥派活时子会话从这里读 agents/<code>.md */
    this._seedRoleFiles(dir)

    return this.getSample(id)
  }

  _seedRoleFiles(sampleDir) {
    const agentsDir = join(sampleDir, 'agents')
    ensureDir(agentsDir)
    const bundled = join(this.root, 'agents')
    if (!existsSync(bundled)) return
    for (const name of readdirSync(bundled)) {
      if (!name.endsWith('.md')) continue
      const src = join(bundled, name)
      const dst = join(agentsDir, name)
      if (!existsSync(dst)) {
        try { copyFileSync(src, dst) } catch { /* 权限问题不阻断开样本 */ }
      }
    }
  }

  activeSampleId() {
    try {
      const raw = readFileSync(join(this.root, 'current'), 'utf8').trim()
      return raw || undefined
    } catch { return undefined }
  }

  setActiveSample(id) {
    const clean = safeName(id, 200)
    if (!clean) throw new Error('样本 id 非法')
    if (!this._db.prepare('SELECT 1 FROM samples WHERE id = ?').get(clean)) {
      throw new Error('样本不存在: ' + clean)
    }
    writeFileSync(join(this.root, 'current'), clean, 'utf8')
    return clean
  }

  /* ── binaries ─────────────────────────────────────────────────────────── */

  listBinaries(sampleId) {
    return this._db.prepare(
      'SELECT * FROM binaries WHERE sample_id = ? ORDER BY added_at',
    ).all(String(sampleId))
  }

  /**
   * 登记一个待分析的二进制文件（自动算 sha256 / size）。
   * @param sampleId - 样本 id
   * @param path - 文件路径
   * @param opts - `{ role?, arch?, bits?, entropy?, protection?, note? }`
   */
  addBinary(sampleId, path, opts = {}) {
    const abs = isAbsolute(path) ? path : join(this.root, path)
    if (!existsSync(abs)) throw new Error('文件不存在: ' + abs)
    const st = statSync(abs)
    if (!st.isFile()) throw new Error('不是普通文件: ' + abs)
    const sha = sha256File(abs)
    const fileName = basename(abs)
    const role = opts.role || 'primary'
    const id = `${String(sampleId)}-${sha.slice(0, 12)}-${safeName(role, 16)}`

    const dup = this._db.prepare('SELECT * FROM binaries WHERE id = ?').get(id)
    const ts = nowIso()
    if (dup) {
      this._db.prepare(
        `UPDATE binaries SET path = ?, size = ?, arch = COALESCE(NULLIF(?, ''), arch),
         bits = COALESCE(NULLIF(?, ''), bits), entropy = COALESCE(?, entropy),
         protection = COALESCE(NULLIF(?, ''), protection), note = COALESCE(NULLIF(?, ''), note)
         WHERE id = ?`,
      ).run(abs, st.size, opts.arch || '', opts.bits || '',
        typeof opts.entropy === 'number' ? opts.entropy : null,
        opts.protection || '', opts.note || '', id)
      this._touchSample(sampleId)
      return this._db.prepare('SELECT * FROM binaries WHERE id = ?').get(id)
    }

    this._db.prepare(
      `INSERT INTO binaries (id, sample_id, role, file_name, path, sha256, size, arch, bits,
         entropy, protection, note, added_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(id, String(sampleId), role, fileName, abs, sha, st.size,
      opts.arch || '', opts.bits || '',
      typeof opts.entropy === 'number' ? opts.entropy : null,
      opts.protection || 'none', opts.note || '', ts)
    this._touchSample(sampleId)
    return this._db.prepare('SELECT * FROM binaries WHERE id = ?').get(id)
  }

  getBinary(id) {
    return this._db.prepare('SELECT * FROM binaries WHERE id = ?').get(String(id)) || null
  }

  /* ── findings ─────────────────────────────────────────────────────────── */

  listFindings(sampleId, phase) {
    if (phase) {
      return this._db.prepare(
        'SELECT * FROM findings WHERE sample_id = ? AND phase = ? ORDER BY created_at',
      ).all(String(sampleId), String(phase))
    }
    return this._db.prepare(
      'SELECT * FROM findings WHERE sample_id = ? ORDER BY created_at',
    ).all(String(sampleId))
  }

  /**
   * 落一条结论。**没落库的结论 = 没发生。**
   * @param sampleId - 样本 id
   * @param data - `{ title, detail?, evidence?, phase?, role?, kind?, confidence?, verified?, binaryId? }`
   */
  addFinding(sampleId, data = {}) {
    const title = String(data.title || '').trim()
    if (!title) throw new Error('结论标题不能为空（title 必填）')
    const phase = VALID_PHASE_CODES.includes(data.phase) ? data.phase : 'baseline'
    const role = ROLE_TITLES[data.role] ? data.role : PLANNER_ROLE
    const kind = FINDING_KINDS.includes(data.kind) ? data.kind : 'other'
    const confidence = ['low', 'medium', 'high'].includes(data.confidence) ? data.confidence : 'medium'
    const ts = nowIso()
    const id = 'F-' + sha256Text(`${sampleId}|${title}|${ts}|${Math.random()}`).slice(0, 12)

    this._db.prepare(
      `INSERT INTO findings (id, sample_id, phase, role, kind, title, detail, evidence,
         confidence, verified, binary_id, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).run(id, String(sampleId), phase, role, kind, title,
      String(data.detail || ''), String(data.evidence || ''),
      confidence, data.verified ? 1 : 0, data.binaryId || null, ts)
    this._touchSample(sampleId)
    return this._db.prepare('SELECT * FROM findings WHERE id = ?').get(id)
  }

  /**
   * 标记结论已验证（L2/L3 通过才能置 1）。
   */
  verifyFinding(findingId, passed, detail = '') {
    const row = this._db.prepare('SELECT * FROM findings WHERE id = ?').get(String(findingId))
    if (!row) throw new Error('结论不存在: ' + findingId)
    this._db.prepare('UPDATE findings SET verified = ? WHERE id = ?')
      .run(passed ? 1 : 0, String(findingId))
    const ts = nowIso()
    const id = 'V-' + sha256Text(`${findingId}|${ts}|${Math.random()}`).slice(0, 12)
    this._db.prepare(
      'INSERT INTO verify (id, sample_id, target, level, passed, detail, created_at) VALUES (?,?,?,?,?,?,?)',
    ).run(id, row.sample_id, String(findingId), 'L2', passed ? 1 : 0, String(detail || ''), ts)
    this._touchSample(row.sample_id)
    return { finding_id: String(findingId), verified: passed ? 1 : 0 }
  }

  listVerify(sampleId) {
    return this._db.prepare(
      'SELECT * FROM verify WHERE sample_id = ? ORDER BY created_at',
    ).all(String(sampleId))
  }

  /* ── artifacts ────────────────────────────────────────────────────────── */

  listArtifacts(sampleId) {
    return this._db.prepare(
      'SELECT * FROM artifacts WHERE sample_id = ? ORDER BY created_at',
    ).all(String(sampleId))
  }

  /**
   * 登记产物（脱壳后的 dex/so、dump 出来的内存、还原的算法脚本）。
   * 文件会复制到 `<root>/artifacts/<sample>/`，原文件不动。
   */
  addArtifact(sampleId, data = {}) {
    const title = String(data.title || '').trim()
    if (!title) throw new Error('产物标题不能为空（title 必填）')
    const kind = String(data.kind || 'file')
    const ts = nowIso()
    const id = 'A-' + sha256Text(`${sampleId}|${title}|${ts}|${Math.random()}`).slice(0, 12)

    let outPath = String(data.path || '')
    let sha = String(data.sha256 || '')
    let size = null

    if (outPath) {
      const abs = isAbsolute(outPath) ? outPath : join(this.root, outPath)
      if (existsSync(abs) && statSync(abs).isFile()) {
        const storeDir = ensureDir(join(this.artifactsDir, String(sampleId)))
        const dst = join(storeDir, `${id}-${safeName(basename(abs))}`)
        try {
          copyFileSync(abs, dst)
          outPath = dst
          sha = sha256File(dst)
          size = fileSize(dst)
        } catch {
          sha = sha256File(abs)
          size = fileSize(abs)
          outPath = abs
        }
      } else if (!sha) {
        throw new Error('产物路径不存在且未给 sha256: ' + abs)
      }
    }

    this._db.prepare(
      `INSERT INTO artifacts (id, sample_id, kind, title, path, sha256, size, note, created_at)
       VALUES (?,?,?,?,?,?,?,?,?)`,
    ).run(id, String(sampleId), kind, title, outPath, sha, size, String(data.note || ''), ts)
    this._touchSample(sampleId)
    return this._db.prepare('SELECT * FROM artifacts WHERE id = ?').get(id)
  }

  /* ── chain ────────────────────────────────────────────────────────────── */

  listChain(sampleId) {
    return this._db.prepare(
      'SELECT * FROM chain WHERE sample_id = ? ORDER BY seq',
    ).all(String(sampleId))
  }

  /**
   * 记一步分析动作。**报告里"壳怎么脱的、算法怎么还原的"全靠这张表。**
   * @param data - `{ phase, role, title, tool?, command?, result? }`
   */
  addChainStep(sampleId, data = {}) {
    const title = String(data.title || '').trim()
    if (!title) throw new Error('步骤标题不能为空（title 必填）')
    const phase = VALID_PHASE_CODES.includes(data.phase) ? data.phase : 'baseline'
    const role = ROLE_TITLES[data.role] ? data.role : PLANNER_ROLE
    const prev = this._db.prepare(
      'SELECT MAX(seq) AS n FROM chain WHERE sample_id = ?',
    ).get(String(sampleId))
    const seq = (prev?.n ?? 0) + 1
    const ts = nowIso()
    const id = 'S-' + sha256Text(`${sampleId}|${seq}|${ts}|${Math.random()}`).slice(0, 12)

    this._db.prepare(
      `INSERT INTO chain (id, sample_id, seq, phase, role, title, tool, command, result, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?)`,
    ).run(id, String(sampleId), seq, phase, role, title,
      String(data.tool || ''), String(data.command || ''), String(data.result || ''), ts)
    this._touchSample(sampleId)
    return this._db.prepare('SELECT * FROM chain WHERE id = ?').get(id)
  }

  /* ── 统计 / 报告 ──────────────────────────────────────────────────────── */

  stats(sampleId) {
    const id = String(sampleId)
    const one = (sql, ...args) => this._db.prepare(sql).get(id, ...args)?.n ?? 0

    const byPhase = {}
    for (const p of PHASE_ORDER) {
      byPhase[p] = {
        title: PHASE_TITLES[p],
        findings: one('SELECT COUNT(*) AS n FROM findings WHERE sample_id = ? AND phase = ?', p),
        steps: one('SELECT COUNT(*) AS n FROM chain WHERE sample_id = ? AND phase = ?', p),
      }
    }

    return {
      sample: id,
      binaries: one('SELECT COUNT(*) AS n FROM binaries WHERE sample_id = ?'),
      findings: one('SELECT COUNT(*) AS n FROM findings WHERE sample_id = ?'),
      verified: one('SELECT COUNT(*) AS n FROM findings WHERE sample_id = ? AND verified = 1'),
      artifacts: one('SELECT COUNT(*) AS n FROM artifacts WHERE sample_id = ?'),
      steps: one('SELECT COUNT(*) AS n FROM chain WHERE sample_id = ?'),
      checks: one('SELECT COUNT(*) AS n FROM verify WHERE sample_id = ?'),
      checks_pass: one('SELECT COUNT(*) AS n FROM verify WHERE sample_id = ? AND passed = 1'),
      by_phase: byPhase,
      current_phase: this.currentPhase(id),
    }
  }

  /** 五个阶段里第一个还没结论的阶段 = 当前位置。 */
  currentPhase(sampleId) {
    for (const p of PHASE_ORDER) {
      const n = this._db.prepare(
        'SELECT COUNT(*) AS n FROM findings WHERE sample_id = ? AND phase = ?',
      ).get(String(sampleId), p)?.n ?? 0
      if (n === 0) return p
    }
    return 'protocol'
  }

  /** 阶段进度条（指挥汇报用）。 */
  phaseProgress(sampleId) {
    const st = this.stats(sampleId)
    return PHASE_ORDER.map((p, i) => ({
      seq: i + 1,
      code: p,
      title: PHASE_TITLES[p],
      findings: st.by_phase[p].findings,
      steps: st.by_phase[p].steps,
      done: st.by_phase[p].findings > 0,
    }))
  }

  /** 按样本聚合成报告数据。 */
  report(sampleId) {
    const sample = this.getSample(sampleId)
    if (!sample) throw new Error('样本不存在: ' + sampleId)
    const st = this.stats(sampleId)
    const byKind = {}
    for (const f of sample.findings) {
      byKind[f.kind] = (byKind[f.kind] || 0) + 1
    }
    return {
      sample: {
        id: sample.id,
        name: sample.name,
        platform: sample.platform,
        platform_title: PLATFORM_TITLES[sample.platform],
        note: sample.note,
        created_at: sample.created_at,
        updated_at: sample.updated_at,
      },
      binaries: sample.binaries,
      stats: st,
      progress: this.phaseProgress(sampleId),
      by_kind: byKind,
      findings: sample.findings,
      artifacts: sample.artifacts,
      chain: sample.chain,
      verify: this.listVerify(sampleId),
      generated_at: nowIso(),
    }
  }

  /** 把报告写成 markdown。 */
  writeReport(sampleId, outPath) {
    const r = this.report(sampleId)
    const lines = []
    lines.push(`# 逆向分析报告：${r.sample.name}`)
    lines.push('')
    lines.push(`- 样本 id：\`${r.sample.id}\``)
    lines.push(`- 平台：${r.sample.platform_title}（\`${r.sample.platform}\`）`)
    lines.push(`- 建档：${r.sample.created_at}`)
    lines.push(`- 更新：${r.sample.updated_at}`)
    if (r.sample.note) lines.push(`- 备注：${r.sample.note}`)
    lines.push('')
    lines.push('## 阶段进度')
    lines.push('')
    lines.push('| 阶段 | 结论数 | 步骤数 | 状态 |')
    lines.push('| --- | --- | --- | --- |')
    for (const p of r.progress) {
      lines.push(`| ${p.title} | ${p.findings} | ${p.steps} | ${p.done ? '已产出' : '未开始'} |`)
    }
    lines.push('')
    lines.push('## 二进制清单')
    lines.push('')
    if (r.binaries.length === 0) {
      lines.push('_（未登记）_')
    } else {
      lines.push('| 文件 | 角色 | 架构 | 熵 | 保护 | SHA256 |')
      lines.push('| --- | --- | --- | --- | --- | --- |')
      for (const b of r.binaries) {
        const arch = [b.arch, b.bits].filter(Boolean).join(' ') || '—'
        const ent = typeof b.entropy === 'number' ? b.entropy.toFixed(2) : '—'
        lines.push(`| ${b.file_name} | ${b.role} | ${arch} | ${ent} | ${b.protection} | \`${b.sha256}\` |`)
      }
    }
    lines.push('')
    lines.push('## 结论（按阶段）')
    if (r.findings.length === 0) {
      lines.push('')
      lines.push('_（暂无落库结论。没有证据的结论不计入报告。）_')
    }
    for (const p of PHASE_ORDER) {
      const rows = r.findings.filter((f) => f.phase === p)
      if (rows.length === 0) continue
      lines.push('')
      lines.push(`### ${PHASE_TITLES[p]}`)
      for (const f of rows) {
        lines.push('')
        lines.push(`#### ${f.id} ${f.title}`)
        lines.push('')
        lines.push(`- 角色：${ROLE_TITLES[f.role] || f.role}`)
        lines.push(`- 类型：${f.kind}`)
        lines.push(`- 置信度：${f.confidence}`)
        lines.push(`- 已验证：${f.verified ? '是（L2+ 通过）' : '否'}`)
        if (f.detail) {
          lines.push('')
          lines.push(f.detail)
        }
        if (f.evidence) {
          lines.push('')
          lines.push(`**证据**：${f.evidence}`)
        }
      }
    }
    lines.push('')
    lines.push('## 分析步骤（证据链）')
    if (r.chain.length === 0) {
      lines.push('')
      lines.push('_（无步骤记录。报告里"怎么做到的"缺这一步。）_')
    } else {
      lines.push('')
      lines.push('| # | 阶段 | 角色 | 做什么 | 工具 | 命令 | 结果 |')
      lines.push('| --- | --- | --- | --- | --- | --- | --- |')
      const esc = (s) => String(s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ')
      for (const s of r.chain) {
        lines.push(`| ${s.seq} | ${PHASE_TITLES[s.phase] || s.phase} | ${ROLE_TITLES[s.role] || s.role} `
          + `| ${esc(s.title)} | ${esc(s.tool)} | ${esc(s.command)} | ${esc(s.result)} |`)
      }
    }
    lines.push('')
    lines.push('## 产物')
    if (r.artifacts.length === 0) {
      lines.push('')
      lines.push('_（无产物）_')
    } else {
      lines.push('')
      lines.push('| id | 类型 | 标题 | SHA256 | 路径 |')
      lines.push('| --- | --- | --- | --- | --- |')
      for (const a of r.artifacts) {
        lines.push(`| ${a.id} | ${a.kind} | ${a.title} | \`${a.sha256 || '—'}\` | ${a.path || '—'} |`)
      }
    }
    if (r.verify.length) {
      lines.push('')
      lines.push('## 验收')
      lines.push('')
      lines.push('| 目标 | 级别 | 结果 | 说明 |')
      lines.push('| --- | --- | --- | --- |')
      for (const v of r.verify) {
        lines.push(`| ${v.target} | ${v.level} | ${v.passed ? 'PASS' : 'FAIL'} | ${v.detail || ''} |`)
      }
    }
    lines.push('')
    lines.push(`_生成时间：${r.generated_at}_`)

    const body = lines.join('\n')
    const dst = outPath
      ? (isAbsolute(outPath) ? outPath : join(this.root, outPath))
      : join(this.reportsDir, `${safeName(r.sample.id)}.md`)
    ensureDir(dirname(dst))
    writeFileSync(dst, body, 'utf8')
    return { path: dst, bytes: Buffer.byteLength(body) }
  }

  /* ── 内部 ─────────────────────────────────────────────────────────────── */

  _touchSample(sampleId) {
    try {
      this._db.prepare('UPDATE samples SET updated_at = ? WHERE id = ?')
        .run(nowIso(), String(sampleId))
    } catch { /* 样本已被删时忽略 */ }
  }
}

export { dispatch } from './dispatch.js'
