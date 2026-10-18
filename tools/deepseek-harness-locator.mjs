#!/usr/bin/env node
/**
 * Cross-platform DeepSeek Harness locator.
 *
 * Usage:
 *   node tools/deepseek-harness-locator.mjs --json
 *   node tools/deepseek-harness-locator.mjs --first
 *
 * The locator is read-only. It checks explicit environment variables, known
 * per-platform install roots, PATH entries, and bounded child directories.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import process from 'node:process'
import { execFileSync } from 'node:child_process'

const isWin = process.platform === 'win32'
const isMac = process.platform === 'darwin'
const home = os.homedir()
const env = process.env
const seen = new Set()
const results = []

function expand(value) {
  if (!value) return ''
  return value
    .replace(/^~(?=$|[\\/])/, home)
    .replace(/%([^%]+)%/g, (_, key) => env[key] ?? `%${key}%`)
    .trim()
}

function canonical(value) {
  const p = path.resolve(expand(value))
  try { return fs.realpathSync.native(p) } catch { return p }
}

function marker(dir) {
  const p = canonical(dir)
  const candidates = isWin
    ? [path.join(p, 'DeepSeek Harness.exe'), path.join(p, 'resources', 'app.asar')]
    : isMac
      ? [path.join(p, 'Contents', 'MacOS', 'DeepSeek Harness'), path.join(p, 'Contents', 'Resources', 'app.asar')]
      : [path.join(p, 'deepseek-harness'), path.join(p, 'DeepSeek Harness'), path.join(p, 'resources', 'app.asar')]
  const hit = candidates.find((x) => fs.existsSync(x))
  if (!hit) return null
  return { installDir: isMac && p.endsWith('.app') ? p : path.dirname(hit), executable: hit }
}

function add(value, source, depth = 0) {
  if (!value || depth > 3) return
  const raw = canonical(value)
  let st
  try { st = fs.statSync(raw) } catch { return }
  const dir = st.isDirectory() ? raw : path.dirname(raw)
  const found = marker(dir) ?? marker(st.isDirectory() ? path.join(raw, 'DeepSeek Harness.app') : dir)
  if (found) {
    const key = canonical(found.installDir)
    if (!seen.has(key)) {
      seen.add(key)
      results.push({ ...found, installDir: key, source })
    }
    return
  }
  if (!st.isDirectory() || depth === 3) return
  let children
  try { children = fs.readdirSync(raw, { withFileTypes: true }) } catch { return }
  for (const child of children) {
    if (!child.isDirectory()) continue
    if (/^(node_modules|cache|code cache|user data|local storage)$/i.test(child.name)) continue
    add(path.join(raw, child.name), `${source}:scan`, depth + 1)
  }
}

function pathCommands() {
  const names = isWin
    ? ['DeepSeek Harness.exe', 'deepseek-harness.exe', 'dsh.exe']
    : ['DeepSeek Harness', 'deepseek-harness', 'dsh']
  for (const name of names) {
    try {
      const out = execFileSync(isWin ? 'where.exe' : 'which', [name], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] })
      for (const line of out.split(/\r?\n/).map((x) => x.trim()).filter(Boolean)) add(line, 'PATH')
    } catch { /* command absent */ }
  }
}

for (const key of ['DEEPSEEK_HARNESS_PATH', 'DSH_INSTALL_PATH', 'DEEPSEEK_HARNESS_HOME']) {
  if (env[key]) add(env[key], `env:${key}`)
}

const roots = isWin
  ? [env.LOCALAPPDATA && path.join(env.LOCALAPPDATA, 'Programs'), env.LOCALAPPDATA, env.ProgramFiles, env['ProgramFiles(x86)'], path.join(home, 'scoop', 'apps'), path.join(home, 'AppData', 'Local')]
  : isMac
    ? ['/Applications', path.join(home, 'Applications'), path.join(home, 'Library', 'Application Support')]
    : ['/opt', '/usr/local', '/usr/bin', path.join(home, '.local', 'share'), path.join(home, '.local', 'bin'), path.join(home, 'Applications')]
for (const root of roots.filter(Boolean)) add(root, 'known-root')
pathCommands()

results.sort((a, b) => {
  const rank = (x) => x.source.startsWith('env:') ? 0 : x.source === 'PATH' ? 1 : 2
  return rank(a) - rank(b) || a.installDir.localeCompare(b.installDir)
})

const first = results[0] ?? null
const args = new Set(process.argv.slice(2))
if (args.has('--first')) {
  process.stdout.write(first ? `${first.installDir}\n` : '')
} else if (args.has('--json') || args.size === 0) {
  process.stdout.write(JSON.stringify({ platform: process.platform, found: results.length > 0, installations: results }, null, 2) + '\n')
} else {
  console.error('Usage: deepseek-harness-locator [--json|--first]')
  process.exitCode = 2
}
