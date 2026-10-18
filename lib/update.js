import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import { promises as fsp } from "node:fs";
import http from "node:http";
import https from "node:https";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { atomicWriteSync, findDshHome } from "./core.js";
import { extractZipArchive } from "./zip-extract.js";

// ── 更新源解析 ────────────────────────────────────────────────────────
// 原作者仓库已停更（停更在 1.1.71）。为了「检查更新」不再失效，源码地址改为
// 可配置：优先读 $DSH_HOME/dsh-purge/update-source.json，其次环境变量
// DSH_PURGE_REPO，最后回退到原作者仓库。配置只在内存缓存 30 秒，改完不用重启。
const DEFAULT_REPO = "YuJunZhiXue/dsh-purge";
// owner/name：每段首字符必须是字母数字，禁止 . 与 .. 作为整段，防目录穿越式注入。
const REPO_OWNER_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]*\/[A-Za-z0-9][A-Za-z0-9_.-]*$/;
const SOURCE_TTL = 30_000;

let _repoCache = { value: DEFAULT_REPO, at: 0, from: "default" };

function readSourceFile() {
  try {
    const home = process.env.DSH_HOME ? String(process.env.DSH_HOME).trim() : "";
    const dir = home || path.join(os.homedir(), ".dsh");
    const file = path.join(dir, "dsh-purge", "update-source.json");
    if (!fs.existsSync(file)) return null;
    const raw = JSON.parse(fs.readFileSync(file, "utf8"));
    const repo = String(raw?.repo || "").trim();
    if (!REPO_OWNER_RE.test(repo)) return null;
    const stable = String(raw?.refs?.stable || "").trim();
    return { repo, refs: stable ? { stable } : null };
  } catch {
    return null;
  }
}

/** 探测一次稳定分支：先试 master，再试 main。结果缓存 10 分钟。 */
let _branchProbe = { ref: "", at: 0 };
async function resolveStableRef() {
  // 配置显式指定了分支就不探测。
  const file = readSourceFile();
  if (file?.refs?.stable) {
    STABLE_REF = file.refs.stable;
    return STABLE_REF;
  }
  const repo = updateRepo();
  const now = Date.now();
  if (_branchProbe.ref && _branchProbe.repo === repo && now - _branchProbe.at < 600_000) {
    STABLE_REF = _branchProbe.ref;
    return STABLE_REF;
  }
  for (const candidate of ["master", "main"]) {
    const sha = await remoteHeadSha(candidate).catch(() => "");
    if (sha) {
      STABLE_REF = candidate;
      _branchProbe = { ref: candidate, at: now, repo };
      return candidate;
    }
  }
  STABLE_REF = "master";
  _branchProbe = { ref: "", at: now, repo };
  return STABLE_REF;
}

/** 当前生效的更新源仓库，形如 "owner/name"。 */
export function updateRepo() {
  const now = Date.now();
  if (now - _repoCache.at < SOURCE_TTL) return _repoCache.value;

  const file = readSourceFile();
  if (file) {
    _repoCache = { value: file.repo, at: now, from: "file" };
    return file.repo;
  }
  const env = String(process.env.DSH_PURGE_REPO || "").trim();
  if (REPO_OWNER_RE.test(env)) {
    _repoCache = { value: env, at: now, from: "env" };
    return env;
  }
  _repoCache = { value: DEFAULT_REPO, at: now, from: "default" };
  return DEFAULT_REPO;
}

/** 更新源诊断信息，给 UI 与排障用。 */
export function updateSourceInfo() {
  const repo = updateRepo();
  return {
    repo,
    ref: STABLE_REF,
    from: _repoCache.from,
    isDefault: repo === DEFAULT_REPO,
    file: path.join(
      process.env.DSH_HOME ? String(process.env.DSH_HOME).trim() : path.join(os.homedir(), ".dsh"),
      "dsh-purge",
      "update-source.json",
    ),
  };
}

/** 写入更新源配置。传空字符串表示清除、回到默认。 */
export function setUpdateRepo(repo, refs) {
  const value = String(repo || "").trim();
  if (value && !REPO_OWNER_RE.test(value)) {
    throw new Error("仓库地址格式应为 owner/name");
  }
  const stable = String(refs?.stable || "").trim();
  if (stable && !/^[A-Za-z0-9][A-Za-z0-9_.\/-]*$/.test(stable)) {
    throw new Error("分支名不合法");
  }
  const home = process.env.DSH_HOME ? String(process.env.DSH_HOME).trim() : "";
  const dir = path.join(home || path.join(os.homedir(), ".dsh"), "dsh-purge");
  const file = path.join(dir, "update-source.json");
  if (!value) {
    try { fs.rmSync(file, { force: true }); } catch { /* 清不掉下次再试 */ }
    _repoCache = { value: DEFAULT_REPO, at: Date.now(), from: "default" };
    STABLE_REF = "master";
    _branchProbe = { ref: "", at: 0, repo: DEFAULT_REPO };
    return updateSourceInfo();
  }
  fs.mkdirSync(dir, { recursive: true });
  const payload = stable ? { repo: value, refs: { stable } } : { repo: value };
  atomicWriteSync(file, JSON.stringify(payload, null, 2) + "\n");
  _repoCache = { value, at: Date.now(), from: "file" };
  if (stable) STABLE_REF = stable;
  // 换源必须重探分支：不同仓库默认分支名可能不同。
  _branchProbe = { ref: "", at: 0, repo: value };
  return updateSourceInfo();
}

// 稳定分支名。原作者仓库用 master，新建仓库默认多为 main。
// 这里保留 let：update-source.json 可以显式指定 refs.stable，
// 未指定时由 resolveStableRef() 探测一次并回写，避免只认 master 导致换成
// main 分支的仓库后 checkUpdate 永远报「无法读取 GitHub master」。
let STABLE_REF = "master";
const BETA_REF = "beta";
const PLUGIN_ROOT = path.resolve(fileURLToPath(new URL(".", import.meta.url)), "..");
const CHANNELS = {
  stable: { id: "stable", ref: STABLE_REF, label: "正式版" },
  beta: { id: "beta", ref: BETA_REF, label: "测试版" },
};
const COPY_NAMES = [
  "lib",
  "bin",
  "docs",
  "client.js",
  "cordis.patch.yml",
  "screenshots.json",
  "package.json",
  "README.md",
  "README.zh-CN.md",
  "LICENSE",
];

const HIDDEN = {
  encoding: "utf8",
  stdio: ["ignore", "pipe", "ignore"],
  windowsHide: true,
  timeout: 20000,
};

// 只允许来自 GitHub / jsdelivr 的 302 跳转落地,阻挡中间人把下载指向任意主机。
const UPDATE_REDIRECT_ALLOWED_HOSTS = new Set([
  "github.com",
  "codeload.github.com",
  "api.github.com",
  "raw.githubusercontent.com",
  "objects.githubusercontent.com",
  "release-assets.githubusercontent.com",
  "cdn.jsdelivr.net",
]);
const MAX_UPDATE_BYTES = 50 * 1024 * 1024;

export function pluginRoot() {
  return PLUGIN_ROOT;
}

export function localVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(PLUGIN_ROOT, "package.json"), "utf8"));
    return String(pkg.version || "");
  } catch {
    return "";
  }
}

function channelStatePath() {
  return path.join(findDshHome(), "dsh-purge", "channel.json");
}

function historyPath() {
  return path.join(findDshHome(), "dsh-purge", "version-history.json");
}

function stampPath() {
  return path.join(findDshHome(), "dsh-purge", "installed-rev");
}

function autoUpdateGuardPath() {
  return path.join(findDshHome(), "dsh-purge", "auto-update-guard.json");
}

function markAutoUpdateGuard(ref, sha = "") {
  atomicWriteSync(autoUpdateGuardPath(), `${JSON.stringify({
    ref: String(ref || ""),
    sha: String(sha || ""),
    at: new Date().toISOString(),
  }, null, 2)}\n`);
}

export function normalizeChannel(value) {
  return String(value || "").toLowerCase() === "beta" ? "beta" : "stable";
}

function isBetaName(name) {
  return /(?:^|[-._])(beta|rc|pre|preview|test)(?:\d|$|[-._])/i.test(String(name || ""));
}

function withdrawnVersion(item) {
  const text = [item?.version, item?.ref, item?.id].filter(Boolean).join(" ");
  return /(?:^|[\sv])1\.1\.11-beta/i.test(String(text).replace(/^v/i, " "));
}

function splitVersion(raw) {
  const text = String(raw || "").trim().replace(/^v/i, "");
  const cut = text.split("-");
  const core = String(cut[0] || "").split(".").map((n) => parseInt(n, 10) || 0);
  return { core: [core[0] || 0, core[1] || 0, core[2] || 0], pre: cut.slice(1).join("-") };
}

export function versionIsNewer(remote, local) {
  if (!remote) return false;
  if (!local) return true;
  if (String(remote) === String(local)) return false;
  const a = splitVersion(remote);
  const b = splitVersion(local);
  for (let i = 0; i < 3; i += 1) {
    if (a.core[i] !== b.core[i]) return a.core[i] > b.core[i];
  }
  if (a.pre && !b.pre) return false;
  if (!a.pre && b.pre) return true;
  return a.pre > b.pre;
}

export function latestStableVersion(versions) {
  let best = "";
  for (const item of versions || []) {
    if (!item || item.channel === "beta") continue;
    const ver = String(item.version || "").replace(/^v/i, "");
    // 允许 v1 / v2 这种短版本号参与比较，只有完全不是数字开头的才跳过。
    if (!/^\d+(?:\.\d+)*/.test(ver) || isBetaName(ver)) continue;
    if (!best || versionIsNewer(ver, best)) best = ver;
  }
  return best;
}

/** 测试通道只认 beta 分支头。旧的 beta/rc/pre 标签不列出。 */
export function hideListedVersion(item, _stableVersion = "") {
  if (!item || withdrawnVersion(item)) return true;
  if (item.ref === BETA_REF && item.channel === "beta") return false;
  return item.channel === "beta" || isBetaName(item.version) || isBetaName(item.ref) || isBetaName(item.id);
}

export function readChannelState() {
  const raw = readJson(channelStatePath()) || {};
  const stored = String(raw.channel || "").toLowerCase();
  const pin = typeof raw.pin === "string" ? raw.pin.trim() : "";
  const channel = stored === "beta" ? "beta" : "stable";
  const state = {
    channel,
    pin: isBetaName(pin) || pin === BETA_REF ? "" : pin,
  };
  if ((stored === "beta") !== (channel === "beta") || state.pin !== pin) writeChannelState(state);
  return state;
}

function writeChannelState(next) {
  const state = {
    channel: normalizeChannel(next?.channel),
    pin: typeof next?.pin === "string" ? next.pin.trim() : "",
  };
  atomicWriteSync(channelStatePath(), `${JSON.stringify(state, null, 2)}\n`);
  return state;
}

export function channelPublic(state = readChannelState()) {
  const meta = CHANNELS[state.channel] || CHANNELS.stable;
  return {
    channel: meta.id,
    channelLabel: meta.label,
    pin: state.pin || "",
  };
}

function currentChannelRef(state = readChannelState()) {
  return (CHANNELS[state.channel] || CHANNELS.stable).ref;
}

function readHistory() {
  const raw = readJson(historyPath());
  const rows = Array.isArray(raw) ? raw : [];
  return rows.filter((item) => item && !withdrawnVersion(item));
}

function pushHistory(entry) {
  const next = [entry, ...readHistory().filter((item) => item && item.ref !== entry.ref)].slice(0, 20);
  atomicWriteSync(historyPath(), `${JSON.stringify(next, null, 2)}\n`);
}

/** 直连 codeload，避免 github.com/archive → 302 在 Electron/部分 Node 下变成 http 302 / fetch failed。 */
function archiveZipUrl(ref) {
  const value = String(ref || STABLE_REF);
  if (/^[0-9a-f]{40}$/i.test(value)) return `https://codeload.github.com/${updateRepo()}/zip/${value}`;
  if (/^v?\d/.test(value)) return `https://codeload.github.com/${updateRepo()}/zip/refs/tags/${encodeURIComponent(value)}`;
  return `https://codeload.github.com/${updateRepo()}/zip/refs/heads/${encodeURIComponent(value)}`;
}

function archiveTarballUrl(ref) {
  const value = String(ref || STABLE_REF);
  if (/^[0-9a-f]{40}$/i.test(value)) return `https://codeload.github.com/${updateRepo()}/tar.gz/${value}`;
  if (/^v?\d/.test(value)) return `https://codeload.github.com/${updateRepo()}/tar.gz/refs/tags/${encodeURIComponent(value)}`;
  return `https://codeload.github.com/${updateRepo()}/tar.gz/refs/heads/${encodeURIComponent(value)}`;
}

function readStamp() {
  try {
    return fs.readFileSync(stampPath(), "utf8").trim();
  } catch {
    return "";
  }
}

function writeStamp(value) {
  if (!value) return;
  atomicWriteSync(stampPath(), `${value}\n`);
}

function sameRev(a, b) {
  if (!a || !b) return false;
  return a === b || a.startsWith(b) || b.startsWith(a);
}

export function realPath(dir) {
  try {
    return fs.realpathSync(dir);
  } catch {
    return path.resolve(dir);
  }
}

function readJson(fp) {
  try {
    return JSON.parse(fs.readFileSync(fp, "utf8"));
  } catch {
    return null;
  }
}

function isGitCheckout(dir) {
  return fs.existsSync(path.join(dir, ".git"));
}

function canGit(dir) {
  if (!isGitCheckout(dir)) return false;
  try {
    execFileSync("git", ["-C", dir, "rev-parse", "--is-inside-work-tree"], HIDDEN);
    return true;
  } catch {
    return false;
  }
}

function gitOk() {
  return canGit(PLUGIN_ROOT);
}

function gitHead(dir) {
  try {
    return execFileSync("git", ["-C", dir, "rev-parse", "HEAD"], HIDDEN).trim();
  } catch {
    return "";
  }
}

export function isLinkSpec(spec) {
  const s = String(spec || "");
  return /^(link|file):/i.test(s) || s === "." || /^\.\.?(?:[/\\]|$)/.test(s);
}

export function resolveLinkDir(profileDir, spec) {
  const raw = String(spec).replace(/^(link|file):/i, "");
  return path.resolve(profileDir, raw);
}

export function findPurgeProfiles() {
  const root = path.join(findDshHome(), "profiles");
  if (!fs.existsSync(root)) return [];
  let names = [];
  try {
    names = fs.readdirSync(root);
  } catch {
    return [];
  }
  const out = [];
  for (const name of names) {
    const dir = path.join(root, name);
    const pkg = readJson(path.join(dir, "package.json"));
    const spec = pkg?.dependencies?.["dsh-purge"] || pkg?.devDependencies?.["dsh-purge"];
    if (!spec) continue;
    out.push({ name, dir, spec: String(spec) });
  }
  return out;
}

export function profilePluginDir(profileDir) {
  const nm = path.join(profileDir, "node_modules", "dsh-purge");
  return fs.existsSync(nm) ? realPath(nm) : "";
}

/** 把 profile 里的安装地址改成 codeload。github.com/archive 会 302，pnpm 的 fetch 接着失败。 */
function pinInstalledSpec(profileDir, ref) {
  if (!profileDir) return;
  const url = archiveTarballUrl(ref);
  const pkgPath = path.join(profileDir, "package.json");
  const pkg = readJson(pkgPath);
  if (pkg) {
    let changed = false;
    for (const key of ["dependencies", "devDependencies", "optionalDependencies"]) {
      if (pkg[key] && Object.prototype.hasOwnProperty.call(pkg[key], "dsh-purge") && pkg[key]["dsh-purge"] !== url) {
        pkg[key]["dsh-purge"] = url;
        changed = true;
      }
    }
    if (changed) atomicWriteSync(pkgPath, `${JSON.stringify(pkg, null, 2)}\n`);
  }
  // 这里曾经用正则把 pnpm-lock.yaml 里 importer 的 specifier/version 两行换成新地址，
  // 却没有写 packages:/snapshots: 条目。锁文件于是自相矛盾，pnpm 在任何命令之前校验
  // 锁文件就失败：
  //   ERR_PNPM_LOCKFILE_MISSING_DEPENDENCY / Broken lockfile: no entry for 'dsh-purge@…'
  // dsh 又给子进程带 CI=1（frozen-lockfile 默认开），于是 profile 里连紧随其后、
  // 本来能修好它的 pnpm add --force 都起不来 —— 整个 profile 从此不可安装。
  // 这个手改并不需要：pin 完 package.json 后，pnpm 自己会在 add --force 时按新地址
  // 重新解析，把 importer / packages / snapshots 一次写一致。锁文件只能由解析出这些
  // 字段的解析器来写。
}

function planUpdates() {
  const profiles = findPurgeProfiles();
  const jobs = [];
  const seen = new Set();
  const remember = (dir) => {
    const key = realPath(dir).toLowerCase();
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  };

  for (const p of profiles) {
    if (isLinkSpec(p.spec)) {
      const dir = resolveLinkDir(p.dir, p.spec);
      if (!remember(dir)) continue;
      jobs.push(canGit(dir) ? { kind: "git", dir, profile: p.name } : { kind: "zip", dir, profile: p.name });
      continue;
    }
    const dir = profilePluginDir(p.dir) || PLUGIN_ROOT;
    jobs.push({ kind: "dsh", profile: p.name, spec: p.spec, dir, profileDir: p.dir });
    remember(dir);
  }

  if (!jobs.length) {
    jobs.push(canGit(PLUGIN_ROOT) ? { kind: "git", dir: PLUGIN_ROOT } : { kind: "zip", dir: PLUGIN_ROOT });
    return jobs;
  }
  if (remember(PLUGIN_ROOT)) {
    jobs.push(canGit(PLUGIN_ROOT) ? { kind: "git", dir: PLUGIN_ROOT } : { kind: "zip", dir: PLUGIN_ROOT });
  }
  return jobs;
}

function detectVia() {
  if (gitOk()) {
    const extra = findPurgeProfiles().some((p) => !isLinkSpec(p.spec));
    return extra ? "mixed" : "git";
  }
  if (findPurgeProfiles().some((p) => !isLinkSpec(p.spec))) return "dsh";
  if (findPurgeProfiles().length) return "dsh";
  return "zip";
}

function isAbortError(e) {
  const msg = String((e && e.message) || e || "");
  return (e && (e.name === "AbortError" || e.name === "TimeoutError")) || /aborted|abort|超时/i.test(msg);
}

function rewriteDownloadUrl(url) {
  const value = String(url || "");
  let match = value.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/archive\/refs\/(tags|heads)\/(.+)\.(zip|tar\.gz)$/i);
  if (match) {
    const kind = match[4].toLowerCase() === "zip" ? "zip" : "tar.gz";
    return `https://codeload.github.com/${match[1]}/${kind}/refs/${match[2]}/${decodeURIComponent(match[3])}`;
  }
  match = value.match(/^https:\/\/github\.com\/([^/]+\/[^/]+)\/archive\/([0-9a-f]{7,40})\.(zip|tar\.gz)$/i);
  if (match) {
    const kind = match[3].toLowerCase() === "zip" ? "zip" : "tar.gz";
    return `https://codeload.github.com/${match[1]}/${kind}/${match[2]}`;
  }
  return "";
}

function requestBuffer(url, ms, headers, redirectsLeft = 5) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(url);
    } catch (e) {
      reject(e);
      return;
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      reject(new Error(`update: unsupported protocol ${parsed.protocol}`));
      return;
    }
    const lib = parsed.protocol === "http:" ? http : https;
    const req = lib.request(parsed, {
      method: "GET",
      headers: { "user-agent": "dsh-purge-update", accept: "*/*", ...headers },
    }, (res) => {
      const status = res.statusCode || 0;
      if ([301, 302, 303, 307, 308].includes(status)) {
        res.resume();
        if (redirectsLeft <= 0) {
          reject(new Error("http redirect loop"));
          return;
        }
        const loc = Array.isArray(res.headers.location) ? res.headers.location[0] : res.headers.location;
        const candidate = loc ? new URL(loc, url).href : rewriteDownloadUrl(url);
        if (!candidate || candidate === url) {
          reject(new Error(`http ${status}`));
          return;
        }
        let nextUrl;
        try {
          nextUrl = new URL(candidate);
        } catch (e) {
          reject(e);
          return;
        }
        if (nextUrl.protocol !== "https:") {
          reject(new Error(`update: redirect rejected (non-https: ${nextUrl.protocol})`));
          return;
        }
        if (!UPDATE_REDIRECT_ALLOWED_HOSTS.has(nextUrl.hostname)) {
          reject(new Error(`update: redirect rejected (host not allowed: ${nextUrl.hostname})`));
          return;
        }
        requestBuffer(nextUrl.href, ms, headers, redirectsLeft - 1).then(resolve, reject);
        return;
      }
      if (status < 200 || status >= 300) {
        res.resume();
        const rewritten = rewriteDownloadUrl(url);
        if (rewritten && rewritten !== url && redirectsLeft > 0) {
          requestBuffer(rewritten, ms, headers, redirectsLeft - 1).then(resolve, reject);
          return;
        }
        reject(new Error(`http ${status}`));
        return;
      }
      const chunks = [];
      let received = 0;
      let aborted = false;
      res.on("data", (chunk) => {
        if (aborted) return;
        received += chunk.length;
        if (received > MAX_UPDATE_BYTES) {
          aborted = true;
          req.destroy(new Error(`update: response exceeds ${MAX_UPDATE_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        if (!aborted) resolve({ status, body: Buffer.concat(chunks) });
      });
      res.on("error", reject);
    });
    req.on("error", reject);
    req.setTimeout(ms, () => {
      req.destroy(new Error("GitHub 超时"));
    });
    req.end();
  });
}

async function fetchRes(url, ms = 20000, headers = {}) {
  const started = rewriteDownloadUrl(url) || url;
  try {
    const result = await requestBuffer(started, ms, headers);
    return {
      ok: true,
      status: result.status,
      async text() {
        return result.body.toString("utf8");
      },
      async arrayBuffer() {
        return result.body.buffer.slice(
          result.body.byteOffset,
          result.body.byteOffset + result.body.byteLength,
        );
      },
    };
  } catch (e) {
    if (isAbortError(e) || /GitHub 超时/.test(String(e && e.message))) throw new Error("GitHub 超时");
    throw e;
  }
}

async function fetchText(url, ms = 20000, headers = {}) {
  return (await fetchRes(url, ms, headers)).text();
}

async function fetchJson(url, ms = 20000, headers = {}) {
  return JSON.parse(await fetchText(url, ms, headers));
}

function versionFromPackageText(text) {
  const pkg = JSON.parse(text);
  return pkg && pkg.version ? String(pkg.version) : "";
}

// 远端 package.json 版本号查询:5 分钟 memo,频繁刷新面板时不重复打 raw.github / jsdelivr。
// key 必须带仓库名：换更新源后旧仓库的缓存不能复用到新仓库上。
const _remotePkgVerCache = new Map();
const REMOTE_PKG_VER_TTL = 300_000;
async function remotePackageVersion(sha = "", fallbackRef = STABLE_REF) {
  const repo = updateRepo();
  const ref = sha || fallbackRef;
  const key = `${repo}::${sha || `ref:${ref}`}`;
  const now = Date.now();
  const hit = _remotePkgVerCache.get(key);
  if (hit && now - hit.at < REMOTE_PKG_VER_TTL) return hit.value;
  const urls = [
    sha ? `https://cdn.jsdelivr.net/gh/${repo}@${sha}/package.json` : "",
    `https://raw.githubusercontent.com/${repo}/${ref}/package.json`,
    `https://cdn.jsdelivr.net/gh/${repo}@${ref}/package.json`,
    `https://api.github.com/repos/${repo}/contents/package.json?ref=${encodeURIComponent(ref)}`,
  ].filter(Boolean);
  for (const url of urls) {
    try {
      if (url.includes("api.github.com/repos/")) {
        const data = await fetchJson(url, 20000, { accept: "application/vnd.github.raw" });
        let ver = "";
        if (typeof data === "string") ver = versionFromPackageText(data);
        else if (data && data.version) ver = String(data.version);
        else if (data && data.content && data.encoding === "base64") {
          ver = versionFromPackageText(Buffer.from(data.content.replace(/\s/g, ""), "base64").toString("utf8"));
        }
        if (ver) { _remotePkgVerCache.set(key, { value: ver, at: now }); return ver; }
        continue;
      }
      const ver = versionFromPackageText(await fetchText(url));
      if (ver) { _remotePkgVerCache.set(key, { value: ver, at: now }); return ver; }
    } catch {
      // 换下一个源。
    }
  }
  // 失败也记短缓存 30 秒,避免反复打空请求。
  _remotePkgVerCache.set(key, { value: "", at: now - (REMOTE_PKG_VER_TTL - 30_000) });
  return "";
}

async function remoteHeadSha(ref = STABLE_REF) {
  const target = encodeURIComponent(ref || STABLE_REF);
  const fromApi = fetchJson(`https://api.github.com/repos/${updateRepo()}/commits/${target}`)
    .then((data) => (data?.sha ? String(data.sha) : ""))
    .catch(() => "");
  const fromAtom = fetchText(`https://github.com/${updateRepo()}/commits/${ref}.atom`)
    .then((atom) => {
      const hit = atom.match(/<id>tag:github\.com,2008:Grit::Commit\/([0-9a-f]{40})<\/id>/);
      return hit ? hit[1] : "";
    })
    .catch(() => "");
  const [apiSha, atomSha] = await Promise.all([fromApi, fromAtom]);
  return apiSha || atomSha || "";
}

function versionLabel(version, channel, sha = "") {
  const ver = String(version || "").replace(/^v/, "") || (sha ? String(sha).slice(0, 7) : "");
  const mark = channel === "beta" ? "测试" : "正式";
  return ver ? `${ver}（${mark}）` : mark;
}

function rememberVersion(item, seen) {
  if (!item || !item.ref) return null;
  const key = `${item.sha || ""}|${item.ref}`.toLowerCase();
  if (seen.has(key)) return null;
  seen.add(key);
  return item;
}

// 允许：v1 / v2 / v1.3.1 / 1.3.1-beta.1 / master / main / beta / 40位sha
// 注意 v?\d+ 单独一项是必要的：把正式版打成 v1/v2 这种短 tag 时也要能切换。
const UPDATE_REF_RE = /^(?:v?\d+(?:\.\d+)*(?:-[\w.]+)?|master|main|beta|[0-9a-f]{7,40})$/i;

export function safeUpdateRef(ref) {
  const target = String(ref || "").trim();
  if (!target) return "";
  if (!UPDATE_REF_RE.test(target)) return "";
  return target;
}

export function markCurrent(versions, state, localVer, localSha) {
  const pin = String(state?.pin || "");
  const rows = versions || [];
  const ver = String(localVer || "").replace(/^v/i, "");
  const channel = state?.channel || "stable";
  const sameVersion = (item) => ver && String(item?.version || "").replace(/^v/i, "") === ver && item.channel === channel;
  const sameSha = (item) => Boolean(localSha && item?.sha && sameRev(localSha, item.sha));
  let chosen = null;
  if (pin) {
    chosen = rows.find((item) => item.ref === pin) || null;
  } else {
    const pool = rows.filter(sameVersion);
    // 安装记录里的旧提交号不能把较低版本标成当前。只认和正在跑的 package.json 相同的版本。
    chosen = pool.find((item) => sameSha(item) && (item.latest || item.ref === "master" || item.kind === "head"))
      || pool.find((item) => item.latest || item.ref === "master" || item.kind === "head")
      || pool.find((item) => sameSha(item))
      || pool[0]
      || null;
  }
  return rows.map((item) => ({
    ...item,
    shaShort: item.shaShort || (item.sha ? String(item.sha).slice(0, 7) : ""),
    current: Boolean(chosen && item === chosen),
  }));
}

async function listGithubTags() {
  try {
    const rows = await fetchJson(`https://api.github.com/repos/${updateRepo()}/tags?per_page=50`);
    if (!Array.isArray(rows)) return [];
    const picked = rows.map((row) => {
      const name = String(row?.name || "").trim();
      // 认 v1 / v2 这种短 tag，也认 v1.3.1 / 1.3.1-beta.1。
      if (!name || !/^v?\d+(?:\.\d+)*(?:-[\w.]+)?$/.test(name)) return null;
      const sha = row?.commit?.sha ? String(row.commit.sha) : "";
      const channel = isBetaName(name) ? "beta" : "stable";
      return { name, sha, channel };
    }).filter(Boolean);

    // tag 名只是标签（v1/v2），真实版本号要以该 tag 内的 package.json 为准。
    // 并行拉取，读不到就回退用 tag 名，不阻塞其他版本。
    const resolved = await Promise.all(picked.map(async (item) => {
      const real = await remotePackageVersion(item.sha, item.name).catch(() => "");
      const version = real || item.name.replace(/^v/, "");
      return {
        id: item.name,
        ref: item.name,
        sha: item.sha,
        version,
        channel: item.channel,
        // tag 名与真实版本不同时，label 里两个都写出来，下拉里一眼能分辨。
        label: versionLabel(version, item.channel, item.sha)
          + (version !== item.name.replace(/^v/, "") ? ` · ${item.name}` : ""),
        kind: "tag",
        tag: item.name,
      };
    }));
    return resolved;
  } catch {
    return [];
  }
}

function ensureRunningVersion(versions, state, localVer, localSha) {
  const ver = String(localVer || "").replace(/^v/i, "");
  if (!ver || isBetaName(ver) || state?.channel === "beta") return versions;
  if ((versions || []).some((item) => item.channel === "stable" && String(item.version || "").replace(/^v/i, "") === ver)) {
    return versions;
  }
  const ref = (versions || []).some((item) => item.ref === "master") ? `local-${ver}` : "master";
  return [{
    id: ref,
    ref,
    sha: localSha || "",
    version: ver,
    channel: "stable",
    label: versionLabel(ver, "stable", localSha),
    kind: "local",
    latest: !(versions || []).some((item) => item.channel === "stable" && item.latest),
  }, ...(versions || [])];
}

async function listRemoteVersions() {
  const state = readChannelState();
  const seen = new Set();
  const out = [];
  const add = (item) => {
    const next = rememberVersion(item, seen);
    if (next) out.push(next);
  };

  // 先确定稳定分支名，再并发取 head/tags。否则 master 不存在时会白打一轮请求。
  await resolveStableRef();
  const [stableSha, betaSha, tags] = await Promise.all([
    remoteHeadSha(STABLE_REF),
    remoteHeadSha(BETA_REF),
    listGithubTags(),
  ]);

  if (stableSha) {
    const version = await remotePackageVersion(stableSha, STABLE_REF).catch(() => "");
    add({
      id: STABLE_REF,
      ref: STABLE_REF,
      sha: stableSha,
      version: version || "",
      channel: "stable",
      label: `${versionLabel(version, "stable", stableSha)} · 最新`,
      kind: "head",
      latest: true,
    });
  }
  if (betaSha) {
    const version = await remotePackageVersion(betaSha, BETA_REF).catch(() => "");
    add({
      id: BETA_REF,
      ref: BETA_REF,
      sha: betaSha,
      version: version || "",
      channel: "beta",
      label: `${versionLabel(version, "beta", betaSha)} · 最新`,
      kind: "head",
      latest: true,
    });
  }
  for (const tag of tags) {
    if (!withdrawnVersion(tag)) add(tag);
  }
  for (const item of readHistory()) {
    if (!item || !item.ref || withdrawnVersion(item)) continue;
    add({
      ...item,
      label: item.label || versionLabel(item.version, item.channel, item.sha),
      kind: item.kind || "history",
    });
  }

  const localVer = localVersion();
  const localSha = (gitOk() ? gitHead(PLUGIN_ROOT) : "") || readStamp();
  const withLocal = ensureRunningVersion(out, state, localVer, localSha);
  const ceiling = latestStableVersion([
    ...withLocal,
    localVer && !isBetaName(localVer) ? { channel: "stable", version: localVer } : null,
  ].filter(Boolean));
  const visible = withLocal.filter((item) => !hideListedVersion(item, ceiling));
  return {
    versions: markCurrent(visible, state, localVer, localSha),
    hasBeta: Boolean(betaSha),
    stableSha,
    betaSha: betaSha || "",
  };
}

function describeLane(id, listed, state, localVer, localRev) {
  const sha = id === "beta" ? listed.betaSha : listed.stableSha;
  const versions = listed.versions.filter((item) => item.channel === id);
  const latest = versions.find((item) => item.latest);
  const version = latest?.version || "";
  const onLane = state.channel === id;
  const matchesHead = Boolean(localRev && sha && sameRev(localRev, sha));
  const current = matchesHead || versions.some((item) => item.current && (item.latest || (state.pin && item.ref === state.pin)));
  let hasUpdate = false;
  if (onLane && state.pin) {
    hasUpdate = Boolean(sha && localRev && !sameRev(localRev, sha));
  } else if (onLane && versionIsNewer(version, localVer)) {
    // 只跟版本号。提交号对不上就再 add --force，会在 dsh 杀掉宿主后形成无限重启。
    hasUpdate = true;
  } else if (onLane && !localVer && sha && localRev && !sameRev(localRev, sha)) {
    hasUpdate = true;
  }
  return {
    id,
    ref: CHANNELS[id].ref,
    version,
    sha: sha ? String(sha).slice(0, 7) : "",
    current,
    hasUpdate,
    // 只认远端真实数据。versions 里可能含 ensureRunningVersion 补进来的本地版本，
    // 用它判 hasRemote 会让「仓库 404」被误报成「已是最新」。
    hasRemote: Boolean(sha),
  };
}

function lanesOf(listed, state, localVer, localRev) {
  return {
    stable: describeLane("stable", listed, state, localVer, localRev),
    beta: describeLane("beta", listed, state, localVer, localRev),
  };
}

export async function checkUpdate() {
  let state = readChannelState();
  const localVer = localVersion();
  const listed = await listRemoteVersions();
  const gitSha = gitOk() ? gitHead(PLUGIN_ROOT) : "";
  const stamp = readStamp();
  const localRev = gitSha || stamp;
  listed.versions = markCurrent(listed.versions, state, localVer, localRev);
  const channelRef = currentChannelRef(state);
  const lanes = lanesOf(listed, state, localVer, localRev);
  const lane = lanes[state.channel] || lanes.stable;
  if (!lane.hasRemote && state.channel === "beta") {
    return rememberUpdate({
      ok: true,
      hasUpdate: false,
      hasBeta: false,
      error: "还没有测试版",
      localVersion: localVer,
      remoteVersion: "",
      localSha: localRev ? localRev.slice(0, 7) : "",
      remoteSha: "",
      updateTarget: channelRef,
      via: detectVia(),
      versions: listed.versions,
      lanes,
      ...channelPublic(state),
    });
  }
  // 远端读不到时不再抛错：把原因和当前源一起返回，UI 能直接显示怎么改。
  if (!lanes.stable.hasRemote) {
    const src = updateSourceInfo();
    const hint = src.isDefault
      ? "原作者仓库已停更，请把更新源改成你自己的仓库"
      : `更新源 ${src.repo} 读取失败，检查该仓库是否有 ${STABLE_REF}（或 main）分支与 package.json`;
    return rememberUpdate({
      ok: false,
      hasUpdate: false,
      hasBeta: listed.hasBeta,
      error: `无法读取 ${STABLE_REF} 分支`,
      hint,
      source: src,
      branch: STABLE_REF,
      localVersion: localVer,
      remoteVersion: "",
      localSha: localRev ? localRev.slice(0, 7) : "",
      remoteSha: "",
      updateTarget: channelRef,
      via: detectVia(),
      versions: listed.versions,
      lanes,
      ...channelPublic(state),
    });
  }
  const result = {
    ok: true,
    hasUpdate: Boolean(lane.hasUpdate),
    hasBeta: listed.hasBeta,
    updateTarget: channelRef,
    pinned: Boolean(state.pin),
    localVersion: localVer,
    remoteVersion: lane.version || lane.sha,
    localSha: localRev ? localRev.slice(0, 7) : "",
    remoteSha: lane.sha,
    via: detectVia(),
    versions: listed.versions,
    lanes,
    source: updateSourceInfo(),
    ...channelPublic(state),
  };
  rememberUpdate(result);
  return result;
}

function gitTrackedDirty(dir) {
  try {
    const out = execFileSync(
      "git",
      ["-C", dir, "status", "--porcelain", "--untracked-files=no", "--", ...COPY_NAMES],
      HIDDEN,
    ).trim();
    return Boolean(out);
  } catch {
    return true;
  }
}

let lastUpdate = null;

function rememberUpdate(result) {
  lastUpdate = result && typeof result === "object" ? result : lastUpdate;
  return lastUpdate;
}

export function lastUpdateResult() {
  return lastUpdate;
}

function runGit(dir, args, timeout = 20000) {
  try {
    return execFileSync("git", ["-C", dir, ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
      timeout,
    });
  } catch (e) {
    const detail = [e.stderr, e.stdout, e.message].filter(Boolean).join("\n").trim();
    throw new Error(detail || `git ${args.join(" ")}`);
  }
}

function gitResetTo(dir, ref, { force = false } = {}) {
  if (!force && gitTrackedDirty(dir)) {
    throw new Error("本地插件文件有未提交改动，未覆盖");
  }
  const target = safeUpdateRef(ref || STABLE_REF);
  if (!target) throw new Error("未知版本");
  try {
    runGit(dir, ["fetch", "origin", "--tags"], 60000);
  } catch {
    runGit(dir, ["fetch", "origin", "--tags", target], 60000);
  }
  if (target === STABLE_REF || target === BETA_REF) {
    try {
      runGit(dir, ["checkout", "-B", target, `origin/${target}`]);
      return;
    } catch {
      runGit(dir, ["reset", "--hard", `origin/${target}`]);
      return;
    }
  }
  try {
    runGit(dir, ["fetch", "origin", "--tags", target], 60000);
  } catch {
    // 上面已经 fetch 过全部分支。
  }
  runGit(dir, ["reset", "--hard", target]);
}

function extractZip(zip, dest) {
  // win32：tar(bsdtar) → powershell。darwin/linux：tar → unzip → python3 → bsdtar。
  // 外部工具都不可用时用 Node 解 zip，Linux 不会再去调用 powershell。
  extractZipArchive(zip, dest);
}

async function overlayFromZip(dests, ref = STABLE_REF) {
  const unique = [...new Set(dests.filter(Boolean).map((d) => realPath(d)))];
  if (!unique.length) return;
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), "dsh-purge-upd-"));
  try {
    const zip = path.join(tmp, "plugin.zip");
    const res = await fetchRes(archiveZipUrl(ref), 45000);
    await fsp.writeFile(zip, Buffer.from(await res.arrayBuffer()));
    extractZip(zip, tmp);
    const names = await fsp.readdir(tmp);
    const unpacked = names
      .map((n) => path.join(tmp, n))
      .find((p) => fs.existsSync(path.join(p, "package.json")));
    if (!unpacked) throw new Error("zip 里没有 package.json");
    for (const dest of unique) {
      for (const name of COPY_NAMES) {
        const from = path.join(unpacked, name);
        const to = path.join(dest, name);
        if (!fs.existsSync(from)) continue;
        if (name === "lib" || name === "docs" || name === "bin") {
          try {
            await fsp.rm(to, { recursive: true, force: true });
          } catch (e) {
            // 删不掉说明文件被进程占用。继续 cp 会写出一半新文件一半旧文件的半升级,
            // 让 host 和插件的版本不一致。宁可抛错让用户彻底退出宿主再重试。
            throw new Error(
              `覆盖 ${to} 失败(${e.message || e})。可能被进程占用,请完全退出宿主后重试。`,
            );
          }
        }
        await fsp.cp(from, to, { recursive: true, force: true });
      }
    }
  } finally {
    await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
  }
}

function parseReapplyOutput(text) {
  const line = String(text || "")
    .split(/\r?\n/)
    .map((item) => item.trim())
    .filter((item) => item.startsWith("{"))
    .pop();
  if (!line) return null;
  try {
    return JSON.parse(line);
  } catch {
    return null;
  }
}

/** 用刚写好的插件文件在新进程里还原并重打，避免还在跑旧补丁列表。 */
function runReapplyChild() {
  const cli = path.join(PLUGIN_ROOT, "lib", "reapply-cli.js");
  if (!fs.existsSync(cli)) return { ok: false, error: "缺少重新应用脚本" };
  const env = { ...process.env, ELECTRON_RUN_AS_NODE: "1" };
  delete env.DSH_PURGE_RESTART;
  let run;
  try {
    run = spawnSync(process.execPath, ["--expose-internals", cli], {
      cwd: PLUGIN_ROOT,
      env,
      encoding: "utf8",
      windowsHide: true,
      timeout: 180000,
      maxBuffer: 8 * 1024 * 1024,
    });
  } catch (e) {
    return { ok: false, error: String(e && e.message ? e.message : e) };
  }
  const parsed = parseReapplyOutput(`${run.stdout || ""}\n${run.stderr || ""}`);
  if (parsed) return parsed;
  const detail = String(run.stderr || run.stdout || (run.error && run.error.message) || "重新应用失败").trim();
  return { ok: false, error: detail.slice(0, 500) || "重新应用失败" };
}

let applyUpdateInflight = null;

export async function applyUpdate(jobs = planUpdates(), options = {}) {
  // 同一时刻只能有一次 applyUpdate 在跑。第二次调用在第一次完成前共享同一个 Promise,
  // 避免两条 overlayFromZip 同时往同一目录写出一半文件,或两次 writeStamp 竞争。
  if (applyUpdateInflight) return applyUpdateInflight;
  applyUpdateInflight = (async () => {
    try {
      return await _applyUpdateImpl(jobs, options);
    } finally {
      applyUpdateInflight = null;
    }
  })();
  return applyUpdateInflight;
}

async function _applyUpdateImpl(jobs, options) {
  if (!Array.isArray(jobs)) {
    options = jobs && typeof jobs === "object" ? jobs : {};
    jobs = planUpdates();
  }
  const state = readChannelState();
  const ref = safeUpdateRef(options.ref || currentChannelRef(state) || STABLE_REF);
  if (!ref) throw new Error("未知版本");
  const force = options.force !== false;
  const pin = options.pin === false ? "" : (options.pin || state.pin || "");
  const channel = normalizeChannel(options.channel || state.channel);
  const zipDirs = [];
  const specProfiles = [];
  const vias = new Set();
  for (const job of jobs) {
    if (job.kind === "git") {
      try {
        gitResetTo(job.dir, ref, { force });
        vias.add("git");
        continue;
      } catch (e) {
        if (!force && /未提交改动/.test(String(e && e.message))) throw e;
        zipDirs.push(job.dir);
      }
      continue;
    }
    if (job.kind === "dsh") {
      // exe 和 web 都走 dsh plugin add → pnpm。pnpm 拉 GitHub 包会 302 或 fetch failed，
      // 而且 add --force 会先杀掉宿主。这里改为自己下载再覆盖。
      if (job.dir) zipDirs.push(job.dir);
      if (job.profileDir) specProfiles.push(job.profileDir);
      continue;
    }
    zipDirs.push(job.dir);
  }
  if (zipDirs.length) {
    await overlayFromZip(zipDirs, ref);
    vias.add("zip");
  }
  for (const dir of specProfiles) pinInstalledSpec(dir, ref);
  const sha = (gitOk() ? gitHead(PLUGIN_ROOT) : "") || (await remoteHeadSha(ref).catch(() => ""));
  const via = vias.size > 1 ? "mixed" : [...vias][0] || detectVia();
  const saved = writeChannelState({ channel, pin });
  const localVer = localVersion();
  const listed = await listRemoteVersions().catch(() => ({ versions: [], hasBeta: saved.channel === "beta" }));
  const reapplied = runReapplyChild();
  // reapply 真的成功才能承认这次升级：写 stamp / guard / history。
  // 失败就不写,下次 checkUpdate 还能发现没完成的升级,而不是误标为"已是最新"。
  if (reapplied.ok === true) {
    if (sha) markAutoUpdateGuard(ref, sha);
    if (sha) writeStamp(sha);
    pushHistory({
      ref,
      sha: sha || "",
      version: localVer,
      channel,
      label: versionLabel(localVer, channel, sha),
      at: new Date().toISOString(),
    });
  }
  const restartAfter = reapplied.ok === true && !reapplied.needsFullQuit;
  const needsFullQuit = reapplied.ok === true && Boolean(reapplied.needsFullQuit);
  return rememberUpdate({
    ok: reapplied.ok !== false,
    applied: reapplied.ok === true,
    hasUpdate: reapplied.ok !== true,
    hasBeta: listed.hasBeta,
    pinned: Boolean(saved.pin),
    localVersion: localVer,
    remoteVersion: localVer,
    localSha: sha ? String(sha).slice(0, 7) : "",
    remoteSha: sha ? String(sha).slice(0, 7) : "",
    needRestart: false,
    reloadClient: !restartAfter && !needsFullQuit,
    restartAfter,
    needsFullQuit,
    reapplied: reapplied.ok === true,
    needsRetry: reapplied.ok === false,
    error: reapplied.ok === false ? `文件已更新，但还原并重新应用失败: ${reapplied.error || "未知错误"}` : undefined,
    via,
    versions: listed.versions,
    lanes: lanesOf(listed, saved, localVer, sha),
    ...channelPublic(saved),
  });
}

export async function switchChannel(channel, { apply = true } = {}) {
  const next = normalizeChannel(channel);
  if (!apply) {
    writeChannelState({ channel: next, pin: "" });
    return checkUpdate();
  }
  return applyUpdate(planUpdates(), { ref: CHANNELS[next].ref, channel: next, pin: false, force: true });
}

function listedUpdateRef(target, listed) {
  const safe = safeUpdateRef(target);
  if (!safe) return "";
  const hit = (listed?.versions || []).find((item) => (
    item.ref === safe
    || item.id === safe
    || item.sha === safe
    || (item.sha && safe.length >= 7 && (item.sha.startsWith(safe) || safe.startsWith(item.sha)))
  ));
  return safeUpdateRef(hit?.ref || "");
}

export async function switchVersion(ref) {
  const raw = String(ref || "").trim();
  if (withdrawnVersion({ ref: raw, version: raw })) throw new Error("该版本已下线");
  const target = safeUpdateRef(raw);
  if (!target) throw new Error("请选择要回退的版本");
  const listed = await listRemoteVersions();
  const resolved = listedUpdateRef(target, listed);
  if (!resolved) throw new Error("未知版本");
  const hit = listed.versions.find((item) => item.ref === resolved);
  const channel = hit?.channel || readChannelState().channel;
  const pin = hit?.latest ? "" : resolved;
  return applyUpdate(planUpdates(), { ref: resolved, channel, pin, force: true });
}

export async function handleUpdateOp(body = {}) {
  const op = String(body.op || (body.auto ? "auto" : "apply")).toLowerCase();
  // 更新源：读取或写入。写入后立刻复检一次，让面板直接看到新结果。
  if (op === "source") {
    if (body.repo !== undefined) {
      setUpdateRepo(body.repo, body.refs);
      return checkUpdate();
    }
    return { ok: true, source: updateSourceInfo() };
  }
  if (op === "check" || op === "status" || op === "versions") return checkUpdate();
  if (op === "channel") return switchChannel(body.channel, { apply: body.apply !== false });
  if (op === "switch" || op === "rollback") return switchVersion(body.ref || body.version || body.id);
  if (op === "auto") return autoUpdateIfNeeded();
  const state = readChannelState();
  const requested = body.ref || currentChannelRef(state);
  const ref = safeUpdateRef(requested);
  if (!ref) throw new Error("未知版本");
  if (ref !== BETA_REF && isBetaName(ref)) throw new Error("该测试标签已不再提供");
  if (ref !== STABLE_REF && ref !== BETA_REF) {
    const listed = await listRemoteVersions();
    if (!listedUpdateRef(ref, listed)) throw new Error("未知版本");
  }
  const channel = ref === BETA_REF ? "beta" : (ref === STABLE_REF ? "stable" : normalizeChannel(body.channel || state.channel));
  return applyUpdate(planUpdates(), { ref, channel, pin: false, force: true });
}

export async function autoUpdateIfNeeded() {
  // 插件只允许用户在面板手动更新；启动路径永不自动升（版本适配依赖本机宿主）。
  return rememberUpdate({
    auto: true,
    skipped: "manual-only",
    hasUpdate: false,
    error: "",
    ...channelPublic(),
  });
}
