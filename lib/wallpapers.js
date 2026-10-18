/**
 * 内置壁纸的静态路由。
 *
 * 壁纸是随插件包分发的三张 JPEG（lib/wallpapers/*.jpg，2560x1440，合计约 700KB），
 * 由浏览器端直接 <img src="/purge-wallpapers/<id>.jpg"> 拉取，不经过客户端 bundle。
 *
 * 安全边界：
 * - 只认白名单里的三个 id，路径由服务端拼，不接受客户端传进来的任意片段；
 * - 不读目录列表，不做通配；
 * - 只允许 GET / HEAD。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WALL_DIR = path.join(HERE, "wallpapers");

/** 随包壁纸白名单，顺序即 UI 里的展示顺序。 */
export const WALLPAPERS = [
  { id: "terminal-rain", label: "终端雨", file: "terminal-rain.jpg" },
  { id: "hexstream", label: "十六进制", file: "hexstream.jpg" },
  { id: "topology", label: "拓扑", file: "topology.jpg" },
];

const BY_ID = new Map(WALLPAPERS.map((w) => [w.id, w]));
const CACHE_CONTROL = "public, max-age=604800, immutable";

/** 壁纸目录是否真的带上了文件（缺文件时路由直接 404，不去 stat 每次请求）。 */
export function wallpapersAvailable() {
  try {
    return fs.statSync(WALL_DIR).isDirectory();
  } catch {
    return false;
  }
}

/** 给 dsh-purge/settings 之类需要枚举的地方用。 */
export function wallpaperList() {
  return WALLPAPERS.map((w) => ({ id: w.id, label: w.label }));
}

/**
 * 处理 GET /purge-wallpapers/<id>.jpg。
 * @param {import("node:http").IncomingMessage} request
 * @param {import("node:http").ServerResponse} response
 * @param {string} subPath 前缀之后的部分，形如 "/terminal-rain.jpg"
 */
export function serveWallpaper(request, response, subPath) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { allow: "GET, HEAD" });
    response.end();
    return;
  }

  // 只取最后一段，且必须以 .jpg 结尾；任何带 .. 或绝对路径的输入都会被这里挡掉。
  const clean = String(subPath || "").replace(/^\/+/, "");
  const m = clean.match(/^([a-z0-9-]+)\.jpg$/i);
  const hit = m ? BY_ID.get(m[1]) : null;
  if (!hit) {
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
    return;
  }

  const file = path.join(WALL_DIR, hit.file);
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    response.end("not found");
    return;
  }

  const headers = {
    "content-type": "image/jpeg",
    "content-length": String(stat.size),
    "cache-control": CACHE_CONTROL,
    "x-content-type-options": "nosniff",
  };

  // 条件请求：文件名是固定的，内容变了就换名字，所以 ETag 用 size-mtime 足够。
  const etag = `"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
  headers.etag = etag;
  if (request.headers["if-none-match"] === etag) {
    response.writeHead(304, { etag, "cache-control": CACHE_CONTROL });
    response.end();
    return;
  }

  if (request.method === "HEAD") {
    response.writeHead(200, headers);
    response.end();
    return;
  }

  response.writeHead(200, headers);
  const stream = fs.createReadStream(file);
  stream.on("error", () => {
    try { response.destroy(); } catch { /* ignore */ }
  });
  stream.pipe(response);
}
