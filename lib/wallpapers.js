/**
 * 内置壁纸的静态路由。
 *
 * 壁纸全部随插件包分发，分两类：
 *   lib/wallpapers/*.jpg   静态图（2560x1440）
 *   lib/wallpapers/*.mp4   动态壁纸（1920x1080，可无缝循环）
 * 浏览器端直接 <img src> / <video src> 拉取，不经过客户端 bundle。
 *
 * 安全边界：
 * - 只认白名单里的 id，路径由服务端拼，不接受客户端传进来的任意片段；
 * - 不做目录列表，不做通配；
 * - 只允许 GET / HEAD。
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WALL_DIR = path.join(HERE, "wallpapers");

const IMAGE_MIME = {
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".webp": "image/webp",
};
const VIDEO_MIME = {
  ".mp4": "video/mp4",
  ".webm": "video/webm",
};

/**
 * 随包壁纸白名单，顺序即 UI 里的展示顺序。
 * kind=image 走 <img>，kind=video 走 <video autoplay loop muted playsinline>。
 */
export const WALLPAPERS = [
  { id: "neko-aurora", label: "极光", file: "neko-aurora.mp4", kind: "video" },
  { id: "neko-ripple", label: "涟漪", file: "neko-ripple.mp4", kind: "video" },
  { id: "terminal-rain", label: "终端雨", file: "terminal-rain.jpg", kind: "image" },
  { id: "hexstream", label: "十六进制", file: "hexstream.jpg", kind: "image" },
  { id: "topology", label: "拓扑", file: "topology.jpg", kind: "image" },
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

/** 给客户端枚举用：id / 名称 / 类型。 */
export function wallpaperList() {
  return WALLPAPERS.map((w) => ({ id: w.id, label: w.label, kind: w.kind }));
}

/** 只报磁盘上真实存在的那些，免得列表里点开 404。 */
export function availableWallpapers() {
  return wallpaperList().filter((w) => {
    const hit = BY_ID.get(w.id);
    try {
      return Boolean(hit) && fs.statSync(path.join(WALL_DIR, hit.file)).isFile();
    } catch {
      return false;
    }
  });
}

function notFound(response) {
  response.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  response.end("not found");
}

/**
 * 流式发送媒体文件，带 Range 支持。
 *
 * <video> 一定要 Range：浏览器对视频会发 `Range: bytes=0-`，服务器若回
 * 200 + 完整 body，播放器要等整个文件下完才开始播，seek 也会失败。
 * 这里按 RFC 7233 实现单区间。
 */
function sendMedia(request, response, file) {
  let stat;
  try {
    stat = fs.statSync(file);
  } catch {
    notFound(response);
    return;
  }
  if (!stat.isFile()) {
    notFound(response);
    return;
  }

  const ext = path.extname(file).toLowerCase();
  const type = IMAGE_MIME[ext] || VIDEO_MIME[ext] || "application/octet-stream";
  const etag = `"${stat.size.toString(16)}-${Math.floor(stat.mtimeMs).toString(16)}"`;
  const baseHeaders = {
    "content-type": type,
    "cache-control": CACHE_CONTROL,
    "x-content-type-options": "nosniff",
    "accept-ranges": "bytes",
    etag,
  };

  if (request.headers["if-none-match"] === etag) {
    response.writeHead(304, { etag, "cache-control": CACHE_CONTROL });
    response.end();
    return;
  }

  const rangeHeader = String(request.headers.range || "");
  let start = 0;
  let end = stat.size - 1;
  let partial = false;
  if (rangeHeader) {
    const m = rangeHeader.match(/^bytes=(\d*)-(\d*)$/);
    if (m && (m[1] || m[2])) {
      if (m[1]) {
        start = Number(m[1]);
        end = m[2] ? Math.min(Number(m[2]), stat.size - 1) : stat.size - 1;
      } else {
        const tail = Number(m[2]);
        start = Math.max(0, stat.size - tail);
        end = stat.size - 1;
      }
      if (!Number.isFinite(start) || !Number.isFinite(end) || start > end || start >= stat.size) {
        response.writeHead(416, {
          "content-range": `bytes */${stat.size}`,
          "content-type": "text/plain; charset=utf-8",
        });
        response.end("range not satisfiable");
        return;
      }
      partial = true;
    }
  }

  const length = end - start + 1;
  if (partial) {
    response.writeHead(206, {
      ...baseHeaders,
      "content-length": String(length),
      "content-range": `bytes ${start}-${end}/${stat.size}`,
    });
  } else {
    response.writeHead(200, {
      ...baseHeaders,
      "content-length": String(stat.size),
    });
  }

  if (request.method === "HEAD") {
    response.end();
    return;
  }

  const stream = fs.createReadStream(file, { start, end });
  stream.on("error", () => {
    try { response.destroy(); } catch { /* ignore */ }
  });
  stream.pipe(response);
}

/**
 * 处理 GET /purge-wallpapers/<id>.<ext>。
 * @param {import("node:http").IncomingMessage} request
 * @param {import("node:http").ServerResponse} response
 * @param {string} subPath 前缀之后的部分，形如 "/neko-aurora.mp4"
 */
export function serveWallpaper(request, response, subPath) {
  if (request.method !== "GET" && request.method !== "HEAD") {
    response.writeHead(405, { allow: "GET, HEAD" });
    response.end();
    return;
  }

  // 只取最后一段；任何带 .. 或绝对路径的输入都会被这条正则挡掉。
  const clean = String(subPath || "").replace(/^\/+/, "").split("?")[0];
  const m = clean.match(/^([a-z0-9-]+)\.(jpg|jpeg|png|webp|mp4|webm)$/i);
  const hit = m ? BY_ID.get(m[1]) : null;
  if (!hit) {
    notFound(response);
    return;
  }
  // 扩展名必须与白名单里登记的一致，避免同一 id 换个后缀绕过。
  if (path.extname(hit.file).slice(1).toLowerCase() !== m[2].toLowerCase()) {
    notFound(response);
    return;
  }
  sendMedia(request, response, path.join(WALL_DIR, hit.file));
}
