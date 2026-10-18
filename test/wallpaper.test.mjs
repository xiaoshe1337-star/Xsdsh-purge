/**
 * 壁纸路由的端到端自检。
 *
 * 起一个只挂 /purge-wallpapers 前缀的临时 HTTP 服务，逐条断言：
 * 每张内置壁纸能取到且 content-type / 长度对得上、HEAD 不带 body、
 * ETag 命中返回 304、越界路径与不存在 id 一律 404、非 GET/HEAD 返回 405、
 * 视频支持 Range（206 + content-range，这是 <video> 拖进度条的硬前提）。
 *
 * 用法：node test/wallpaper.test.mjs
 */
import http from "node:http";
import * as wallpapers from "../lib/wallpapers.js";

let pass = 0;
let fail = 0;

function ok(name, cond, extra = "") {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name} ${extra}`); }
}

const server = http.createServer((req, res) => {
  const url = String(req.url || "").split("?")[0];
  wallpapers.serveWallpaper(req, res, url.slice("/purge-wallpapers".length));
});

await new Promise((r) => server.listen(0, "127.0.0.1", r));
const port = server.address().port;
const base = `http://127.0.0.1:${port}/purge-wallpapers`;

async function get(pathname, init) {
  const res = await fetch(base + pathname, init);
  const body = init?.method === "HEAD" ? Buffer.alloc(0) : Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, body };
}

console.log("壁纸路由自检 / wallpaper route");

ok("壁纸目录存在", wallpapers.wallpapersAvailable());

const list = wallpapers.availableWallpapers();
ok("内置壁纸至少 5 个", list.length >= 5, `实际 ${list.length}`);
ok("含动态壁纸", list.some((w) => w.kind === "video"));
ok("含静态壁纸", list.some((w) => w.kind === "image"));

for (const wp of list) {
  const ext = wp.kind === "video" ? "mp4" : "jpg";
  const r = await get(`/${wp.id}.${ext}`);
  const magicOk = wp.kind === "video"
    // ISO BMFF: 第 4..8 字节是 "ftyp"
    ? r.body.subarray(4, 8).toString("latin1") === "ftyp"
    : r.body[0] === 0xff && r.body[1] === 0xd8;
  ok(
    `${wp.id} (${wp.kind}): 200 + 正确 MIME + 魔数 + 非空`,
    r.status === 200
      && r.headers.get("content-type") === (wp.kind === "video" ? "video/mp4" : "image/jpeg")
      && magicOk
      && r.body.length > 10_000,
    `status=${r.status} type=${r.headers.get("content-type")} len=${r.body.length}`,
  );
  const declared = Number(r.headers.get("content-length"));
  ok(`${wp.id}: content-length 与实际一致`, declared === r.body.length, `${declared} vs ${r.body.length}`);
}

{
  const r = await get("/neko-aurora.mp4", { method: "HEAD" });
  ok("HEAD 返回 200 且无 body", r.status === 200 && r.body.length === 0, `len=${r.body.length}`);
  ok("HEAD 带 accept-ranges", r.headers.get("accept-ranges") === "bytes");
}

{
  const first = await get("/neko-ripple.mp4");
  const etag = first.headers.get("etag");
  ok("响应带 ETag", Boolean(etag), String(etag));
  const second = await get("/neko-ripple.mp4", { headers: { "if-none-match": etag } });
  ok("ETag 命中返回 304", second.status === 304, `status=${second.status}`);
}

{
  // Range 是视频能拖进度条的前提
  const full = await get("/neko-aurora.mp4");
  const total = full.body.length;
  const r = await get("/neko-aurora.mp4", { headers: { range: "bytes=0-1023" } });
  ok("Range 返回 206", r.status === 206, `status=${r.status}`);
  ok("Range 内容是前 1024 字节", r.body.length === 1024 && r.body.equals(full.body.subarray(0, 1024)), `len=${r.body.length}`);
  ok(
    "Range 带 content-range",
    r.headers.get("content-range") === `bytes 0-1023/${total}`,
    String(r.headers.get("content-range")),
  );

  const tail = await get("/neko-aurora.mp4", { headers: { range: "bytes=-512" } });
  ok("尾部 Range (bytes=-512) 正确", tail.status === 206 && tail.body.length === 512, `len=${tail.body.length}`);

  const bad = await get("/neko-aurora.mp4", { headers: { range: "bytes=999999999-" } });
  ok("越界 Range 返回 416", bad.status === 416, `status=${bad.status}`);
}

for (const bad of [
  "/nope.jpg",
  "/neko-aurora.jpg",        // id 存在但扩展名不符
  "/terminal-rain.mp4",      // 反向：静态图配视频扩展名
  "/..%2F..%2Fpackage.json",
  "/",
  "/neko-aurora.mp4/extra",
]) {
  const r = await get(bad);
  ok(`越界路径 ${bad} → 404`, r.status === 404, `status=${r.status}`);
}

{
  const r = await get("/neko-ripple.mp4", { method: "POST" });
  ok("POST 返回 405", r.status === 405, `status=${r.status}`);
}

server.close();
console.log(`\n结果：${pass} 通过, ${fail} 失败`);
console.log(fail === 0 ? "RESULT: ALL PASS" : "RESULT: FAIL");
process.exit(fail === 0 ? 0 : 1);
