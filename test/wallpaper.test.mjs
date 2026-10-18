/**
 * 壁纸路由的端到端自检。
 *
 * 起一个只挂 /purge-wallpapers 前缀的临时 HTTP 服务，逐条断言：
 * 三张图能取到且 content-type / 长度对得上、HEAD 不带 body、
 * ETag 命中返回 304、越界路径与不存在 id 一律 404、非 GET/HEAD 返回 405。
 *
 * 用法：node test/wallpaper.test.mjs
 */
import http from "node:http";
import { fileURLToPath } from "node:url";
import path from "node:path";
import * as wallpapers from "../lib/wallpapers.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
let pass = 0;
let fail = 0;

function ok(name, cond, extra = "") {
  if (cond) { pass += 1; console.log(`  PASS  ${name}`); }
  else { fail += 1; console.log(`  FAIL  ${name} ${extra}`); }
}

const server = http.createServer((req, res) => {
  const url = String(req.url || "").split("?")[0];
  const sub = url.slice("/purge-wallpapers".length);
  wallpapers.serveWallpaper(req, res, sub);
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
ok("白名单正好 3 张", wallpapers.wallpaperList().length === 3);

for (const wp of wallpapers.wallpaperList()) {
  const r = await get(`/${wp.id}.jpg`);
  ok(
    `${wp.id}: 200 + image/jpeg + JPEG magic + 非空`,
    r.status === 200
      && r.headers.get("content-type") === "image/jpeg"
      && r.body[0] === 0xff && r.body[1] === 0xd8
      && r.body.length > 10_000,
    `status=${r.status} type=${r.headers.get("content-type")} len=${r.body.length}`,
  );
  const declared = Number(r.headers.get("content-length"));
  ok(`${wp.id}: content-length 与实际字节一致`, declared === r.body.length, `${declared} vs ${r.body.length}`);
}

{
  const r = await get("/terminal-rain.jpg", { method: "HEAD" });
  ok("HEAD 返回 200 且无 body", r.status === 200 && r.body.length === 0, `len=${r.body.length}`);
}

{
  const first = await get("/hexstream.jpg");
  const etag = first.headers.get("etag");
  ok("响应带 ETag", Boolean(etag), String(etag));
  const second = await get("/hexstream.jpg", { headers: { "if-none-match": etag } });
  ok("ETag 命中返回 304", second.status === 304, `status=${second.status}`);
}

for (const bad of ["/nope.jpg", "/terminal-rain.png", "/..%2F..%2Fpackage.json", "/", "/terminal-rain.jpg/extra"]) {
  const r = await get(bad);
  ok(`越界路径 ${bad} → 404`, r.status === 404, `status=${r.status}`);
}

{
  const r = await get("/topology.jpg", { method: "POST" });
  ok("POST 返回 405", r.status === 405, `status=${r.status}`);
}

server.close();
console.log(`\n结果：${pass} 通过, ${fail} 失败`);
console.log(fail === 0 ? "RESULT: ALL PASS" : "RESULT: FAIL");
process.exit(fail === 0 ? 0 : 1);
