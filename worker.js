// Cloudflare Worker 邮件追踪器
// 绑定：D1 数据库变量名 DB
// 环境变量（必须）：
//   ADMIN        —— 后台管理密码
//   IPAPI_KEY    —— ipapi.is 的 Key（用于 IP 详情查询，可留空）
// 可选环境变量：
//   IMAGE_HOST   —— 自定义图床地址，默认 https://tc.ilqx.dpdns.org

const DEFAULT_IMAGE_HOST = "https://tc.ilqx.dpdns.org";
const IMAGE_UPLOAD_PATH = "/upload";
const MAX_FILE_SIZE = 5 * 1024 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{4,64}$/;
const SESSION_MAX_AGE = 86400;

let dbReady = false;

export default {
  async fetch(request, env, ctx) {
    if (!env.ADMIN) return renderSetupNotice();

    const url = new URL(request.url);
    const path = url.pathname;

    await initDB(env);

    if (path === "/" || path === "/index.html") return renderHome(request, env);

    if (path.startsWith("/pixel/")) {
      const id = path.split("/")[2];
      if (!id) return notFound();
      return handlePixel(request, env, id);
    }

    if (path === "/api/generate" && request.method === "POST") return handleGenerate(request, env);
    if (path === "/api/query") return handleQuery(request, env);
    if (path === "/api/stats") return handleStats(request, env);

    if (path === "/admin/login" && request.method === "POST") return handleAdminLogin(request, env);
    if (path === "/admin/logout") return handleAdminLogout(request, env);
    if (path === "/admin") return renderAdmin(request, env);

    if (path === "/api/admin/delete" && request.method === "POST") return handleAdminDelete(request, env);
    if (path === "/api/admin/clear" && request.method === "POST") return handleAdminClear(request, env);
    if (path === "/api/admin/delete-target" && request.method === "POST") return handleAdminDeleteTarget(request, env);
    if (path === "/api/admin/delete-targets" && request.method === "POST") return handleAdminDeleteTargets(request, env);
    if (path === "/api/admin/clear-targets" && request.method === "POST") return handleAdminClearTargets(request, env);

    if (/^\/tile\/\d+\/\d+\/\d+\.png$/.test(path)) return handleTile(request);

    return notFound();
  }
};

function notFound() {
  return new Response("Not Found", { status: 404 });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8" }
  });
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  return new Response(html, {
    status,
    headers: { "Content-Type": "text/html; charset=utf-8", ...extraHeaders }
  });
}

function escapeHtml(s) {
  return String(s ?? "").replace(/[&<>"']/g, c => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ============ 数据库 ============
async function initDB(env) {
  if (dbReady) return;

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS targets (
      id TEXT PRIMARY KEY,
      creator_ip TEXT,
      creator_ua TEXT,
      creator_webrtc_ips TEXT,
      creator_fingerprint TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  for (const col of ["password_hash", "media_type", "media_source", "media_url"]) {
    try { await env.DB.prepare(`ALTER TABLE targets ADD COLUMN ${col} TEXT DEFAULT ''`).run(); } catch (e) {}
  }

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS tracking_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target_id TEXT NOT NULL,
      event_type TEXT NOT NULL DEFAULT 'open',
      ip TEXT,
      country TEXT,
      country_code TEXT,
      region TEXT,
      city TEXT,
      timezone TEXT,
      isp TEXT,
      org TEXT,
      as_text TEXT,
      lat REAL,
      lon REAL,
      ua TEXT,
      languages TEXT,
      referer TEXT,
      accept TEXT,
      accept_encoding TEXT,
      sec_ch_ua TEXT,
      sec_ch_ua_platform TEXT,
      sec_ch_ua_mobile TEXT,
      opened_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  for (const col of [
    "country_code", "region", "city", "timezone", "isp", "org", "as_text",
    "referer", "accept", "accept_encoding", "sec_ch_ua", "sec_ch_ua_platform", "sec_ch_ua_mobile"
  ]) {
    try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN ${col} TEXT`).run(); } catch (e) {}
  }
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lat REAL`).run(); } catch (e) {}
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lon REAL`).run(); } catch (e) {}

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admin_session (
      id INTEGER PRIMARY KEY,
      token TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  dbReady = true;
}

// ============ 工具 ============
async function sha256Hex(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function hashPassword(id, password) {
  return sha256Hex(`${id}::mailtrack::${password}`);
}

async function getIpInfo(ip) {
  if (!ip || ip === "Unknown" || ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.")) {
    return null;
  }
  try {
    const resp = await fetch(
      `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,countryCode,regionName,city,timezone,isp,org,as,lat,lon`
    );
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.status !== "success") return null;
    return {
      country: data.country || "",
      countryCode: data.countryCode || "",
      region: data.regionName || "",
      city: data.city || "",
      timezone: data.timezone || "",
      isp: data.isp || "",
      org: data.org || "",
      as_text: data.as || "",
      lat: data.lat ?? null,
      lon: data.lon ?? null
    };
  } catch {
    return null;
  }
}

async function uploadFileToHost(env, file) {
  const host = env.IMAGE_HOST || DEFAULT_IMAGE_HOST;
  const fd = new FormData();
  fd.append("file", file, file.name || "file");
  const resp = await fetch(host + IMAGE_UPLOAD_PATH, { method: "POST", body: fd });
  if (!resp.ok) throw new Error(`图床上传失败 HTTP ${resp.status}`);
  const result = await resp.json().catch(() => null);
  if (Array.isArray(result) && result[0]?.src) return host + result[0].src;
  if (result?.data?.url) return result.data.url;
  if (result?.url) return result.url;
  throw new Error("图床返回格式无法识别");
}

// ============ 追踪像素 ============
function transparentPixel() {
  const b64 = "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==";
  const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  return new Response(bytes, {
    headers: {
      "Content-Type": "image/gif",
      "Cache-Control": "no-cache, no-store, must-revalidate",
      "Pragma": "no-cache",
      "Expires": "0"
    }
  });
}

async function handlePixel(request, env, targetId) {
  const ip = request.headers.get("CF-Connecting-IP") || "Unknown";
  const cfCountry = request.cf?.country || "";
  const ua = request.headers.get("User-Agent") || "";
  const languages = request.headers.get("Accept-Language") || "";
  const referer = request.headers.get("Referer") || "";
  const accept = request.headers.get("Accept") || "";
  const acceptEncoding = request.headers.get("Accept-Encoding") || "";
  const secChUa = request.headers.get("Sec-Ch-Ua") || "";
  const secChUaPlatform = request.headers.get("Sec-Ch-Ua-Platform") || "";
  const secChUaMobile = request.headers.get("Sec-Ch-Ua-Mobile") || "";

  const target = await env.DB.prepare(
    "SELECT media_type, media_source, media_url FROM targets WHERE id = ?"
  ).bind(targetId).first();

  const ipInfo = await getIpInfo(ip);

  try {
    await env.DB.prepare(`
      INSERT INTO tracking_logs (
        target_id, event_type, ip, country, country_code, region, city, timezone,
        isp, org, as_text, lat, lon, ua, languages, referer, accept, accept_encoding,
        sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile
      ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      targetId, ip,
      ipInfo?.country || cfCountry || "",
      ipInfo?.countryCode || "",
      ipInfo?.region || "",
      ipInfo?.city || "",
      ipInfo?.timezone || "",
      ipInfo?.isp || "",
      ipInfo?.org || "",
      ipInfo?.as_text || "",
      ipInfo?.lat ?? null,
      ipInfo?.lon ?? null,
      ua, languages, referer, accept, acceptEncoding,
      secChUa, secChUaPlatform, secChUaMobile
    ).run();
  } catch (e) {}

  if (!target) return transparentPixel();

  const mediaSource = target.media_source || "default";
  const mediaUrl = target.media_url || "";

  if (mediaSource === "default" || !mediaUrl) return transparentPixel();

  try {
    const resp = await fetch(mediaUrl);
    if (!resp.ok) throw new Error("media fetch failed");
    const buf = await resp.arrayBuffer();
    return new Response(buf, {
      headers: {
        "Content-Type": resp.headers.get("Content-Type") || "application/octet-stream",
        "Content-Length": String(buf.byteLength),
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0",
        "Accept-Ranges": "bytes"
      }
    });
  } catch {
    return transparentPixel();
  }
}

// ============ 生成追踪 ============
async function handleGenerate(request, env) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return jsonResponse({ error: "请求格式错误" }, 400);
  }

  const customId = String(form.get("customId") || "").trim();
  const password = String(form.get("password") || "");
  const mediaType = String(form.get("mediaType") || "image");
  const source = String(form.get("source") || "default");
  const mediaUrlInput = String(form.get("mediaUrl") || "").trim();
  const file = form.get("mediaFile");
  const webrtcIps = String(form.get("webrtcIps") || "[]");
  const fingerprint = String(form.get("fingerprint") || "");
  const creatorIp = request.headers.get("CF-Connecting-IP") || "Unknown";
  const creatorUa = request.headers.get("User-Agent") || "";

  if (!ID_RE.test(customId)) {
    return jsonResponse({ error: "追踪 ID 需为 4-64 位字母、数字、下划线或短横线" }, 400);
  }
  if (password.length < 4) {
    return jsonResponse({ error: "访问密码至少 4 位" }, 400);
  }
  if (mediaType !== "image" && mediaType !== "video") {
    return jsonResponse({ error: "内容类型不正确" }, 400);
  }

  const existing = await env.DB.prepare("SELECT id FROM targets WHERE id = ?").bind(customId).first();
  if (existing) {
    return jsonResponse({ error: "该追踪 ID 已被占用，请换一个" }, 400);
  }

  let finalSource = source;
  let finalUrl = "";

  if (source === "upload") {
    if (!file || typeof file === "string" || !file.size) {
      return jsonResponse({ error: "请选择要上传的文件" }, 400);
    }
    if (file.size > MAX_FILE_SIZE) {
      return jsonResponse({ error: "文件大小不能超过 5 MB" }, 400);
    }
    const type = file.type || "";
    if (mediaType === "image" && !type.startsWith("image/")) {
      return jsonResponse({ error: "只允许上传图片文件" }, 400);
    }
    if (mediaType === "video" && !type.startsWith("video/")) {
      return jsonResponse({ error: "只允许上传视频文件" }, 400);
    }
    try {
      finalUrl = await uploadFileToHost(env, file);
    } catch (e) {
      return jsonResponse({ error: "上传失败：" + e.message }, 500);
    }
  } else if (source === "url") {
    if (!mediaUrlInput) return jsonResponse({ error: "请填写文件 URL" }, 400);
    if (!/^https?:\/\//i.test(mediaUrlInput)) {
      return jsonResponse({ error: "URL 必须以 http:// 或 https:// 开头" }, 400);
    }
    finalUrl = mediaUrlInput;
  } else {
    finalSource = mediaType === "video" ? "url" : "default";
    if (mediaType === "video") {
      return jsonResponse({ error: "视频必须选择自定义 URL 或上传视频" }, 400);
    }
  }

  const origin = new URL(request.url).origin;
  let trackingHtml;
  if (mediaType === "image" && finalSource === "default") {
    trackingHtml = `<img src="${origin}/pixel/${customId}" width="1" height="1" alt="" style="display:none" />`;
  } else if (mediaType === "image") {
    trackingHtml = `<img src="${origin}/pixel/${customId}" alt="" style="max-width:100%;height:auto;" />`;
  } else {
    trackingHtml = `<video src="${origin}/pixel/${customId}" controls playsinline preload="metadata" style="max-width:100%;height:auto;"></video>`;
  }

  const passwordHash = await hashPassword(customId, password);

  await env.DB.prepare(
    `INSERT INTO targets (id, password_hash, media_type, media_source, media_url,
      creator_ip, creator_ua, creator_webrtc_ips, creator_fingerprint)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    customId, passwordHash, mediaType, finalSource, finalUrl,
    creatorIp, creatorUa, webrtcIps, fingerprint
  ).run();

  return jsonResponse({
    id: customId,
    trackingHtml,
    emailHtml: `<div>${trackingHtml}</div>`
  });
}

// ============ 查询 / 统计 ============
async function verifyTarget(env, id, password) {
  const target = await env.DB.prepare(
    "SELECT id, password_hash, creator_ip, creator_webrtc_ips, media_type FROM targets WHERE id = ?"
  ).bind(id).first();
  if (!target) return { error: "追踪 ID 不存在", status: 404 };
  const hash = await hashPassword(id, password || "");
  if (hash !== (target.password_hash || "")) return { error: "访问密码错误", status: 403 };
  return { target };
}

async function handleQuery(request, env) {
  const params = new URL(request.url).searchParams;
  const id = params.get("id");
  const password = params.get("password") || "";
  if (!id) return jsonResponse({ error: "缺少追踪 ID" }, 400);

  const check = await verifyTarget(env, id, password);
  if (check.error) return jsonResponse({ error: check.error }, check.status);

  const creatorIps = new Set();
  if (check.target.creator_ip) creatorIps.add(check.target.creator_ip);
  if (check.target.creator_webrtc_ips) {
    try {
      const arr = JSON.parse(check.target.creator_webrtc_ips);
      if (Array.isArray(arr)) arr.forEach(ip => creatorIps.add(ip));
    } catch (e) {}
  }
  creatorIps.delete("Unknown");

  const logs = await env.DB.prepare(
    `SELECT id, target_id, event_type, ip, country, country_code, region, city, timezone,
      isp, org, as_text, lat, lon, ua, languages, referer, accept, accept_encoding,
      sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile, opened_at
     FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC`
  ).bind(id).all();

  const results = (logs.results || []).map(log => ({
    ...log,
    is_local: creatorIps.has(log.ip)
  }));

  return jsonResponse(results);
}

async function handleStats(request, env) {
  const params = new URL(request.url).searchParams;
  const id = params.get("id");
  const password = params.get("password") || "";
  if (!id) return jsonResponse({ error: "缺少追踪 ID" }, 400);

  const check = await verifyTarget(env, id, password);
  if (check.error) return jsonResponse({ error: check.error }, check.status);

  const total = await env.DB.prepare("SELECT COUNT(*) AS c FROM tracking_logs WHERE target_id = ?").bind(id).first();
  const unique = await env.DB.prepare("SELECT COUNT(DISTINCT ip) AS c FROM tracking_logs WHERE target_id = ?").bind(id).first();
  const latest = await env.DB.prepare("SELECT opened_at FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 1").bind(id).first();

  return jsonResponse({
    total: total?.c || 0,
    uniqueIps: unique?.c || 0,
    latestOpen: latest?.opened_at || null
  });
}

// ============ 后台登录 ============
function parseCookies(request) {
  const raw = request.headers.get("Cookie") || "";
  const out = {};
  raw.split(";").forEach(p => {
    const idx = p.indexOf("=");
    if (idx > -1) out[p.slice(0, idx).trim()] = p.slice(idx + 1).trim();
  });
  return out;
}

async function getAdminToken(env) {
  const row = await env.DB.prepare("SELECT token FROM admin_session WHERE id = 1").first();
  return row?.token || "";
}

async function checkAdmin(request, env) {
  const token = parseCookies(request).admin_session;
  if (!token) return false;
  const current = await getAdminToken(env);
  return !!current && current === token;
}

async function handleAdminLogin(request, env) {
  let form;
  try {
    form = await request.formData();
  } catch {
    return renderLogin("请求格式错误");
  }
  const password = String(form.get("password") || "");

  if (password !== env.ADMIN) {
    return renderLogin("密码错误，请重新输入");
  }

  const token = crypto.randomUUID().replace(/-/g, "") + crypto.randomUUID().replace(/-/g, "");
  await env.DB.prepare("DELETE FROM admin_session").run();
  await env.DB.prepare("INSERT INTO admin_session (id, token) VALUES (1, ?)").bind(token).run();

  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/admin",
      "Set-Cookie": `admin_session=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_MAX_AGE}`
    }
  });
}

async function handleAdminLogout(request, env) {
  await env.DB.prepare("DELETE FROM admin_session").run();
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/admin",
      "Set-Cookie": "admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    }
  });
}

// ============ 后台数据操作 ============
async function handleAdminDelete(request, env) {
  if (!await checkAdmin(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);
  const { id } = await request.json();
  await env.DB.prepare("DELETE FROM tracking_logs WHERE id = ?").bind(id).run();
  return jsonResponse({ success: true });
}

async function handleAdminClear(request, env) {
  if (!await checkAdmin(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);
  await env.DB.prepare("DELETE FROM tracking_logs").run();
  return jsonResponse({ success: true });
}

async function handleAdminDeleteTarget(request, env) {
  if (!await checkAdmin(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);
  const { id } = await request.json();
  await env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(id).run();
  await env.DB.prepare("DELETE FROM targets WHERE id = ?").bind(id).run();
  return jsonResponse({ success: true });
}

async function handleAdminDeleteTargets(request, env) {
  if (!await checkAdmin(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);
  const { ids } = await request.json();
  if (!Array.isArray(ids) || !ids.length) return jsonResponse({ error: "未选择任何 ID" }, 400);
  for (const id of ids) {
    await env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(id).run();
    await env.DB.prepare("DELETE FROM targets WHERE id = ?").bind(id).run();
  }
  return jsonResponse({ success: true });
}

async function handleAdminClearTargets(request, env) {
  if (!await checkAdmin(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);
  await env.DB.prepare("DELETE FROM tracking_logs").run();
  await env.DB.prepare("DELETE FROM targets").run();
  return jsonResponse({ success: true });
}

// ============ 地图瓦片 ============
async function handleTile(request) {
  const parts = new URL(request.url).pathname.split("/");
  const [z, x, yRaw] = [parts[2], parts[3], parts[4]];
  const y = yRaw.split(".")[0];
  const resp = await fetch(`https://a.tile.openstreetmap.org/${z}/${x}/${y}.png`, {
    headers: {
      "Referer": request.url,
      "User-Agent": request.headers.get("User-Agent") || "Mozilla/5.0"
    }
  });
  const headers = new Headers(resp.headers);
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Cache-Control", "public, max-age=86400");
  return new Response(resp.body, { status: resp.status, headers });
}

// ============ 未配置提示 ============
function renderSetupNotice() {
  return htmlResponse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>需要完成配置</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
    background:radial-gradient(1000px 500px at 15% 5%,#1e293b,#0b1120 65%);color:#e2e8f0}
  .box{max-width:560px;width:100%;background:rgba(30,41,59,.72);border:1px solid rgba(148,163,184,.18);
    border-radius:18px;padding:32px;backdrop-filter:blur(12px);box-shadow:0 24px 60px rgba(0,0,0,.45)}
  .icon{width:52px;height:52px;border-radius:16px;display:grid;place-items:center;font-size:24px;
    background:linear-gradient(135deg,#f59e0b,#ef4444);margin-bottom:20px}
  h1{font-size:20px;margin:0 0 12px;font-weight:600}
  p{font-size:14px;line-height:1.75;color:#94a3b8;margin:0 0 14px}
  code{background:rgba(15,23,42,.8);padding:3px 8px;border-radius:6px;color:#a5b4fc;
    font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px}
  ol{margin:0;padding-left:20px;color:#cbd5e1;font-size:14px;line-height:2}
  .foot{margin-top:24px;padding-top:18px;border-top:1px solid rgba(148,163,184,.15);
    font-size:12px;color:#64748b;text-align:center}
</style>
</head>
<body>
  <div class="box">
    <div class="icon">⚙️</div>
    <h1>还差一步：请先设置管理密码</h1>
    <p>这个 Worker 没有在代码里写死后台密码，密码只能通过 Cloudflare 环境变量下发。未配置之前，所有页面都不会对外提供服务。</p>
    <ol>
      <li>进入 Cloudflare 控制台 → Workers &amp; Pages → 打开本 Worker</li>
      <li>Settings → Variables and Secrets → 添加变量</li>
      <li>类型选 <code>Text</code>，变量名填 <code>ADMIN</code>，值填你的后台密码</li>
      <li>建议再添加一个 <code>IPAPI_KEY</code>，值为 ipapi.is 的 API Key（用于 IP 详情查询，可留空）</li>
      <li>保存后重新访问本页面</li>
    </ol>
    <div class="foot">Copyright © 2026 SAK All rights reserved.</div>
  </div>
</body>
</html>`, 503);
}

// ============ 登录页 ============
function renderLogin(errorMsg = "") {
  return htmlResponse(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>后台登录</title>
<style>
  *{box-sizing:border-box}
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;
    font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
    background:radial-gradient(1100px 560px at 20% 8%,#1e293b,#0b1120 62%);color:#e2e8f0}
  .card{width:100%;max-width:380px;background:rgba(30,41,59,.74);border:1px solid rgba(148,163,184,.18);
    border-radius:18px;padding:34px 28px 26px;backdrop-filter:blur(14px);box-shadow:0 24px 60px rgba(0,0,0,.5)}
  .logo{width:50px;height:50px;border-radius:15px;display:grid;place-items:center;font-size:22px;
    background:linear-gradient(135deg,#6366f1,#8b5cf6);margin-bottom:20px;
    box-shadow:0 10px 24px rgba(99,102,241,.35)}
  h1{font-size:19px;margin:0 0 6px;font-weight:600;letter-spacing:.3px}
  p.sub{margin:0 0 26px;font-size:13px;color:#94a3b8}
  label{display:block;font-size:13px;color:#cbd5e1;margin-bottom:8px}
  input{width:100%;padding:12px 14px;border-radius:11px;border:1px solid rgba(148,163,184,.25);
    background:rgba(15,23,42,.6);color:#e2e8f0;font-size:14px;outline:none;transition:.2s}
  input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.18)}
  button{width:100%;margin-top:20px;padding:12px;border:0;border-radius:11px;cursor:pointer;
    background:linear-gradient(135deg,#6366f1,#8b5cf6);color:#fff;font-size:14px;font-weight:600;
    transition:.2s;letter-spacing:2px}
  button:hover{filter:brightness(1.08)}
  button:active{transform:translateY(1px)}
  .err{margin-top:16px;font-size:13px;color:#fca5a5;text-align:center}
  .foot{margin-top:24px;padding-top:16px;border-top:1px solid rgba(148,163,184,.15);
    text-align:center;font-size:12px;color:#64748b}
</style>
</head>
<body>
  <form class="card" method="POST" action="/admin/login">
    <div class="logo">🔒</div>
    <h1>后台管理登录</h1>
    <p class="sub">每次登录都会重新下发凭证，同一时间仅允许一个会话在线</p>
    <label for="password">管理密码</label>
    <input id="password" name="password" type="password" autocomplete="current-password" autofocus required>
    <button type="submit">登录</button>
    ${errorMsg ? `<div class="err">${escapeHtml(errorMsg)}</div>` : ""}
    <div class="foot">Copyright © 2026 SAK All rights reserved.</div>
  </form>
</body>
</html>`, errorMsg ? 401 : 200);
}

// ============ 首页 ============
function renderHome(request, env) {
  const ipKeyJson = JSON.stringify(env.IPAPI_KEY || "");

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>邮件追踪器</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<script src="https://openfpcdn.io/fingerprintjs/v3/iife.min.js"><\/script>
<style>
  *{box-sizing:border-box}
  body{
    margin:0;padding:32px 16px 48px;
    background:#f7f8fb;
    color:#1f2937;
    font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
    -webkit-font-smoothing:antialiased;
  }
  .wrap{max-width:920px;margin:0 auto}
  .brand{margin-bottom:26px}
  .brand h1{font-size:24px;font-weight:700;margin:0 0 8px;letter-spacing:.2px}
  .brand p{margin:0;font-size:13.5px;color:#6b7280;line-height:1.7}
  .card{background:#fff;border-radius:16px;padding:24px;margin-bottom:20px;
    box-shadow:0 1px 2px rgba(16,24,40,.04),0 8px 24px -12px rgba(16,24,40,.12)}
  .card h2{font-size:16px;font-weight:600;margin:0 0 18px;display:flex;align-items:center;gap:8px}
  .field{margin-bottom:18px}
  .field > label{display:block;font-size:13px;font-weight:500;color:#374151;margin-bottom:7px}
  input[type=text],input[type=password],input[type=url]{
    width:100%;padding:10px 13px;border:1px solid #e3e6ec;border-radius:10px;
    font-size:14px;outline:none;transition:.18s;background:#fcfcfd;color:#111827}
  input[type=text]:focus,input[type=password]:focus,input[type=url]:focus{
    border-color:#6366f1;background:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.12)}
  input[type=file]{width:100%;padding:9px 11px;border:1px dashed #d5d9e2;border-radius:10px;
    font-size:13px;background:#fcfcfd;color:#4b5563}
  .hint{font-size:12px;color:#9ca3af;margin:6px 0 0;line-height:1.6}
  .chips{display:flex;flex-wrap:wrap;gap:9px}
  .chip{position:relative;display:inline-flex;align-items:center;gap:7px;
    padding:9px 14px;border:1px solid #e3e6ec;border-radius:10px;font-size:13.5px;
    cursor:pointer;background:#fcfcfd;transition:.16s;user-select:none;color:#374151}
  .chip:hover{border-color:#c7cbe0;background:#f7f8ff}
  .chip input{accent-color:#6366f1;margin:0}
  .chip:has(input:checked){border-color:#6366f1;background:#eef0ff;color:#4338ca;font-weight:500}
  .sub-box{margin-top:12px}
  .btn{display:inline-flex;align-items:center;gap:8px;justify-content:center;
    padding:11px 22px;border:0;border-radius:10px;font-size:14px;font-weight:600;
    cursor:pointer;transition:.18s;background:#4f46e5;color:#fff}
  .btn:hover{background:#4338ca}
  .btn:disabled{opacity:.6;cursor:not-allowed}
  .btn-ghost{background:#eef0f6;color:#374151}
  .btn-ghost:hover{background:#e3e6f0}
  .btn-green{background:#059669}
  .btn-green:hover{background:#047857}
  .btn-blue{background:#2563eb}
  .btn-blue:hover{background:#1d4ed8}
  .row{display:flex;gap:10px;flex-wrap:wrap}
  .row > *{flex:1 1 200px;min-width:0}
  .code-box{width:100%;min-height:70px;padding:12px;border:1px solid #e3e6ec;border-radius:10px;
    font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;resize:vertical;
    background:#fcfcfd;color:#374151;line-height:1.6;word-break:break-all}
  .muted{color:#9ca3af;font-size:13.5px}
  .err{color:#dc2626;font-size:13.5px}
  .ip-card{background:#fbfbfd;border:1px solid #eceef3;border-radius:14px;padding:16px;margin-bottom:14px}
  .ip-head{display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between}
  .ip-main{display:flex;flex-wrap:wrap;align-items:center;gap:8px;min-width:0;flex:1 1 220px}
  .ip-addr{font-family:ui-monospace,Menlo,Consolas,monospace;font-weight:700;font-size:15px;
    color:#4338ca;word-break:break-all;overflow-wrap:anywhere;min-width:0;max-width:100%}
  .ip-loc{font-size:13px;color:#6b7280;word-break:break-word}
  .ip-count{font-size:12px;color:#9ca3af}
  .flag{width:20px;height:14px;border-radius:3px;box-shadow:0 1px 2px rgba(0,0,0,.18);flex:none}
  .badge{background:#fef3c7;color:#92400e;padding:2px 9px;border-radius:999px;
    font-size:11px;font-weight:600;white-space:nowrap}
  .link-btn{background:none;border:0;padding:0;color:#4f46e5;font-size:13px;
    cursor:pointer;text-decoration:underline;white-space:nowrap}
  .link-btn:hover{color:#3730a3}
  .timeline{margin-top:14px;border-left:2px solid #e9ebf2;padding-left:14px;margin-left:5px}
  .tl-item{position:relative;padding:7px 0}
  .tl-item::before{content:"";position:absolute;left:-20px;top:13px;width:9px;height:9px;
    background:#6366f1;border-radius:50%;border:2px solid #fff;box-shadow:0 0 0 2px #c7cbf7}
  .tl-time{font-size:12px;color:#9ca3af}
  .tl-text{font-size:12px;color:#6b7280;margin-top:4px;word-break:break-all;overflow-wrap:anywhere;line-height:1.6}
  .map-container{height:280px;width:100%;border-radius:12px;margin-top:12px;border:1px solid #e9ebf2;z-index:0}
  .modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);
    align-items:center;justify-content:center;z-index:999;padding:18px}
  .modal.active{display:flex}
  .modal-content{background:#fff;border-radius:18px;padding:22px;max-width:640px;width:100%;
    max-height:88vh;overflow-y:auto;box-shadow:0 24px 60px rgba(0,0,0,.28)}
  .modal-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  .modal-head h3{margin:0;font-size:16px;font-weight:600}
  .close-btn{background:none;border:0;font-size:24px;line-height:1;color:#9ca3af;cursor:pointer;padding:0 4px}
  .close-btn:hover{color:#ef4444}
  .detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px 14px}
  @media (max-width:560px){.detail-grid{grid-template-columns:1fr}}
  .d-item{display:flex;justify-content:space-between;gap:10px;padding:6px 0;
    border-bottom:1px solid #f1f2f6;font-size:13px}
  .d-label{color:#6b7280;flex:none}
  .d-value{font-weight:500;text-align:right;word-break:break-all;overflow-wrap:anywhere;min-width:0}
  .sec-title{font-size:13.5px;font-weight:600;margin:16px 0 8px}
  .panel-bg{background:#f8f9fc;border-radius:12px;padding:12px 14px}
  .toast{position:fixed;left:50%;top:22px;transform:translate(-50%,-140%);
    background:#111827;color:#fff;padding:11px 20px;border-radius:11px;font-size:13.5px;
    transition:transform .28s ease;z-index:2000;max-width:88vw;text-align:center;
    box-shadow:0 12px 32px rgba(0,0,0,.28)}
  .toast.show{transform:translate(-50%,0)}
  footer{text-align:center;font-size:12px;color:#9ca3af;line-height:2;margin-top:34px}
  footer a{color:#6b7280;text-decoration:none}
  footer a:hover{color:#4f46e5;text-decoration:underline}
  .hidden{display:none !important}
</style>
</head>
<body>
<div class="wrap">

  <div class="brand">
    <h1>邮件追踪器</h1>
    <p>生成一段追踪代码，粘贴进邮件的 HTML 源码。收件人打开邮件的那一刻，IP、归属地、设备信息会被自动记录。</p>
  </div>

  <!-- 生成 -->
  <div class="card">
    <h2><i class="fa-solid fa-wand-magic-sparkles" style="color:#6366f1"></i> 生成追踪代码</h2>

    <div class="field">
      <label>追踪 ID</label>
      <input id="customId" type="text" maxlength="64" placeholder="4-64 位字母、数字、下划线或短横线">
      <p class="hint">ID 全局唯一，被占用时无法生成，请换一个。</p>
    </div>

    <div class="field">
      <label>访问密码</label>
      <input id="password" type="password" placeholder="至少 4 位，查询记录时同样需要">
      <p class="hint">密码会经过加盐哈希后保存，查询该 ID 的记录时必须输入正确密码。</p>
    </div>

    <div class="field">
      <label>追踪内容</label>
      <div class="chips">
        <label class="chip"><input type="radio" name="mediaType" value="image" checked> 图片</label>
        <label class="chip"><input type="radio" name="mediaType" value="video"> 视频</label>
      </div>
    </div>

    <div id="imagePanel" class="field">
      <div class="chips">
        <label class="chip"><input type="radio" name="imageSource" value="default" checked> 默认 1×1 隐藏像素</label>
        <label class="chip"><input type="radio" name="imageSource" value="url"> 自定义图片 URL</label>
        <label class="chip"><input type="radio" name="imageSource" value="upload"> 上传图片</label>
      </div>
      <div id="imageUrlBox" class="sub-box hidden">
        <input id="imageUrl" type="url" placeholder="https://example.com/pic.jpg">
      </div>
      <div id="imageFileBox" class="sub-box hidden">
        <input id="imageFile" type="file" accept="image/*">
        <p class="hint">支持 JPG / PNG / GIF / WebP 等图片格式，单个文件不超过 5 MB。</p>
      </div>
    </div>

    <div id="videoPanel" class="field hidden">
      <div class="chips">
        <label class="chip"><input type="radio" name="videoSource" value="url" checked> 自定义视频 URL</label>
        <label class="chip"><input type="radio" name="videoSource" value="upload"> 上传视频</label>
      </div>
      <div id="videoUrlBox" class="sub-box">
        <input id="videoUrl" type="url" placeholder="https://example.com/clip.mp4">
      </div>
      <div id="videoFileBox" class="sub-box hidden">
        <input id="videoFile" type="file" accept="video/*">
        <p class="hint">支持 MP4 / WebM 等视频格式，单个文件不超过 5 MB。邮件客户端对视频的支持有限，建议作为网页嵌入使用。</p>
      </div>
    </div>

    <button id="genBtn" class="btn"><i class="fa-solid fa-bolt"></i> 生成追踪代码</button>

    <div id="result" class="hidden" style="margin-top:20px">
      <label style="display:block;font-size:13px;font-weight:500;color:#374151;margin-bottom:7px">
        将以下代码粘贴到邮件的 HTML 源码中
      </label>
      <textarea id="imgCode" class="code-box" readonly></textarea>
      <p class="hint" style="margin-top:8px">
        追踪 ID：<strong id="trackId" style="color:#4f46e5"></strong>
      </p>
      <button id="copyBtn" class="btn btn-ghost" style="margin-top:10px">
        <i class="fa-regular fa-copy"></i> 复制代码
      </button>
    </div>
  </div>

  <!-- 查询 -->
  <div class="card">
    <h2><i class="fa-solid fa-magnifying-glass" style="color:#059669"></i> 查询记录</h2>
    <div class="row" style="margin-bottom:10px">
      <input id="queryId" type="text" placeholder="追踪 ID">
      <input id="queryPwd" type="password" placeholder="访问密码">
    </div>
    <div class="row">
      <button id="queryBtn" class="btn btn-green" style="flex:0 1 auto"><i class="fa-solid fa-magnifying-glass"></i> 查询</button>
      <button id="statsBtn" class="btn btn-blue" style="flex:0 1 auto"><i class="fa-solid fa-chart-simple"></i> 统计</button>
    </div>
    <div id="statsResult" class="hidden" style="margin-top:14px;font-size:13.5px;color:#4b5563"></div>
    <div id="queryResult" style="margin-top:18px"></div>
  </div>

  <footer>
    <div>Copyright © 2026 SAK All rights reserved.</div>
    <div>
      QQ:3344310554 &nbsp;·&nbsp; E-mail:cnzz666@163.com &nbsp;·&nbsp;
      <a href="https://b23.tv/8fCttY7" target="_blank" rel="noopener">Bilibili:SAK_CN</a>
    </div>
    <div><a href="/admin">后台管理</a> · 仅供合法测试</div>
  </footer>
</div>

<div id="toast" class="toast"></div>

<!-- IP 详情弹窗 -->
<div id="ipModal" class="modal">
  <div class="modal-content">
    <div class="modal-head">
      <h3><i class="fa-solid fa-circle-info" style="color:#6366f1"></i> IP 详细信息</h3>
      <button class="close-btn" onclick="document.getElementById('ipModal').classList.remove('active')">&times;</button>
    </div>
    <div id="ipModalBody"></div>
  </div>
</div>

<script>
(function () {
  "use strict";

  var IPAPI_KEY = ${ipKeyJson};
  var mapInstances = {};

  var $ = function (sel) { return document.querySelector(sel); };

  var toastTimer;
  function toast(msg) {
    var el = document.getElementById("toast");
    el.textContent = msg;
    el.classList.add("show");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.remove("show"); }, 2800);
  }

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  /* ---------- 采集创建者信息 ---------- */
  var creatorWebRTC = [];
  var creatorFingerprint = null;

  (function collect() {
    if (window.FingerprintJS) {
      FingerprintJS.load().then(function (fp) { return fp.get(); })
        .then(function (r) { creatorFingerprint = r; })
        .catch(function () {});
    }
    try {
      var ips = new Set();
      var pc = new RTCPeerConnection({
        iceServers: [
          { urls: "stun:stun.chat.bilibili.com:3478" },
          { urls: "stun:stun.hitv.com:3478" },
          { urls: "stun:stun.miwifi.com:3478" },
          { urls: "stun:stun.l.google.com:19302" }
        ]
      });
      pc.createDataChannel("");
      pc.onicecandidate = function (e) {
        if (!e.candidate || !e.candidate.candidate) return;
        var m = e.candidate.candidate.match(/([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i);
        if (m && m[1] && m[1] !== "0.0.0.0" && m[1] !== "127.0.0.1") ips.add(m[1]);
      };
      pc.createOffer().then(function (o) { return pc.setLocalDescription(o); }).catch(function () {});
      setTimeout(function () {
        creatorWebRTC = Array.from(ips);
        try { pc.close(); } catch (e) {}
      }, 2600);
    } catch (e) {}
  })();

  /* ---------- 面板切换 ---------- */
  function currentMedia() {
    return document.querySelector('input[name="mediaType"]:checked').value;
  }

  function syncPanels() {
    var media = currentMedia();
    document.getElementById("imagePanel").classList.toggle("hidden", media !== "image");
    document.getElementById("videoPanel").classList.toggle("hidden", media !== "video");

    if (media === "image") {
      var src = document.querySelector('input[name="imageSource"]:checked').value;
      document.getElementById("imageUrlBox").classList.toggle("hidden", src !== "url");
      document.getElementById("imageFileBox").classList.toggle("hidden", src !== "upload");
    } else {
      var vsrc = document.querySelector('input[name="videoSource"]:checked').value;
      document.getElementById("videoUrlBox").classList.toggle("hidden", vsrc !== "url");
      document.getElementById("videoFileBox").classList.toggle("hidden", vsrc !== "upload");
    }
  }

  document.querySelectorAll('input[name="mediaType"], input[name="imageSource"], input[name="videoSource"]')
    .forEach(function (el) { el.addEventListener("change", syncPanels); });

  /* ---------- 生成 ---------- */
  document.getElementById("genBtn").addEventListener("click", async function () {
    var btn = this;
    var customId = document.getElementById("customId").value.trim();
    var password = document.getElementById("password").value;
    var mediaType = currentMedia();

    if (!/^[A-Za-z0-9_-]{4,64}$/.test(customId)) {
      return toast("追踪 ID 需为 4-64 位字母、数字、下划线或短横线");
    }
    if (password.length < 4) return toast("访问密码至少 4 位");

    var fd = new FormData();
    fd.append("customId", customId);
    fd.append("password", password);
    fd.append("mediaType", mediaType);

    if (mediaType === "image") {
      var src = document.querySelector('input[name="imageSource"]:checked').value;
      fd.append("source", src);
      if (src === "url") {
        var u = document.getElementById("imageUrl").value.trim();
        if (!u) return toast("请填写图片 URL");
        fd.append("mediaUrl", u);
      } else if (src === "upload") {
        var f = document.getElementById("imageFile").files[0];
        if (!f) return toast("请选择图片文件");
        if (f.size > 5 * 1024 * 1024) return toast("图片大小不能超过 5 MB");
        if (!f.type || f.type.indexOf("image/") !== 0) return toast("请选择图片文件");
        fd.append("mediaFile", f);
      }
    } else {
      var vsrc = document.querySelector('input[name="videoSource"]:checked').value;
      fd.append("source", vsrc);
      if (vsrc === "url") {
        var vu = document.getElementById("videoUrl").value.trim();
        if (!vu) return toast("请填写视频 URL");
        fd.append("mediaUrl", vu);
      } else {
        var vf = document.getElementById("videoFile").files[0];
        if (!vf) return toast("请选择视频文件");
        if (vf.size > 5 * 1024 * 1024) return toast("视频大小不能超过 5 MB");
        if (!vf.type || vf.type.indexOf("video/") !== 0) return toast("请选择视频文件");
        fd.append("mediaFile", vf);
      }
    }

    fd.append("webrtcIps", JSON.stringify(creatorWebRTC));
    if (creatorFingerprint) fd.append("fingerprint", JSON.stringify(creatorFingerprint));

    btn.disabled = true;
    var original = btn.innerHTML;
    btn.textContent = "生成中…";

    try {
      var res = await fetch("/api/generate", { method: "POST", body: fd });
      var data = await res.json();
      if (!res.ok) return toast(data.error || "生成失败");
      document.getElementById("imgCode").value = data.trackingHtml;
      document.getElementById("trackId").textContent = data.id;
      document.getElementById("result").classList.remove("hidden");
      toast("生成成功");
    } catch (e) {
      toast("网络错误：" + e.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = original;
    }
  });

  /* ---------- 复制 ---------- */
  document.getElementById("copyBtn").addEventListener("click", function () {
    var ta = document.getElementById("imgCode");
    ta.select();
    ta.setSelectionRange(0, 99999);
    try {
      if (navigator.clipboard) {
        navigator.clipboard.writeText(ta.value).then(function () { toast("已复制"); });
      } else {
        document.execCommand("copy");
        toast("已复制");
      }
    } catch (e) {
      document.execCommand("copy");
      toast("已复制");
    }
  });

  /* ---------- 查询 ---------- */
  function mapIdOf(ip) {
    return "map_" + String(ip).replace(/[^a-zA-Z0-9]/g, "_");
  }

  function renderLogs(logs) {
    var groups = {};
    logs.forEach(function (log) {
      var ip = log.ip || "Unknown";
      if (!groups[ip]) groups[ip] = [];
      groups[ip].push(log);
    });

    var html = "";
    Object.keys(groups).forEach(function (ip) {
      var items = groups[ip];
      var first = items[0];
      var hasGeo = first.lat && first.lon;
      var flag = first.country_code
        ? '<img class="flag" src="https://ipdata.co/flags/' + encodeURIComponent(String(first.country_code).toLowerCase()) + '.png" alt="">'
        : "";
      var isLocal = items.some(function (i) { return i.is_local; });
      var locText = [first.country, first.city].filter(Boolean).join(" ");

      html += '<div class="ip-card">';
      html += '  <div class="ip-head">';
      html += '    <div class="ip-main">';
      html += '      <span class="ip-addr">' + esc(ip) + "</span>" + flag;
      if (locText) html += '      <span class="ip-loc">' + esc(locText) + "</span>";
      if (isLocal) html += '      <span class="badge"><i class="fa-solid fa-house"></i> 本地查看</span>';
      html += '      <span class="ip-count">共 ' + items.length + " 次打开</span>";
      html += "    </div>";
      html += '    <button class="link-btn ip-detail-btn"'
        + ' data-ip="' + esc(ip) + '"'
        + ' data-country="' + esc(first.country || "") + '"'
        + ' data-region="' + esc(first.region || "") + '"'
        + ' data-city="' + esc(first.city || "") + '"'
        + ' data-lat="' + esc(first.lat || "") + '"'
        + ' data-lon="' + esc(first.lon || "") + '"'
        + ' data-timezone="' + esc(first.timezone || "") + '"'
        + ' data-isp="' + esc(first.isp || "") + '"'
        + ' data-org="' + esc(first.org || "") + '"'
        + ' data-as="' + esc(first.as_text || "") + '"'
        + ' data-countrycode="' + esc(first.country_code || "") + '">'
        + '<i class="fa-solid fa-circle-info"></i> 详情</button>';
      html += "  </div>";

      if (hasGeo) {
        html += '  <div class="ip-loc" style="margin-top:10px;font-size:12.5px;color:#6b7280">'
          + "📍 " + esc([first.city, first.region, first.country].filter(Boolean).join(", "))
          + " &nbsp;|&nbsp; 时区：" + esc(first.timezone || "未知")
          + " &nbsp;|&nbsp; " + esc([first.isp, first.org].filter(Boolean).join(" ") || "未知")
          + "</div>";
        html += '  <div id="' + mapIdOf(ip) + '" class="map-container"></div>';
      } else {
        html += '  <div class="muted" style="margin-top:10px;font-size:12.5px">🌐 未获取到地理位置</div>';
      }

      html += '  <div class="timeline">';
      items.forEach(function (log) {
        var date = new Date(log.opened_at + "Z").toLocaleString("zh-CN", { timeZone: "Asia/Shanghai" });
        html += '<div class="tl-item">';
        html += '  <div class="tl-time">' + esc(date)
          + (log.is_local ? ' <span class="badge" style="font-size:10px">本地</span>' : "")
          + "</div>";
        html += '  <div class="tl-text"><strong>UA：</strong>' + esc(log.ua || "未知") + "</div>";
        if (log.referer) html += '  <div class="tl-text"><strong>Referer：</strong>' + esc(log.referer) + "</div>";
        if (log.languages) html += '  <div class="tl-text"><strong>语言：</strong>' + esc(log.languages) + "</div>";
        if (log.sec_ch_ua_platform) html += '  <div class="tl-text"><strong>平台：</strong>' + esc(log.sec_ch_ua_platform) + "</div>";
        html += "</div>";
      });
      html += "  </div>";
      html += "</div>";
    });

    return html;
  }

  function initMaps(logs) {
    var groups = {};
    logs.forEach(function (log) {
      var ip = log.ip || "Unknown";
      if (!groups[ip]) groups[ip] = log;
    });

    setTimeout(function () {
      Object.keys(groups).forEach(function (ip) {
        var first = groups[ip];
        if (!first.lat || !first.lon) return;
        var el = document.getElementById(mapIdOf(ip));
        if (!el) return;
        var key = mapIdOf(ip);
        if (mapInstances[key]) {
          try { mapInstances[key].remove(); } catch (e) {}
          delete mapInstances[key];
        }
        var map = L.map(el, { scrollWheelZoom: false }).setView([first.lat, first.lon], 5);
        L.tileLayer("/tile/{z}/{x}/{y}.png", {
          maxZoom: 19,
          attribution: "&copy; OpenStreetMap"
        }).addTo(map);
        L.marker([first.lat, first.lon]).addTo(map)
          .bindPopup(esc(ip) + "<br>" + esc([first.city, first.country].filter(Boolean).join(", ")));
        mapInstances[key] = map;
      });
    }, 90);
  }

  function bindDetailButtons() {
    document.querySelectorAll(".ip-detail-btn").forEach(function (btn) {
      btn.addEventListener("click", function () {
        showIPDetail(this.dataset.ip, {
          country: this.dataset.country,
          region: this.dataset.region,
          city: this.dataset.city,
          lat: this.dataset.lat,
          lon: this.dataset.lon,
          timezone: this.dataset.timezone,
          isp: this.dataset.isp,
          org: this.dataset.org,
          as: this.dataset.as,
          countryCode: this.dataset.countrycode
        });
      });
    });
  }

  async function doQuery() {
    var id = document.getElementById("queryId").value.trim();
    var pwd = document.getElementById("queryPwd").value;
    var box = document.getElementById("queryResult");

    if (!id) return toast("请输入追踪 ID");
    if (!pwd) return toast("请输入访问密码");

    box.innerHTML = '<p class="muted">查询中…</p>';

    try {
      var res = await fetch("/api/query?id=" + encodeURIComponent(id) + "&password=" + encodeURIComponent(pwd));
      var data = await res.json();
      if (!res.ok) {
        box.innerHTML = '<p class="err">' + esc(data.error || "查询失败") + "</p>";
        return;
      }
      if (!Array.isArray(data) || !data.length) {
        box.innerHTML = '<p class="muted">暂无打开记录</p>';
        return;
      }
      box.innerHTML = renderLogs(data);
      bindDetailButtons();
      initMaps(data);
    } catch (e) {
      box.innerHTML = '<p class="err">查询失败：' + esc(e.message) + "</p>";
    }
  }

  document.getElementById("queryBtn").addEventListener("click", doQuery);
  document.getElementById("queryPwd").addEventListener("keydown", function (e) {
    if (e.key === "Enter") doQuery();
  });

  document.getElementById("statsBtn").addEventListener("click", async function () {
    var id = document.getElementById("queryId").value.trim();
    var pwd = document.getElementById("queryPwd").value;
    var box = document.getElementById("statsResult");
    box.classList.remove("hidden");

    if (!id) { box.innerHTML = '<span class="err">请输入追踪 ID</span>'; return; }
    if (!pwd) { box.innerHTML = '<span class="err">请输入访问密码</span>'; return; }

    box.innerHTML = "统计中…";
    try {
      var res = await fetch("/api/stats?id=" + encodeURIComponent(id) + "&password=" + encodeURIComponent(pwd));
      var data = await res.json();
      if (!res.ok) { box.innerHTML = '<span class="err">' + esc(data.error || "统计失败") + "</span>"; return; }
      box.innerHTML = "📊 总打开：<strong>" + data.total + "</strong> 次 &nbsp;·&nbsp; 独立 IP：<strong>"
        + data.uniqueIps + "</strong> 个 &nbsp;·&nbsp; 最近打开："
        + (data.latestOpen ? esc(new Date(data.latestOpen + "Z").toLocaleString("zh-CN")) : "无");
    } catch (e) {
      box.innerHTML = '<span class="err">统计失败</span>';
    }
  });

  /* ---------- IP 详情 ---------- */
  function detailRow(label, value) {
    return '<div class="d-item"><span class="d-label">' + label + '</span><span class="d-value">' + value + "</span></div>";
  }

  async function showIPDetail(ip, fallback) {
    fallback = fallback || {};
    var body = document.getElementById("ipModalBody");
    document.getElementById("ipModal").classList.add("active");

    if (!IPAPI_KEY) {
      body.innerHTML = '<p class="err">未配置 IPAPI_KEY，无法查询 IP 详情。请在 Worker 环境变量中添加 IPAPI_KEY。</p>';
      return;
    }

    body.innerHTML = '<p class="muted">加载中…</p>';

    var data = null;
    try {
      var res = await fetch("https://api.ipapi.is/?q=" + encodeURIComponent(ip) + "&key=" + encodeURIComponent(IPAPI_KEY));
      if (res.ok) data = await res.json();
    } catch (e) {}

    if (!data || data.error) {
      body.innerHTML = '<p class="err">无法获取该 IP 的详细信息，请稍后重试。</p>';
      return;
    }

    var loc = data.location || {};
    var comp = data.company || {};
    var asn = data.asn || {};
    var dc = data.datacenter || {};
    var abuse = data.abuse || {};

    var cc = loc.country_code || fallback.countryCode || "";
    var country = loc.country || fallback.country || "未知";
    var region = loc.state || fallback.region || "未知";
    var city = loc.city || fallback.city || "未知";
    var timezone = loc.timezone || fallback.timezone || "未知";
    var lat = loc.latitude || fallback.lat || null;
    var lon = loc.longitude || fallback.lon || null;

    var risk = "未知";
    if (typeof data.risk_score === "number") {
      risk = data.risk_score.toFixed(2) + "% " + (data.risk_score > 30 ? "⚠️ 高风险" : "正常");
    } else if (data.is_proxy || data.is_tor || data.is_vpn || data.is_abuser) {
      risk = "⚠️ 高风险";
    } else if (data.is_datacenter) {
      risk = "🏢 数据中心";
    }

    var html = "";
    html += '<div style="display:flex;align-items:center;gap:10px;padding-bottom:12px;border-bottom:1px solid #eef0f5">';
    html += '<span style="font-family:ui-monospace,Menlo,monospace;font-weight:700;font-size:16px;color:#4338ca;word-break:break-all">' + esc(ip) + "</span>";
    if (cc) {
      html += '<img src="https://ipdata.co/flags/' + encodeURIComponent(String(cc).toLowerCase()) + '.png" style="width:30px;height:21px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,.2)" alt="">';
    }
    html += "</div>";

    html += '<div class="sec-title" style="color:#4338ca">📍 基本信息</div><div class="panel-bg detail-grid">';
    html += detailRow("国家 / 地区", esc(country + (cc ? " (" + cc + ")" : "")));
    html += detailRow("州 / 省", esc(region));
    html += detailRow("城市", esc(city));
    html += detailRow("时区", esc(timezone));
    html += detailRow("经纬度", esc(lat && lon ? lat + ", " + lon : "未知"));
    html += detailRow("风控评级", '<span style="color:' + (risk.indexOf("高风险") > -1 ? "#dc2626" : "#059669") + '">' + risk + "</span>");
    html += "</div>";

    html += '<div class="sec-title" style="color:#047857">🏢 运营商 / ASN</div><div class="panel-bg detail-grid">';
    html += detailRow("运营商", esc(comp.name || "未知"));
    html += detailRow("类型", esc(comp.type || "未知"));
    html += detailRow("域名", esc(comp.domain || "未知"));
    html += detailRow("ASN", esc(asn.asn || "未知"));
    html += detailRow("ASN 描述", esc(asn.descr || "未知"));
    html += detailRow("ASN 所属", esc(asn.org || "未知"));
    html += detailRow("路由前缀", esc(asn.route || "未知"));
    html += detailRow("ASN 国家", esc(asn.country || "未知"));
    html += "</div>";

    if (dc.datacenter) {
      html += '<div class="sec-title" style="color:#b45309">☁️ 数据中心</div><div class="panel-bg detail-grid">';
      html += detailRow("名称", esc(dc.datacenter));
      html += detailRow("服务商", esc(dc.service || "未知"));
      html += detailRow("区域", esc(dc.scope || "未知"));
      html += detailRow("网段", esc(dc.network || "未知"));
      html += "</div>";
    }

    if (abuse.email) {
      html += '<div class="sec-title" style="color:#dc2626">⚠️ 滥用举报</div><div class="panel-bg detail-grid">';
      html += detailRow("姓名", esc(abuse.name || "未知"));
      html += detailRow("邮箱", esc(abuse.email));
      html += detailRow("电话", esc(abuse.phone || "未知"));
      html += detailRow("地址", esc(abuse.address || "未知"));
      html += "</div>";
    }

    html += '<div class="sec-title" style="color:#7c3aed">🛡️ 安全检测</div><div class="panel-bg detail-grid">';
    html += detailRow("数据中心", data.is_datacenter ? "🏢 是" : "✅ 否");
    html += detailRow("代理", data.is_proxy ? "⚠️ 是" : "✅ 否");
    html += detailRow("VPN", data.is_vpn ? "⚠️ 是" : "✅ 否");
    html += detailRow("Tor", data.is_tor ? "⚠️ 是" : "✅ 否");
    html += detailRow("爬虫", data.is_crawler ? "⚠️ 是" : "✅ 否");
    html += detailRow("移动网络", data.is_mobile ? "📱 是" : "✅ 否");
    html += detailRow("卫星网络", data.is_satellite ? "🛰️ 是" : "✅ 否");
    html += detailRow("已知滥用", data.is_abuser ? '<span style="color:#dc2626">⚠️ 是</span>' : "✅ 否");
    html += "</div>";

    if (lat && lon) {
      html += '<div class="sec-title" style="color:#2563eb">🗺️ 地理位置</div>';
      html += '<div id="ipDetailMap" class="map-container" style="height:260px"></div>';
    }

    body.innerHTML = html;

    if (lat && lon && window.L) {
      setTimeout(function () {
        var el = document.getElementById("ipDetailMap");
        if (!el) return;
        var map = L.map(el, { scrollWheelZoom: false }).setView([lat, lon], 8);
        L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 19 }).addTo(map);
        L.marker([lat, lon]).addTo(map)
          .bindPopup(esc(ip) + "<br>" + esc([city, country].filter(Boolean).join(", ")));
      }, 60);
    }
  }

  document.getElementById("ipModal").addEventListener("click", function (e) {
    if (e.target === this) this.classList.remove("active");
  });

  syncPanels();
})();
<\/script>
</body>
</html>`;

  return htmlResponse(html);
}

// ============ 后台页面 ============
async function renderAdmin(request, env) {
  if (!await checkAdmin(request, env)) {
    return renderLogin();
  }

  const ipKeyJson = JSON.stringify(env.IPAPI_KEY || "");

  const totalTargets = await env.DB.prepare("SELECT COUNT(*) AS c FROM targets").first();
  const totalLogs = await env.DB.prepare("SELECT COUNT(*) AS c FROM tracking_logs").first();
  const uniqueIps = await env.DB.prepare("SELECT COUNT(DISTINCT ip) AS c FROM tracking_logs").first();

  const filter = new URL(request.url).searchParams.get("filter_id") || "";

  const logs = filter
    ? await env.DB.prepare("SELECT * FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 200").bind(filter).all()
    : await env.DB.prepare("SELECT * FROM tracking_logs ORDER BY opened_at DESC LIMIT 200").all();

  const targetsResult = await env.DB.prepare(
    "SELECT id, creator_ip, creator_ua, creator_webrtc_ips, creator_fingerprint, media_type, media_source FROM targets"
  ).all();

  const targetMap = {};
  for (const t of (targetsResult.results || [])) targetMap[t.id] = t;

  const mediaLabel = { image: "图片", video: "视频" };
  const sourceLabel = { default: "隐藏像素", url: "外链", upload: "上传" };

  // 日志表格
  let rows = "";
  for (const r of (logs.results || [])) {
    const date = new Date(r.opened_at + "Z").toLocaleString("zh-CN");
    const geo = [r.country, r.region, r.city].filter(Boolean).join(", ");
    const info = targetMap[r.target_id] || {};

    let isLocal = false;
    if (info.creator_ip && r.ip === info.creator_ip) isLocal = true;
    if (!isLocal && info.creator_webrtc_ips) {
      try {
        const arr = JSON.parse(info.creator_webrtc_ips);
        if (Array.isArray(arr) && arr.includes(r.ip)) isLocal = true;
      } catch (e) {}
    }

    const cc = r.country_code || "";
    const flagHtml = cc
      ? `<img class="flag" src="https://ipdata.co/flags/${escapeHtml(String(cc).toLowerCase())}.png" alt="">`
      : "";
    const localBadge = isLocal
      ? '<span class="local-badge">本地</span>'
      : "";
    const media = info.media_type
      ? `<span class="media-tag">${mediaLabel[info.media_type] || info.media_type}</span>`
      : '<span class="muted-tag">—</span>';

    rows += `<tr>
      <td><input type="checkbox" class="target-checkbox" data-target-id="${escapeHtml(r.target_id)}"></td>
      <td class="mono">${escapeHtml(r.target_id)}</td>
      <td>${media}</td>
      <td class="nowrap">${escapeHtml(date)}</td>
      <td class="mono ip-cell">${escapeHtml(r.ip || "")} ${flagHtml}${localBadge}
        <button class="admin-ip-detail"
          data-ip="${escapeHtml(r.ip || "")}"
          data-country="${escapeHtml(r.country || "")}"
          data-region="${escapeHtml(r.region || "")}"
          data-city="${escapeHtml(r.city || "")}"
          data-lat="${escapeHtml(r.lat || "")}"
          data-lon="${escapeHtml(r.lon || "")}"
          data-timezone="${escapeHtml(r.timezone || "")}"
          data-isp="${escapeHtml(r.isp || "")}"
          data-org="${escapeHtml(r.org || "")}"
          data-as="${escapeHtml(r.as_text || "")}"
          data-countrycode="${escapeHtml(cc)}">详情</button>
      </td>
      <td>${escapeHtml(geo)}</td>
      <td>${escapeHtml(r.timezone || "")}</td>
      <td class="ua-cell">${escapeHtml(r.ua || "")}</td>
      <td><button class="danger-btn del-btn" data-id="${r.id}">删除</button></td>
    </tr>`;
  }

  // 创建者表格
  let creatorRows = "";
  for (const id of Object.keys(targetMap)) {
    const info = targetMap[id];
    let webrtcArr = [];
    try {
      const parsed = info.creator_webrtc_ips ? JSON.parse(info.creator_webrtc_ips) : [];
      if (Array.isArray(parsed)) webrtcArr = parsed;
    } catch (e) {}

    const webrtcStr = webrtcArr.length
      ? webrtcArr.map(ip =>
          `<span class="mono">${escapeHtml(ip)}</span> <button class="admin-ip-detail"
            data-ip="${escapeHtml(ip)}" data-country="" data-region="" data-city=""
            data-lat="" data-lon="" data-timezone="" data-isp="" data-org=""
            data-as="" data-countrycode="">详情</button>`
        ).join(" &nbsp;")
      : '<span class="muted-tag">无</span>';

    let fpId = "—";
    if (info.creator_fingerprint) {
      try {
        const fp = JSON.parse(info.creator_fingerprint);
        if (fp && fp.visitorId) fpId = String(fp.visitorId).slice(0, 14);
      } catch (e) {}
    }

    const creatorIp = info.creator_ip || "Unknown";

    creatorRows += `<tr>
      <td><input type="checkbox" class="creator-checkbox" data-creator-id="${escapeHtml(id)}"></td>
      <td class="mono">${escapeHtml(id)}</td>
      <td class="mono ip-cell">${escapeHtml(creatorIp)}
        <button class="admin-ip-detail"
          data-ip="${escapeHtml(creatorIp)}" data-country="" data-region="" data-city=""
          data-lat="" data-lon="" data-timezone="" data-isp="" data-org=""
          data-as="" data-countrycode="">详情</button>
      </td>
      <td class="ua-cell">${escapeHtml(info.creator_ua || "")}</td>
      <td class="ip-cell">${webrtcStr}</td>
      <td class="mono">${escapeHtml(fpId)}</td>
      <td><button class="danger-btn del-target-btn" data-id="${escapeHtml(id)}">删除 ID</button></td>
    </tr>`;
  }

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>后台管理</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<style>
  *{box-sizing:border-box}
  body{margin:0;padding:24px 16px 48px;background:#f6f7fb;color:#1f2937;
    font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
    -webkit-font-smoothing:antialiased}
  .wrap{max-width:1300px;margin:0 auto}
  .topbar{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:12px;margin-bottom:20px}
  .topbar h1{font-size:20px;font-weight:700;margin:0}
  .stats{display:flex;flex-wrap:wrap;gap:14px;margin-bottom:20px}
  .stat{background:#fff;border-radius:14px;padding:16px 20px;flex:1 1 160px;
    box-shadow:0 1px 2px rgba(16,24,40,.04),0 8px 24px -16px rgba(16,24,40,.2)}
  .stat .num{font-size:24px;font-weight:700;line-height:1.2}
  .stat .lbl{font-size:12px;color:#6b7280;margin-top:4px}
  .card{background:#fff;border-radius:16px;padding:20px;margin-bottom:20px;
    box-shadow:0 1px 2px rgba(16,24,40,.04),0 8px 24px -16px rgba(16,24,40,.2)}
  .card h2{font-size:15.5px;font-weight:600;margin:0 0 14px}
  .toolbar{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px}
  .toolbar input{flex:1 1 200px;min-width:0;padding:9px 12px;border:1px solid #e3e6ec;
    border-radius:9px;font-size:13.5px;outline:none}
  .toolbar input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.12)}
  button{cursor:pointer;border:0;border-radius:9px;padding:9px 15px;font-size:13px;
    font-weight:500;transition:.16s}
  .btn-soft{background:#eef0f6;color:#374151}
  .btn-soft:hover{background:#e2e5ef}
  .btn-red{background:#fee2e2;color:#b91c1c}
  .btn-red:hover{background:#fecaca}
  .btn-red-strong{background:#fca5a5;color:#7f1d1d}
  .btn-red-strong:hover{background:#f87171}
  .btn-outline{background:#fff;border:1px solid #e3e6ec;color:#4b5563}
  .btn-outline:hover{background:#f7f8fc}
  .table-wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
  table{width:100%;border-collapse:collapse;font-size:13px}
  thead th{background:#f9fafb;text-align:left;padding:10px 10px;font-weight:600;
    font-size:12px;color:#6b7280;border-bottom:1px solid #eceef3;white-space:nowrap}
  tbody td{padding:10px;border-bottom:1px solid #f3f4f7;vertical-align:middle}
  tbody tr:hover{background:#fafbff}
  .mono{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all;overflow-wrap:anywhere}
  .ip-cell{max-width:260px;word-break:break-all;overflow-wrap:anywhere}
  .ua-cell{max-width:260px;font-size:11.5px;color:#6b7280;word-break:break-all;overflow-wrap:anywhere}
  .nowrap{white-space:nowrap}
  .flag{width:18px;height:12px;border-radius:2px;box-shadow:0 1px 2px rgba(0,0,0,.18);
    vertical-align:middle;margin-left:4px}
  .local-badge{background:#fef3c7;color:#92400e;padding:1px 7px;border-radius:999px;
    font-size:10.5px;font-weight:600;margin-left:5px;white-space:nowrap}
  .media-tag{background:#eef2ff;color:#4338ca;padding:2px 8px;border-radius:999px;
    font-size:11px;font-weight:600;white-space:nowrap}
  .muted-tag{color:#9ca3af;font-size:12px}
  .admin-ip-detail{background:none;border:0;padding:0 0 0 6px;color:#4f46e5;
    font-size:12px;text-decoration:underline;cursor:pointer}
  .admin-ip-detail:hover{color:#3730a3}
  .danger-btn{background:none;border:0;padding:0;color:#dc2626;font-size:12px;
    text-decoration:underline;cursor:pointer}
  .danger-btn:hover{color:#991b1b}
  .modal{display:none;position:fixed;inset:0;background:rgba(15,23,42,.55);
    align-items:center;justify-content:center;z-index:999;padding:18px}
  .modal.active{display:flex}
  .modal-content{background:#fff;border-radius:18px;padding:22px;max-width:640px;width:100%;
    max-height:88vh;overflow-y:auto;box-shadow:0 24px 60px rgba(0,0,0,.28)}
  .modal-head{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
  .modal-head h3{margin:0;font-size:16px;font-weight:600}
  .close-btn{background:none;border:0;font-size:24px;line-height:1;color:#9ca3af;cursor:pointer}
  .close-btn:hover{color:#ef4444}
  .detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:2px 14px}
  @media (max-width:560px){.detail-grid{grid-template-columns:1fr}}
  .d-item{display:flex;justify-content:space-between;gap:10px;padding:6px 0;
    border-bottom:1px solid #f1f2f6;font-size:13px}
  .d-label{color:#6b7280;flex:none}
  .d-value{font-weight:500;text-align:right;word-break:break-all;overflow-wrap:anywhere;min-width:0}
  .sec-title{font-size:13.5px;font-weight:600;margin:16px 0 8px}
  .panel-bg{background:#f8f9fc;border-radius:12px;padding:12px 14px}
  .map-container{height:260px;width:100%;border-radius:12px;margin-top:10px;border:1px solid #e9ebf2}
  .err{color:#dc2626}
  footer{text-align:center;font-size:12px;color:#9ca3af;line-height:2;margin-top:26px}
  footer a{color:#6b7280;text-decoration:none}
  footer a:hover{color:#4f46e5;text-decoration:underline}
</style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <h1>后台管理</h1>
    <div style="display:flex;gap:8px;flex-wrap:wrap">
      <button class="btn-outline" onclick="location.href='/'">返回首页</button>
      <a href="/admin/logout" class="btn-outline" style="text-decoration:none;display:inline-flex;align-items:center">退出登录</a>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num" style="color:#4f46e5">${totalTargets?.c || 0}</div><div class="lbl">追踪 ID 总数</div></div>
    <div class="stat"><div class="num" style="color:#059669">${totalLogs?.c || 0}</div><div class="lbl">总打开次数</div></div>
    <div class="stat"><div class="num" style="color:#d97706">${uniqueIps?.c || 0}</div><div class="lbl">独立 IP 数</div></div>
  </div>

  <div class="card">
    <h2>📋 追踪日志（最近 200 条）</h2>
    <div class="toolbar">
      <input id="filterInput" value="${escapeHtml(filter)}" placeholder="按追踪 ID 过滤">
      <button class="btn-soft" id="filterBtn">筛选</button>
      <button class="btn-red" id="clearAllBtn">清空全部日志</button>
      <button class="btn-red-strong" id="clearTargetsBtn">清空所有 ID</button>
      <button class="btn-red-strong" id="deleteSelectedBtn">删除选中 ID</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th><input type="checkbox" id="selectAll"></th>
            <th>追踪 ID</th>
            <th>类型</th>
            <th>时间</th>
            <th>IP</th>
            <th>地理位置</th>
            <th>时区</th>
            <th>UA</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>${rows || '<tr><td colspan="9" class="muted-tag" style="text-align:center;padding:26px">暂无数据</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="card">
    <h2>🧑‍💻 追踪 ID 创建者信息</h2>
    <div class="toolbar">
      <button class="btn-red-strong" id="deleteSelectedCreatorsBtn">删除选中创建者</button>
    </div>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th><input type="checkbox" id="selectAllCreators"></th>
            <th>追踪 ID</th>
            <th>创建 IP</th>
            <th>UA</th>
            <th>WebRTC 泄露 IP</th>
            <th>指纹 ID</th>
            <th>操作</th>
          </tr>
        </thead>
        <tbody>${creatorRows || '<tr><td colspan="7" class="muted-tag" style="text-align:center;padding:26px">暂无数据</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <footer>
    <div>Copyright © 2026 SAK All rights reserved.</div>
    <div>
      QQ:3344310554 &nbsp;·&nbsp; E-mail:cnzz666@163.com &nbsp;·&nbsp;
      <a href="https://b23.tv/8fCttY7" target="_blank" rel="noopener">Bilibili:SAK_CN</a>
    </div>
  </footer>
</div>

<div id="ipModal" class="modal">
  <div class="modal-content">
    <div class="modal-head">
      <h3>IP 详细信息</h3>
      <button class="close-btn" onclick="document.getElementById('ipModal').classList.remove('active')">&times;</button>
    </div>
    <div id="ipModalBody"></div>
  </div>
</div>

<script>
(function () {
  "use strict";
  var IPAPI_KEY = ${ipKeyJson};
  var $ = function (s) { return document.querySelector(s); };

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  function postJSON(url, body) {
    return fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {})
    });
  }

  $("#selectAll").addEventListener("change", function () {
    document.querySelectorAll(".target-checkbox").forEach(function (cb) { cb.checked = this.checked; }, this);
  });
  $("#selectAllCreators").addEventListener("change", function () {
    document.querySelectorAll(".creator-checkbox").forEach(function (cb) { cb.checked = this.checked; }, this);
  });

  $("#deleteSelectedBtn").addEventListener("click", async function () {
    var checked = document.querySelectorAll(".target-checkbox:checked");
    if (!checked.length) return alert("请至少选择一个追踪 ID");
    if (!confirm("确认删除选中的 " + checked.length + " 个追踪 ID 及其全部日志？")) return;
    var ids = Array.prototype.map.call(checked, function (cb) { return cb.dataset.targetId; });
    var res = await postJSON("/api/admin/delete-targets", { ids: ids });
    if (res.ok) location.reload(); else alert("删除失败");
  });

  $("#deleteSelectedCreatorsBtn").addEventListener("click", async function () {
    var checked = document.querySelectorAll(".creator-checkbox:checked");
    if (!checked.length) return alert("请至少选择一个创建者");
    if (!confirm("确认删除选中的 " + checked.length + " 个创建者及其全部日志？")) return;
    var ids = Array.prototype.map.call(checked, function (cb) { return cb.dataset.creatorId; });
    var res = await postJSON("/api/admin/delete-targets", { ids: ids });
    if (res.ok) location.reload(); else alert("删除失败");
  });

  $("#clearTargetsBtn").addEventListener("click", async function () {
    if (!confirm("⚠️ 将清空所有追踪 ID 及其日志，此操作不可撤销。确认继续？")) return;
    var res = await postJSON("/api/admin/clear-targets");
    if (res.ok) location.reload(); else alert("操作失败");
  });

  $("#clearAllBtn").addEventListener("click", async function () {
    if (!confirm("清空全部日志记录？此操作不可撤销。")) return;
    var res = await postJSON("/api/admin/clear");
    if (res.ok) location.reload(); else alert("操作失败");
  });

  $("#filterBtn").addEventListener("click", function () {
    var v = $("#filterInput").value.trim();
    location.href = "/admin" + (v ? "?filter_id=" + encodeURIComponent(v) : "");
  });

  document.querySelectorAll(".del-btn").forEach(function (b) {
    b.addEventListener("click", async function () {
      if (!confirm("删除这条日志？")) return;
      await postJSON("/api/admin/delete", { id: parseInt(this.dataset.id, 10) });
      location.reload();
    });
  });

  document.querySelectorAll(".del-target-btn").forEach(function (b) {
    b.addEventListener("click", async function () {
      if (!confirm("删除该追踪 ID 及其全部日志？")) return;
      await postJSON("/api/admin/delete-target", { id: this.dataset.id });
      location.reload();
    });
  });

  /* ---------- IP 详情 ---------- */
  function row(label, value) {
    return '<div class="d-item"><span class="d-label">' + label + '</span><span class="d-value">' + value + "</span></div>";
  }

  async function showIPDetail(ip, fallback) {
    var body = document.getElementById("ipModalBody");
    document.getElementById("ipModal").classList.add("active");

    if (!IPAPI_KEY) {
      body.innerHTML = '<p class="err">未配置 IPAPI_KEY，无法查询 IP 详情。</p>';
      return;
    }
    body.innerHTML = "<p style='color:#9ca3af'>加载中…</p>";

    var data = null;
    try {
      var res = await fetch("https://api.ipapi.is/?q=" + encodeURIComponent(ip) + "&key=" + encodeURIComponent(IPAPI_KEY));
      if (res.ok) data = await res.json();
    } catch (e) {}

    if (!data || data.error) {
      body.innerHTML = '<p class="err">无法获取该 IP 的详细信息，请稍后重试。</p>';
      return;
    }

    var loc = data.location || {};
    var comp = data.company || {};
    var asn = data.asn || {};
    var dc = data.datacenter || {};
    var abuse = data.abuse || {};

    var cc = loc.country_code || fallback.countryCode || "";
    var country = loc.country || fallback.country || "未知";
    var region = loc.state || fallback.region || "未知";
    var city = loc.city || fallback.city || "未知";
    var timezone = loc.timezone || fallback.timezone || "未知";
    var lat = loc.latitude || fallback.lat || null;
    var lon = loc.longitude || fallback.lon || null;

    var risk = "未知";
    if (typeof data.risk_score === "number") {
      risk = data.risk_score.toFixed(2) + "% " + (data.risk_score > 30 ? "⚠️ 高风险" : "正常");
    } else if (data.is_proxy || data.is_tor || data.is_vpn || data.is_abuser) {
      risk = "⚠️ 高风险";
    } else if (data.is_datacenter) {
      risk = "🏢 数据中心";
    }

    var html = "";
    html += '<div style="display:flex;align-items:center;gap:10px;padding-bottom:12px;border-bottom:1px solid #eef0f5">';
    html += '<span style="font-family:ui-monospace,Menlo,monospace;font-weight:700;font-size:16px;color:#4338ca;word-break:break-all">' + esc(ip) + "</span>";
    if (cc) html += '<img src="https://ipdata.co/flags/' + encodeURIComponent(String(cc).toLowerCase()) + '.png" style="width:30px;height:21px;border-radius:4px" alt="">';
    html += "</div>";

    html += '<div class="sec-title" style="color:#4338ca">📍 基本信息</div><div class="panel-bg detail-grid">';
    html += row("国家 / 地区", esc(country + (cc ? " (" + cc + ")" : "")));
    html += row("州 / 省", esc(region));
    html += row("城市", esc(city));
    html += row("时区", esc(timezone));
    html += row("经纬度", esc(lat && lon ? lat + ", " + lon : "未知"));
    html += row("风控评级", '<span style="color:' + (risk.indexOf("高风险") > -1 ? "#dc2626" : "#059669") + '">' + risk + "</span>");
    html += "</div>";

    html += '<div class="sec-title" style="color:#047857">🏢 运营商 / ASN</div><div class="panel-bg detail-grid">';
    html += row("运营商", esc(comp.name || "未知"));
    html += row("类型", esc(comp.type || "未知"));
    html += row("域名", esc(comp.domain || "未知"));
    html += row("ASN", esc(asn.asn || "未知"));
    html += row("ASN 描述", esc(asn.descr || "未知"));
    html += row("ASN 所属", esc(asn.org || "未知"));
    html += row("路由前缀", esc(asn.route || "未知"));
    html += row("ASN 国家", esc(asn.country || "未知"));
    html += "</div>";

    if (dc.datacenter) {
      html += '<div class="sec-title" style="color:#b45309">☁️ 数据中心</div><div class="panel-bg detail-grid">';
      html += row("名称", esc(dc.datacenter));
      html += row("服务商", esc(dc.service || "未知"));
      html += row("区域", esc(dc.scope || "未知"));
      html += row("网段", esc(dc.network || "未知"));
      html += "</div>";
    }

    if (abuse.email) {
      html += '<div class="sec-title" style="color:#dc2626">⚠️ 滥用举报</div><div class="panel-bg detail-grid">';
      html += row("姓名", esc(abuse.name || "未知"));
      html += row("邮箱", esc(abuse.email));
      html += row("电话", esc(abuse.phone || "未知"));
      html += row("地址", esc(abuse.address || "未知"));
      html += "</div>";
    }

    html += '<div class="sec-title" style="color:#7c3aed">🛡️ 安全检测</div><div class="panel-bg detail-grid">';
    html += row("数据中心", data.is_datacenter ? "🏢 是" : "✅ 否");
    html += row("代理", data.is_proxy ? "⚠️ 是" : "✅ 否");
    html += row("VPN", data.is_vpn ? "⚠️ 是" : "✅ 否");
    html += row("Tor", data.is_tor ? "⚠️ 是" : "✅ 否");
    html += row("爬虫", data.is_crawler ? "⚠️ 是" : "✅ 否");
    html += row("移动网络", data.is_mobile ? "📱 是" : "✅ 否");
    html += row("卫星网络", data.is_satellite ? "🛰️ 是" : "✅ 否");
    html += row("已知滥用", data.is_abuser ? '<span style="color:#dc2626">⚠️ 是</span>' : "✅ 否");
    html += "</div>";

    if (lat && lon && window.L) {
      html += '<div class="sec-title" style="color:#2563eb">🗺️ 地理位置</div>';
      html += '<div id="adminIpMap" class="map-container"></div>';
    }

    body.innerHTML = html;

    if (lat && lon && window.L) {
      setTimeout(function () {
        var el = document.getElementById("adminIpMap");
        if (!el) return;
        var map = L.map(el, { scrollWheelZoom: false }).setView([lat, lon], 8);
        L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 19 }).addTo(map);
        L.marker([lat, lon]).addTo(map)
          .bindPopup(esc(ip) + "<br>" + esc([city, country].filter(Boolean).join(", ")));
      }, 60);
    }
  }

  document.querySelectorAll(".admin-ip-detail").forEach(function (btn) {
    btn.addEventListener("click", function () {
      var ip = this.dataset.ip;
      if (!ip || ip === "Unknown") return alert("无效的 IP 地址");
      showIPDetail(ip, {
        country: this.dataset.country,
        region: this.dataset.region,
        city: this.dataset.city,
        lat: this.dataset.lat,
        lon: this.dataset.lon,
        timezone: this.dataset.timezone,
        isp: this.dataset.isp,
        org: this.dataset.org,
        as: this.dataset.as,
        countryCode: this.dataset.countrycode
      });
    });
  });

  document.getElementById("ipModal").addEventListener("click", function (e) {
    if (e.target === this) this.classList.remove("active");
  });
})();
<\/script>
</body>
</html>`;

  return htmlResponse(html);
}