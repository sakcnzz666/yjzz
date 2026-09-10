// @ts-nocheck
// Cloudflare Worker 邮件/链接追踪器
// 绑定 D1 数据库 "DB"，环境变量 ADMIN（管理员密码），可选 IPAPI_KEY

const IMAGE_HOST = "https://tc.ilqx.dpdns.org";
const IMAGE_UPLOAD_PATH = "/upload";
const MAX_UPLOAD = 5 * 1024 * 1024;
const ALLOWED_IMAGE = ["image/jpeg", "image/jpg", "image/png", "image/gif", "image/webp", "image/bmp"];
const ALLOWED_VIDEO = ["video/mp4", "video/webm", "video/ogg", "video/quicktime"];
const PIXEL_B64 = "R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";
const DEFAULT_IPAPI_KEY = "91d0c00fdc50af8b1e84";

function getIpapiKey(env) {
  return (env && env.IPAPI_KEY && String(env.IPAPI_KEY).trim()) || DEFAULT_IPAPI_KEY;
}

/* =========================================================
 *  关键修复 1：多 header 兜底取客户端 IP
 *  Cloudflare 的 CF-Connecting-IP 在绝大多数情况下都有值，
 *  但如果 Worker 前面还有反代 / 内网访问 / 预览地址，可能为空，
 *  这时兜底到 X-Forwarded-For / X-Real-IP / True-Client-IP。
 * =======================================================*/
function getClientIp(request) {
  const h = request.headers;
  const direct = h.get("CF-Connecting-IP") || h.get("True-Client-IP") || h.get("X-Real-IP");
  if (direct && direct.trim()) return direct.trim();
  const xff = h.get("X-Forwarded-For");
  if (xff) {
    const first = xff.split(",")[0].trim();
    if (first) return first;
  }
  return "Unknown";
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (!env || !env.ADMIN || !String(env.ADMIN).trim()) return setupNotice();
    if (!env.DB) return new Response("未绑定 D1 数据库（变量名应为 DB）", { status: 500 });

    try { await initDB(env); } catch (e) {
      return new Response("数据库初始化失败：" + (e && e.message ? e.message : e), { status: 500 });
    }

    if (path === "/" || path === "/index.html") return renderHome(env);
    if (path.startsWith("/pixel/")) {
      const id = path.split("/")[2];
      if (!id) return notFound();
      return handlePixel(request, env, ctx, decodeURIComponent(id));
    }
    if (path === "/api/generate") return handleGenerate(request, env);
    if (path === "/api/query") return handleQuery(request, env);
    if (path === "/api/stats") return handleStats(request, env);
    if (path === "/api/ip") return handleIpLookup(request, env);
    if (path === "/api/admin/login") return handleAdminLogin(request, env);
    if (path === "/api/admin/logout") return handleAdminLogout(request, env);
    if (path === "/api/admin/delete") return handleAdminDelete(request, env);
    if (path === "/api/admin/clear") return handleAdminClear(request, env);
    if (path === "/api/admin/delete-target") return handleAdminDeleteTarget(request, env);
    if (path === "/api/admin/delete-targets") return handleAdminDeleteTargets(request, env);
    if (path === "/api/admin/clear-targets") return handleAdminClearTargets(request, env);
    if (path === "/admin") return renderAdmin(request, env);
    if (/^\/tile\/\d+\/\d+\/\d+\.png$/.test(path)) return handleTile(request);
    return notFound();
  }
};

/* =========================================================
 *  基础工具
 * =======================================================*/
function notFound() { return new Response("Not Found", { status: 404 }); }

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", ...extraHeaders }
  });
}

function randomHex(bytes = 32) {
  const arr = new Uint8Array(bytes);
  crypto.getRandomValues(arr);
  return Array.from(arr, b => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(request, name) {
  const raw = request.headers.get("Cookie") || "";
  for (const part of raw.split(";")) {
    const idx = part.indexOf("=");
    if (idx < 0) continue;
    if (part.slice(0, idx).trim() === name) return part.slice(idx + 1).trim();
  }
  return null;
}

function transparentPixel() {
  const buf = Uint8Array.from(atob(PIXEL_B64), c => c.charCodeAt(0));
  return new Response(buf, {
    headers: {
      "Content-Type": "image/gif",
      "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
      "Pragma": "no-cache",
      "Expires": "0",
      "Cross-Origin-Resource-Policy": "cross-origin"
    }
  });
}

async function hashPassword(password, salt) {
  const enc = new TextEncoder();
  const km = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: 100000, hash: "SHA-256" },
    km, 256
  );
  return Array.from(new Uint8Array(bits), b => b.toString(16).padStart(2, "0")).join("");
}

function matchMagic(bytes, sig, offset = 0) {
  if (bytes.length < offset + sig.length) return false;
  for (let i = 0; i < sig.length; i++) if (bytes[offset + i] !== sig[i]) return false;
  return true;
}
function validateFileBytes(mime, bytes) {
  mime = (mime || "").toLowerCase();
  if (mime === "image/jpg") mime = "image/jpeg";
  switch (mime) {
    case "image/jpeg": return matchMagic(bytes, [0xff, 0xd8, 0xff]);
    case "image/png": return matchMagic(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
    case "image/gif": return matchMagic(bytes, [0x47, 0x49, 0x46, 0x38]);
    case "image/bmp": return matchMagic(bytes, [0x42, 0x4d]);
    case "image/webp":
      return bytes.length >= 12 &&
        matchMagic(bytes, [0x52, 0x49, 0x46, 0x46], 0) &&
        matchMagic(bytes, [0x57, 0x45, 0x42, 0x50], 8);
    case "video/mp4":
    case "video/quicktime":
      return bytes.length >= 12 && matchMagic(bytes, [0x66, 0x74, 0x79, 0x70], 4);
    case "video/webm": return matchMagic(bytes, [0x1a, 0x45, 0xdf, 0xa3]);
    case "video/ogg": return matchMagic(bytes, [0x4f, 0x67, 0x67, 0x53]);
    default: return false;
  }
}

async function uploadToHost(blob, filename) {
  const fd = new FormData();
  fd.append("file", blob, filename);
  const resp = await fetch(IMAGE_HOST + IMAGE_UPLOAD_PATH, { method: "POST", body: fd });
  if (!resp.ok) throw new Error(`图床返回 HTTP ${resp.status}`);
  let result;
  try { result = await resp.json(); } catch { throw new Error("图床返回内容无法解析"); }
  if (Array.isArray(result) && result[0] && result[0].src) return IMAGE_HOST + result[0].src;
  if (result && result.data && result.data.url) return result.data.url;
  if (result && result.url) return result.url;
  throw new Error("图床返回格式异常");
}

/* =========================================================
 *  数据库
 * =======================================================*/
let initPromise = null;
function initDB(env) {
  if (!initPromise) {
    initPromise = doInitDB(env).catch(err => { initPromise = null; throw err; });
  }
  return initPromise;
}

async function doInitDB(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS targets (
      id TEXT PRIMARY KEY, pass_hash TEXT, pass_salt TEXT,
      image_type TEXT DEFAULT 'default', image_url TEXT,
      creator_ip TEXT, creator_ua TEXT, creator_webrtc_ips TEXT, creator_fingerprint TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS tracking_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT, target_id TEXT NOT NULL,
      event_type TEXT NOT NULL DEFAULT 'open', ip TEXT,
      country TEXT, country_code TEXT, region TEXT, city TEXT, timezone TEXT,
      isp TEXT, org TEXT, as_text TEXT, lat REAL, lon REAL,
      ua TEXT, languages TEXT, referer TEXT, accept TEXT, accept_encoding TEXT,
      sec_ch_ua TEXT, sec_ch_ua_platform TEXT, sec_ch_ua_mobile TEXT,
      opened_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();

  const targetCols = ["pass_hash","pass_salt","image_type","image_url","creator_ip","creator_ua","creator_webrtc_ips","creator_fingerprint"];
  for (const col of targetCols) { try { await env.DB.prepare(`ALTER TABLE targets ADD COLUMN ${col} TEXT`).run(); } catch (e) {} }

  const logCols = ["country_code","region","city","timezone","isp","org","as_text","referer","accept","accept_encoding","sec_ch_ua","sec_ch_ua_platform","sec_ch_ua_mobile"];
  for (const col of logCols) { try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN ${col} TEXT`).run(); } catch (e) {} }
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lat REAL`).run(); } catch (e) {}
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lon REAL`).run(); } catch (e) {}
}

/* =========================================================
 *  追踪像素
 * =======================================================*/
async function handlePixel(request, env, ctx, targetId) {
  const target = await env.DB.prepare("SELECT image_type, image_url FROM targets WHERE id = ?").bind(targetId).first();
  if (!target) return transparentPixel();

  const cf = request.cf || {};
  const ip = getClientIp(request);  // ← 关键：多 header 兜底
  const ua = request.headers.get("User-Agent") || "";
  const lat = cf.latitude ? parseFloat(cf.latitude) : null;
  const lon = cf.longitude ? parseFloat(cf.longitude) : null;

  try {
    await env.DB.prepare(`
      INSERT INTO tracking_logs (
        target_id, event_type, ip, country, country_code, region, city, timezone,
        isp, org, as_text, lat, lon, ua, languages, referer, accept, accept_encoding,
        sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile
      ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      targetId, ip,
      cf.country || "", cf.country || "", cf.region || "", cf.city || "", cf.timezone || "",
      cf.asOrganization || "", cf.asOrganization || "", cf.asn ? ("AS" + cf.asn) : "",
      Number.isFinite(lat) ? lat : null, Number.isFinite(lon) ? lon : null,
      ua,
      request.headers.get("Accept-Language") || "",
      request.headers.get("Referer") || "",
      request.headers.get("Accept") || "",
      request.headers.get("Accept-Encoding") || "",
      request.headers.get("Sec-Ch-Ua") || "",
      request.headers.get("Sec-Ch-Ua-Platform") || "",
      request.headers.get("Sec-Ch-Ua-Mobile") || ""
    ).run();
  } catch (e) {}

  const type = target.image_type || "default";
  const mediaUrl = target.image_url || "";
  if (type === "default" || !mediaUrl) return transparentPixel();

  try {
    const upstream = await fetch(mediaUrl, { cf: { cacheTtl: 0 } });
    if (!upstream.ok) return transparentPixel();
    const headers = new Headers();
    const ct = upstream.headers.get("Content-Type");
    headers.set("Content-Type", ct || (type === "video" ? "video/mp4" : "image/jpeg"));
    headers.set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
    headers.set("Pragma", "no-cache");
    headers.set("Expires", "0");
    headers.set("Cross-Origin-Resource-Policy", "cross-origin");
    if (upstream.headers.get("Content-Length")) headers.set("Content-Length", upstream.headers.get("Content-Length"));
    return new Response(upstream.body, { headers });
  } catch (e) { return transparentPixel(); }
}

/* =========================================================
 *  生成
 * =======================================================*/
async function handleGenerate(request, env) {
  if (request.method !== "POST") return jsonResponse({ error: "请求方式错误" }, 405);
  let formData;
  try { formData = await request.formData(); } catch { return jsonResponse({ error: "表单格式错误" }, 400); }

  const customId = String(formData.get("customId") || "").trim();
  const password = String(formData.get("password") || "");
  const mediaType = String(formData.get("mediaType") || "default");
  const imageUrl = String(formData.get("imageUrl") || "").trim();
  const file = formData.get("file");
  const webrtcIps = String(formData.get("webrtcIps") || "[]");
  const fingerprint = String(formData.get("fingerprint") || "");
  const creatorIp = getClientIp(request);  // ← 关键：多 header 兜底
  const creatorUa = request.headers.get("User-Agent") || "";

  if (!/^[A-Za-z0-9_-]{4,32}$/.test(customId)) return jsonResponse({ error: "追踪 ID 需为 4–32 位字母、数字、下划线或短横线" }, 400);
  if (password.length < 4 || password.length > 64) return jsonResponse({ error: "访问密码长度需为 4–64 位" }, 400);

  const existing = await env.DB.prepare("SELECT id FROM targets WHERE id = ?").bind(customId).first();
  if (existing) return jsonResponse({ error: "该追踪 ID 已被占用，请更换" }, 400);

  let finalType = "default", finalUrl = "";

  if (mediaType === "default") {
    finalType = "default";
  } else if (mediaType === "image-url" || mediaType === "video-url") {
    if (!/^https?:\/\/.+/i.test(imageUrl)) return jsonResponse({ error: "请填写有效的 http(s) 链接" }, 400);
    if (imageUrl.length > 2048) return jsonResponse({ error: "链接过长" }, 400);
    finalType = mediaType === "image-url" ? "image" : "video";
    finalUrl = imageUrl;
  } else if (mediaType === "image-upload" || mediaType === "video-upload") {
    if (!file || typeof file === "string" || typeof file.size !== "number") return jsonResponse({ error: "请选择要上传的文件" }, 400);
    if (file.size === 0) return jsonResponse({ error: "文件为空" }, 400);
    if (file.size > MAX_UPLOAD) return jsonResponse({ error: "文件超过 5MB 限制" }, 400);
    let mime = (file.type || "").toLowerCase();
    if (mime === "image/jpg") mime = "image/jpeg";
    const isVideo = mediaType === "video-upload";
    const allowList = isVideo ? ALLOWED_VIDEO : ALLOWED_IMAGE;
    if (!allowList.includes(mime)) {
      return jsonResponse({ error: isVideo ? "仅支持 MP4/WebM/OGG/MOV" : "仅支持 JPG/PNG/GIF/WebP/BMP" }, 400);
    }
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (!validateFileBytes(mime, bytes)) return jsonResponse({ error: "文件内容与声明的格式不符" }, 400);
    const fallbackName = (file.name && /^[\w\-. ]+$/.test(file.name)) ? file.name : (isVideo ? "video.mp4" : "image.jpg");
    try {
      finalUrl = await uploadToHost(new Blob([bytes], { type: mime }), fallbackName);
      finalType = isVideo ? "video" : "image";
    } catch (e) { return jsonResponse({ error: "上传失败：" + (e && e.message ? e.message : e) }, 502); }
  } else {
    return jsonResponse({ error: "未知的媒体类型" }, 400);
  }

  const salt = randomHex(16);
  const passHash = await hashPassword(password, salt);

  const origin = new URL(request.url).origin;
  let snippet;
  if (finalType === "default") snippet = `<img src="${origin}/pixel/${customId}" width="1" height="1" alt="" style="display:none!important;border:0;outline:none;" />`;
  else if (finalType === "image") snippet = `<img src="${origin}/pixel/${customId}" alt="" style="max-width:100%;height:auto;border-radius:10px;" />`;
  else snippet = `<video src="${origin}/pixel/${customId}" controls playsinline preload="metadata" style="max-width:100%;border-radius:10px;"></video>`;

  await env.DB.prepare(`
    INSERT INTO targets (id, pass_hash, pass_salt, image_type, image_url,
      creator_ip, creator_ua, creator_webrtc_ips, creator_fingerprint)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(customId, passHash, salt, finalType, finalUrl, creatorIp, creatorUa, webrtcIps, fingerprint).run();

  return jsonResponse({ id: customId, mediaType: finalType, trackingHtml: snippet });
}

/* =========================================================
 *  查询 / 统计
 * =======================================================*/
async function verifyTargetPassword(env, id, password) {
  if (!id || !password) return { ok: false, code: 400, error: "缺少参数" };
  const target = await env.DB.prepare("SELECT * FROM targets WHERE id = ?").bind(id).first();
  if (!target) return { ok: false, code: 404, error: "追踪 ID 不存在" };
  if (!target.pass_hash || !target.pass_salt) return { ok: false, code: 403, error: "该记录无访问密码" };
  const hash = await hashPassword(password, target.pass_salt);
  if (hash !== target.pass_hash) return { ok: false, code: 401, error: "访问密码错误" };
  return { ok: true, target };
}

async function handleQuery(request, env) {
  const u = new URL(request.url);
  const id = (u.searchParams.get("id") || "").trim();
  const password = u.searchParams.get("password") || "";
  const burn = u.searchParams.get("burn") === "true";

  const check = await verifyTargetPassword(env, id, password);
  if (!check.ok) return jsonResponse({ error: check.error }, check.code);

  const target = check.target;

  // 把 creator_ip / webrtc_ips 全部加入集合（含 Unknown）用于本地标记
  const creatorIpSet = new Set();
  if (target.creator_ip) creatorIpSet.add(String(target.creator_ip).trim());
  if (target.creator_webrtc_ips) {
    try {
      const arr = JSON.parse(target.creator_webrtc_ips);
      if (Array.isArray(arr)) arr.forEach(ip => { if (ip) creatorIpSet.add(String(ip).trim()); });
    } catch (e) {}
  }

  const logs = await env.DB.prepare(`
    SELECT id, target_id, event_type, ip, country, country_code, region, city, timezone,
           isp, org, as_text, lat, lon, ua, languages, referer, accept, accept_encoding,
           sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile, opened_at
    FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 500
  `).bind(id).all();

  const results = logs.results.map(log => ({
    ...log,
    is_local: creatorIpSet.has(String(log.ip || "").trim())
  }));

  if (burn && results.length > 0) {
    await env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(id).run();
  }

  return jsonResponse({
    id,
    mediaType: target.image_type || "default",
    mediaUrl: target.image_url || "",
    createdAt: target.created_at || null,
    logs: results
  });
}

async function handleStats(request, env) {
  const u = new URL(request.url);
  const id = (u.searchParams.get("id") || "").trim();
  const password = u.searchParams.get("password") || "";
  const check = await verifyTargetPassword(env, id, password);
  if (!check.ok) return jsonResponse({ error: check.error }, check.code);

  const total = await env.DB.prepare("SELECT COUNT(*) AS c FROM tracking_logs WHERE target_id = ?").bind(id).first();
  const uniqueIp = await env.DB.prepare("SELECT COUNT(DISTINCT ip) AS c FROM tracking_logs WHERE target_id = ?").bind(id).first();
  const latest = await env.DB.prepare("SELECT opened_at FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 1").bind(id).first();

  return jsonResponse({
    total: total ? total.c : 0,
    uniqueIps: uniqueIp ? uniqueIp.c : 0,
    latestOpen: latest ? latest.opened_at : null
  });
}

/* =========================================================
 *  IP 详情（服务端代理，前端只需调 /api/ip?ip=）
 * =======================================================*/
async function handleIpLookup(request, env) {
  const u = new URL(request.url);
  const ip = (u.searchParams.get("ip") || "").trim();
  if (!ip) return jsonResponse({ error: "缺少 IP 参数" }, 400);
  if (ip.length > 64) return jsonResponse({ error: "IP 参数异常" }, 400);
  if (!ip || ip.toLowerCase() === "unknown" || ip === "127.0.0.1" || ip === "::1") {
    return jsonResponse({ error: "该 IP 无法查询（Unknown 或本地地址）" }, 200);
  }

  const key = getIpapiKey(env);
  try {
    const resp = await fetch(`https://api.ipapi.is/?q=${encodeURIComponent(ip)}&key=${encodeURIComponent(key)}`, {
      cf: { cacheTtl: 300 }
    });
    if (!resp.ok) {
      if (resp.status === 404) return jsonResponse({ error: "上游未收录该 IP" }, 200);
      return jsonResponse({ error: `上游返回 HTTP ${resp.status}` }, 200);
    }
    return jsonResponse(await resp.json());
  } catch (e) {
    return jsonResponse({ error: "查询异常：" + (e && e.message ? e.message : e) }, 200);
  }
}

/* =========================================================
 *  关键修复 2：登录改为「无状态」
 *  - 不再使用 admin_sessions 表
 *  - cookie 里存的是 env.ADMIN 的 PBKDF2 hash
 *  - 两端 trim()，避免环境变量带空白
 * =======================================================*/
async function adminToken(env) {
  return await hashPassword(String(env.ADMIN || "").trim(), "sak-admin-static-v1");
}

async function isAdmin(request, env) {
  const token = getCookie(request, "admin_token");
  if (!token || !/^[a-f0-9]{64}$/.test(token)) return false;
  const expected = await adminToken(env);
  return token === expected;
}

async function handleAdminLogin(request, env) {
  if (request.method !== "POST") return jsonResponse({ error: "请求方式错误" }, 405);
  let body;
  try { body = await request.json(); } catch { return jsonResponse({ error: "请求体格式错误" }, 400); }

  const password = String(body.password || "").trim();
  const expected = String(env.ADMIN || "").trim();
  if (!password) return jsonResponse({ error: "请输入密码" }, 400);
  if (password !== expected) {
    await new Promise(r => setTimeout(r, 400));
    return jsonResponse({ error: "密码错误" }, 401);
  }

  const token = await adminToken(env);
  return jsonResponse({ success: true }, 200, {
    "Set-Cookie": `admin_token=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400`
  });
}

async function handleAdminLogout(request, env) {
  if (request.method !== "POST") return jsonResponse({ error: "请求方式错误" }, 405);
  return jsonResponse({ success: true }, 200, {
    "Set-Cookie": "admin_token=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
  });
}

/* =========================================================
 *  后台操作
 * =======================================================*/
async function requireAdmin(request, env) {
  if (!await isAdmin(request, env)) return jsonResponse({ error: "未登录或登录已失效" }, 401);
  return null;
}

async function handleAdminDelete(request, env) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  let body; try { body = await request.json(); } catch { return jsonResponse({ error: "请求体错误" }, 400); }
  const id = parseInt(body.id, 10);
  if (!Number.isFinite(id)) return jsonResponse({ error: "无效 ID" }, 400);
  await env.DB.prepare("DELETE FROM tracking_logs WHERE id = ?").bind(id).run();
  return jsonResponse({ success: true });
}

async function handleAdminClear(request, env) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  await env.DB.prepare("DELETE FROM tracking_logs").run();
  return jsonResponse({ success: true });
}

async function handleAdminDeleteTarget(request, env) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  let body; try { body = await request.json(); } catch { return jsonResponse({ error: "请求体错误" }, 400); }
  const id = String(body.id || "");
  if (!id) return jsonResponse({ error: "无效 ID" }, 400);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(id),
    env.DB.prepare("DELETE FROM targets WHERE id = ?").bind(id)
  ]);
  return jsonResponse({ success: true });
}

async function handleAdminDeleteTargets(request, env) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  let body; try { body = await request.json(); } catch { return jsonResponse({ error: "请求体错误" }, 400); }
  const ids = body.ids;
  if (!Array.isArray(ids) || ids.length === 0) return jsonResponse({ error: "未选择任何 ID" }, 400);
  if (ids.length > 200) return jsonResponse({ error: "单次最多删除 200 条" }, 400);
  const stmts = [];
  for (const id of ids) {
    stmts.push(env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(String(id)));
    stmts.push(env.DB.prepare("DELETE FROM targets WHERE id = ?").bind(String(id)));
  }
  await env.DB.batch(stmts);
  return jsonResponse({ success: true, deleted: ids.length });
}

async function handleAdminClearTargets(request, env) {
  const denied = await requireAdmin(request, env);
  if (denied) return denied;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM tracking_logs"),
    env.DB.prepare("DELETE FROM targets")
  ]);
  return jsonResponse({ success: true });
}

/* =========================================================
 *  瓦片反代
 * =======================================================*/
async function handleTile(request) {
  const url = new URL(request.url);
  const parts = url.pathname.split("/");
  const z = parts[2], x = parts[3], y = parts[4].split(".")[0];
  if (!/^\d+$/.test(z) || !/^\d+$/.test(x) || !/^\d+$/.test(y)) return new Response("Bad tile", { status: 400 });

  const upstream = await fetch(`https://a.tile.openstreetmap.org/${z}/${x}/${y}.png`, {
    headers: { "Referer": url.origin, "User-Agent": "Mozilla/5.0 (compatible; TrackerTileProxy/1.0)" },
    cf: { cacheTtl: 86400, cacheEverything: true }
  });
  const headers = new Headers();
  headers.set("Content-Type", upstream.headers.get("Content-Type") || "image/png");
  headers.set("Access-Control-Allow-Origin", "*");
  headers.set("Cache-Control", "public, max-age=86400");
  return new Response(upstream.body, { status: upstream.status, headers });
}

/* =========================================================
 *  配置缺失提示
 * =======================================================*/
function setupNotice() {
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>配置未完成</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;background:#0b1120;color:#e2e8f0}
.box{max-width:560px;width:100%;background:#111a2e;border:1px solid #1e293b;border-radius:18px;padding:32px}
h1{margin:0 0 10px;font-size:20px;color:#f1f5f9}p{margin:10px 0;font-size:14px;line-height:1.8;color:#94a3b8}
code{background:#0b1120;border:1px solid #1e293b;padding:2px 7px;border-radius:6px;color:#7dd3fc;font-size:13px}
ul{margin:10px 0 0;padding-left:20px;color:#94a3b8;font-size:14px;line-height:1.9}</style></head>
<body><div class="box"><h1>服务尚未配置完成</h1>
<p>请在 Cloudflare 后台设置环境变量：</p>
<ul><li><code>ADMIN</code>（必须）— 后台登录密码</li><li><code>IPAPI_KEY</code>（可选）— ipapi.is 的 Key</li><li>D1 绑定变量名需为 <code>DB</code></li></ul>
</div></body></html>`;
  return new Response(html, { status: 503, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/* =========================================================
 *  首页（沿用你原来简版的 glass / timeline 风格）
 * =======================================================*/
function renderHome(env) {
  const html = `<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>邮件追踪器</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<script src="https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"><\/script>
<style>
  body { background: linear-gradient(135deg, #f6f8fd 0%, #f1f5f9 100%); font-family: system-ui, -apple-system, sans-serif; }
  .glass { background: rgba(255,255,255,0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255,255,255,0.5); }
  .timeline { border-left: 2px solid #e5e7eb; padding-left: 1rem; margin-left: 1rem; }
  .timeline-item { position: relative; padding: 0.5rem 0; }
  .timeline-item::before { content: ''; position: absolute; left: -1.35rem; top: 0.8rem; width: 0.75rem; height: 0.75rem; background: #6366f1; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 0 2px #6366f1; }
  .modal { display:none; position:fixed; inset:0; background:rgba(0,0,0,0.5); align-items:center; justify-content:center; z-index:100; }
  .modal.active { display:flex; }
  .modal-content { background:white; border-radius:1.5rem; padding:1.5rem; max-width:42rem; width:92%; max-height:85vh; overflow-y:auto; }
  .map-container { height: 280px; width: 100%; border-radius: 0.75rem; margin-top: 0.5rem; border: 1px solid #e5e7eb; }
  .local-badge { background:#fbbf24; color:#78350f; padding:0.1rem 0.5rem; border-radius:9999px; font-size:0.65rem; font-weight:600; margin-left:0.5rem; }
  .flag-icon { width:22px; height:16px; border-radius:2px; box-shadow:0 1px 2px rgba(0,0,0,0.2); margin-left:4px; vertical-align:middle; }
  .detail-grid { display:grid; grid-template-columns: 1fr 1fr; gap:4px 8px; }
  .detail-item { display:flex; justify-content:space-between; padding:2px 0; border-bottom:1px solid #f3f4f6; }
  .detail-label { color:#6b7280; font-weight:500; }
  .detail-value { font-weight:500; word-break:break-word; text-align:right; }
  .ip-word-break { word-break: break-all; }
  .opt { display:flex; align-items:center; gap:8px; font-size:13.5px; color:#334155; padding:9px 13px; border:1px solid #e6ebf3; border-radius:11px; cursor:pointer; transition:.15s; background:#fbfcfe; }
  .opt:hover { border-color:#c7d2fe; background:#f8faff; }
  .opt input { accent-color:#4f46e5; margin:0; }
  .opt.on { border-color:#a5b4fc; background:#eef2ff; }
  .fld { width:100%; border:1px solid #dfe5f0; border-radius:12px; padding:10px 13px; font-size:14px; outline:none; background:#fbfcfe; transition:.18s; }
  .fld:focus { border-color:#6366f1; background:#fff; box-shadow:0 0 0 3px rgba(99,102,241,.12); }
  .tabbar { display:inline-flex; background:#eef2f8; border-radius:12px; padding:3px; gap:3px; }
  .tabbar button { border:none; background:transparent; font-size:13.5px; font-weight:600; color:#64748b; padding:7px 18px; border-radius:9px; cursor:pointer; }
  .tabbar button.on { background:#fff; color:#4338ca; box-shadow:0 1px 5px rgba(15,23,42,.1); }
</style>
</head>
<body class="min-h-screen p-4">
<div class="max-w-6xl mx-auto space-y-6 pt-8">

  <!-- 生成卡片 -->
  <div class="glass rounded-2xl p-6 shadow-sm">
    <h1 class="text-2xl font-bold mb-4 flex items-center"><i class="fa-solid fa-envelope-open-text text-indigo-600 mr-2"></i>邮件追踪器</h1>
    <p class="text-sm text-gray-500 mb-6">生成追踪图片代码，粘贴到邮件 HTML 源码中。对方打开后即可记录详细访问信息，并自动标记「本地查看」。每个追踪 ID 对应独立访问密码，只有你知道。</p>

    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
      <div>
        <label class="text-sm font-medium">追踪 ID（4–32 位字母/数字/_/-）</label>
        <input id="customId" class="fld mt-1" placeholder="例如：mail-2026" autocomplete="off">
      </div>
      <div>
        <label class="text-sm font-medium">访问密码（4–64 位）</label>
        <div class="relative">
          <input id="password" type="password" class="fld mt-1 pr-10" placeholder="设置一个只有你知道的密码">
          <button type="button" id="pwdEye" class="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 px-2">
            <i class="fa-regular fa-eye"></i>
          </button>
        </div>
      </div>
    </div>

    <div class="mb-4">
      <label class="text-sm font-medium block mb-2">追踪媒体类型</label>
      <div class="tabbar" id="kindTabs">
        <button type="button" data-kind="image" class="on"><i class="fa-regular fa-image mr-1"></i>图片</button>
        <button type="button" data-kind="video"><i class="fa-solid fa-video mr-1"></i>视频</button>
      </div>
    </div>

    <div id="imageOpts" class="space-y-2">
      <label class="opt on"><input type="radio" name="imageMode" value="default" checked> 默认 1×1 像素（隐藏，最不易被察觉）</label>
      <label class="opt"><input type="radio" name="imageMode" value="url"> 自定义图片 URL</label>
      <label class="opt"><input type="radio" name="imageMode" value="upload"> 上传图片（推荐）</label>
    </div>
    <div id="videoOpts" class="space-y-2 hidden">
      <label class="opt on"><input type="radio" name="videoMode" value="upload" checked> 上传视频（推荐）</label>
      <label class="opt"><input type="radio" name="videoMode" value="url"> 自定义视频 URL</label>
    </div>

    <div id="urlBox" class="mt-3 hidden"><input id="mediaUrl" class="fld" placeholder="https://…"></div>
    <div id="fileBox" class="mt-3 hidden">
      <input id="mediaFile" type="file" class="fld py-2.5">
      <p id="fileHint" class="text-xs text-gray-400 mt-1.5"></p>
    </div>

    <button id="genBtn" class="mt-6 bg-indigo-600 text-white font-medium py-2.5 px-6 rounded-xl hover:bg-indigo-700 transition-colors">生成追踪代码</button>

    <div id="result" class="mt-4 hidden">
      <p class="text-sm font-medium">将以下代码粘贴到邮件的 HTML 源码中：</p>
      <textarea id="codeOut" class="w-full h-20 p-2 border rounded-xl font-mono text-xs resize-none mt-1" readonly></textarea>
      <p class="text-xs mt-1 text-gray-400">追踪 ID：<span id="trackId" class="font-bold text-indigo-600"></span></p>
      <button id="copyBtn" class="mt-2 bg-gray-200 hover:bg-gray-300 px-3 py-1 rounded-xl text-sm">复制代码</button>
    </div>
  </div>

  <!-- 查询卡片 -->
  <div class="glass rounded-2xl p-6 shadow-sm">
    <h2 class="text-xl font-bold mb-4 flex items-center"><i class="fa-solid fa-magnifying-glass text-emerald-600 mr-2"></i>查询记录</h2>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
      <input id="qId" placeholder="输入追踪 ID" class="fld">
      <input id="qPwd" type="password" placeholder="输入访问密码" class="fld">
    </div>
    <div class="flex flex-wrap gap-2 mb-4">
      <button id="qBtn" class="bg-emerald-600 text-white font-medium py-2.5 px-6 rounded-xl hover:bg-emerald-700">查询</button>
      <button id="sBtn" class="bg-blue-600 text-white font-medium py-2.5 px-6 rounded-xl hover:bg-blue-700">统计</button>
      <button id="burnBtn" class="bg-gray-200 text-gray-700 font-medium py-2.5 px-6 rounded-xl hover:bg-gray-300">查询并清除</button>
    </div>
    <div id="statsResult" class="text-sm text-gray-600 mb-4 hidden"></div>
    <div id="qResult" class="space-y-4 text-sm"></div>
  </div>

  <div class="text-center text-xs text-gray-400 space-y-1">
    <div><a href="/admin" class="underline">后台管理</a></div>
    <div>Copyright © 2026 SAK All rights reserved.</div>
    <div>QQ:3344310554 · E-mail:cnzz666@163.com · Bilibili:SAK _CN</div>
  </div>
</div>

<!-- IP 弹窗 -->
<div id="ipModal" class="modal">
  <div class="modal-content">
    <div class="flex justify-between items-center mb-3">
      <h3 class="font-bold text-lg"><i class="fa-solid fa-circle-info text-indigo-500 mr-2"></i>IP 详细信息</h3>
      <button id="ipClose" class="text-gray-400 hover:text-red-500 text-xl leading-none">&times;</button>
    </div>
    <div id="ipBody"></div>
  </div>
</div>

<script>
(function(){
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  function escapeHtml(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }

  // 创建者信息采集
  let creatorWebRTC = [], creatorFingerprint = null;
  (async function collect(){
    try {
      if (window.FingerprintJS) { const fp = await FingerprintJS.load(); creatorFingerprint = await fp.get(); }
    } catch(e){}
    try {
      const ips = new Set();
      const pc = new RTCPeerConnection({ iceServers: [
        { urls: "stun:stun.l.google.com:19302" },
        { urls: "stun:stun.miwifi.com:3478" }
      ]});
      pc.createDataChannel("x");
      pc.onicecandidate = e => {
        if (!e.candidate || !e.candidate.candidate) return;
        const m = e.candidate.candidate.match(/([0-9]{1,3}(\\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i);
        if (m && m[1] && m[1] !== "0.0.0.0" && m[1] !== "127.0.0.1") ips.add(m[1]);
      };
      await new Promise(r => {
        pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === "complete") r(); };
        pc.createOffer().then(o => pc.setLocalDescription(o)).catch(()=>{});
        setTimeout(r, 2200);
      });
      creatorWebRTC = Array.from(ips);
    } catch(e){}
  })();

  // 密码显隐
  $("#pwdEye").addEventListener("click", () => {
    const el = $("#password");
    const isPwd = el.type === "password";
    el.type = isPwd ? "text" : "password";
    $("#pwdEye").innerHTML = isPwd ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
  });

  // 媒体类型切换
  let kind = "image";
  function currentMode(){
    if (kind === "image") {
      const r = document.querySelector('input[name="imageMode"]:checked');
      const v = r ? r.value : "default";
      return v === "default" ? "default" : (v === "url" ? "image-url" : "image-upload");
    }
    const r = document.querySelector('input[name="videoMode"]:checked');
    const v = r ? r.value : "upload";
    return v === "url" ? "video-url" : "video-upload";
  }
  function refreshUI(){
    const mode = currentMode();
    $$("#imageOpts .opt, #videoOpts .opt").forEach(el => {
      const input = el.querySelector("input");
      el.classList.toggle("on", input.checked);
    });
    const needUrl = mode === "image-url" || mode === "video-url";
    const needFile = mode === "image-upload" || mode === "video-upload";
    $("#urlBox").classList.toggle("hidden", !needUrl);
    $("#fileBox").classList.toggle("hidden", !needFile);
    if (needFile) {
      const isVideo = mode === "video-upload";
      $("#mediaFile").setAttribute("accept", isVideo
        ? "video/mp4,video/webm,video/ogg,video/quicktime"
        : "image/jpeg,image/png,image/gif,image/webp,image/bmp");
      $("#fileHint").textContent = isVideo
        ? "支持 MP4/WebM/OGG/MOV，单文件 ≤ 5MB"
        : "支持 JPG/PNG/GIF/WebP/BMP，单文件 ≤ 5MB";
    }
    $("#mediaUrl").placeholder = mode === "video-url" ? "https://…/video.mp4" : "https://…/image.jpg";
  }
  $("#kindTabs").addEventListener("click", e => {
    const btn = e.target.closest("button[data-kind]");
    if (!btn) return;
    kind = btn.dataset.kind;
    $$("#kindTabs button").forEach(b => b.classList.toggle("on", b === btn));
    $("#imageOpts").classList.toggle("hidden", kind !== "image");
    $("#videoOpts").classList.toggle("hidden", kind !== "video");
    $("#mediaFile").value = "";
    refreshUI();
  });
  document.addEventListener("change", e => {
    if (e.target.name === "imageMode" || e.target.name === "videoMode") refreshUI();
  });
  refreshUI();

  // 生成
  $("#genBtn").addEventListener("click", async () => {
    const customId = $("#customId").value.trim();
    const password = $("#password").value;
    const mode = currentMode();
    const file = $("#mediaFile").files[0];

    if (!/^[A-Za-z0-9_-]{4,32}$/.test(customId)) { alert("追踪 ID 需为 4–32 位字母、数字、下划线或短横线"); return; }
    if (password.length < 4 || password.length > 64) { alert("访问密码长度需为 4–64 位"); return; }
    if ((mode === "image-url" || mode === "video-url") && !/^https?:\\/\\/.+/i.test($("#mediaUrl").value.trim())) { alert("请填写有效的 http(s) 链接"); return; }
    if ((mode === "image-upload" || mode === "video-upload")) {
      if (!file) { alert("请选择要上传的文件"); return; }
      if (file.size > 5*1024*1024) { alert("文件超过 5MB"); return; }
    }

    const btn = $("#genBtn");
    btn.disabled = true; btn.textContent = "处理中…";
    try {
      const fd = new FormData();
      fd.append("customId", customId);
      fd.append("password", password);
      fd.append("mediaType", mode);
      fd.append("imageUrl", $("#mediaUrl").value.trim());
      if (file) fd.append("file", file);
      fd.append("webrtcIps", JSON.stringify(creatorWebRTC));
      if (creatorFingerprint) fd.append("fingerprint", JSON.stringify(creatorFingerprint));

      const res = await fetch("/api/generate", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok || data.error) { alert(data.error || "生成失败"); return; }
      $("#codeOut").value = data.trackingHtml;
      $("#trackId").textContent = data.id;
      $("#result").classList.remove("hidden");
    } catch(e) { alert("请求失败：" + e.message); }
    finally { btn.disabled = false; btn.textContent = "生成追踪代码"; }
  });

  $("#copyBtn").addEventListener("click", async () => {
    const ta = $("#codeOut");
    try { await navigator.clipboard.writeText(ta.value); $("#copyBtn").textContent = "已复制"; setTimeout(()=>$("#copyBtn").textContent="复制代码", 1500); }
    catch { ta.select(); document.execCommand("copy"); }
  });

  // 查询
  const mapPool = {};
  function fmtTime(s){
    if (!s) return "";
    const d = new Date(s.replace(" ","T") + "Z");
    if (isNaN(d)) return s;
    return d.toLocaleString("zh-CN", { hour12: false });
  }

  async function doQuery(burn){
    const id = $("#qId").value.trim();
    const pwd = $("#qPwd").value;
    const box = $("#qResult");
    if (!id || !pwd) { box.innerHTML = '<p class="text-red-500">请填写追踪 ID 和访问密码</p>'; return; }
    box.innerHTML = '<p class="text-gray-400"><i class="fa-solid fa-spinner fa-spin"></i> 查询中…</p>';

    try {
      const res = await fetch("/api/query?id=" + encodeURIComponent(id) + "&password=" + encodeURIComponent(pwd) + "&burn=" + (burn ? "true" : "false"));
      const data = await res.json();
      if (!res.ok || data.error) { box.innerHTML = '<p class="text-red-500">' + escapeHtml(data.error || "查询失败") + '</p>'; return; }
      const logs = data.logs || [];
      if (logs.length === 0) { box.innerHTML = '<p class="text-gray-400">暂无访问记录</p>'; return; }

      const groups = new Map();
      for (const log of logs) {
        const ip = log.ip || "Unknown";
        if (!groups.has(ip)) groups.set(ip, []);
        groups.get(ip).push(log);
      }

      let html = "";
      const mapIds = [];
      let idx = 0;
      for (const [ip, items] of groups) {
        const first = items[0];
        const isLocal = items.some(x => x.is_local === true);
        const place = [first.country, first.region, first.city].filter(Boolean).join(", ");
        const cc = (first.country_code || "").toLowerCase();
        const mapId = "m" + (idx++);
        mapIds.push({ id: mapId, lat: first.lat, lon: first.lon, ip, city: first.city, country: first.country });

        html += '<div class="bg-gray-50 border border-gray-200 rounded-xl p-4 mb-3">';
        html += '<div class="flex items-center justify-between mb-3 flex-wrap gap-2">';
        html += '<div class="min-w-0">';
        html += '<span class="font-mono font-bold text-indigo-700 text-lg ip-word-break">' + escapeHtml(ip) + '</span>';
        if (cc) html += ' <img src="https://ipdata.co/flags/' + cc + '.png" class="flag-icon">';
        if (place) html += '<div class="text-xs text-gray-500 mt-1">' + escapeHtml(place) + '</div>';
        html += '</div>';
        html += '<div class="flex items-center gap-2 shrink-0">';
        if (isLocal) html += '<span class="local-badge"><i class="fa-solid fa-house mr-1"></i>本地查看</span>';
        html += '<span class="text-xs text-gray-400">共 ' + items.length + ' 次</span>';
        html += '<button class="ip-detail-btn text-indigo-500 hover:text-indigo-700 text-xs underline" data-ip="' + escapeHtml(ip) + '"><i class="fa-solid fa-magnifying-glass mr-1"></i>详情</button>';
        html += '</div></div>';
        if (first.lat && first.lon) html += '<div id="' + mapId + '" class="map-container"></div>';
        html += '<div class="timeline mt-3">';
        for (const log of items) {
          html += '<div class="timeline-item">';
          html += '<div class="flex flex-wrap items-center gap-2">';
          html += '<span class="text-xs text-gray-400">' + fmtTime(log.opened_at) + '</span>';
          if (log.is_local) html += '<span class="local-badge">本地</span>';
          html += '</div>';
          if (log.ua) html += '<div class="text-xs text-gray-600 break-all mt-1">UA: ' + escapeHtml(log.ua) + '</div>';
          if (log.referer) html += '<div class="text-xs text-gray-400 break-all">Referer: ' + escapeHtml(log.referer) + '</div>';
          html += '</div>';
        }
        html += '</div></div>';
      }
      box.innerHTML = html;

      for (const m of mapIds) {
        if (!m.lat || !m.lon) continue;
        const el = document.getElementById(m.id);
        if (!el) continue;
        try {
          if (mapPool[m.id]) mapPool[m.id].remove();
          const map = L.map(m.id).setView([m.lat, m.lon], 6);
          L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
          L.marker([m.lat, m.lon]).addTo(map).bindPopup(escapeHtml(m.ip) + "<br>" + escapeHtml([m.city, m.country].filter(Boolean).join(", ")));
          mapPool[m.id] = map;
        } catch(e){}
      }
      box.querySelectorAll(".ip-detail-btn").forEach(btn => {
        btn.addEventListener("click", () => openIpDetail(btn.dataset.ip));
      });
    } catch(e) { box.innerHTML = '<p class="text-red-500">查询失败：' + escapeHtml(e.message) + '</p>'; }
  }

  $("#qBtn").addEventListener("click", () => doQuery(false));
  $("#burnBtn").addEventListener("click", () => { if (!confirm("查询后将立即删除该 ID 下的所有记录，确认继续？")) return; doQuery(true); });

  $("#sBtn").addEventListener("click", async () => {
    const id = $("#qId").value.trim();
    const pwd = $("#qPwd").value;
    const box = $("#statsResult");
    if (!id || !pwd) { box.textContent = "请填写追踪 ID 和访问密码"; box.classList.remove("hidden"); return; }
    try {
      const res = await fetch("/api/stats?id=" + encodeURIComponent(id) + "&password=" + encodeURIComponent(pwd));
      const d = await res.json();
      box.classList.remove("hidden");
      if (!res.ok || d.error) { box.innerHTML = '<span class="text-red-500">' + escapeHtml(d.error) + '</span>'; return; }
      box.innerHTML = '📊 总访问 <b class="text-indigo-600">' + d.total + '</b> 次 · 独立 IP <b class="text-emerald-600">' + d.uniqueIps + '</b> 个 · 最近一次 ' + (d.latestOpen ? fmtTime(d.latestOpen) : "无");
    } catch(e) { box.classList.remove("hidden"); box.innerHTML = '<span class="text-red-500">统计失败</span>'; }
  });

  // IP 详情（走服务端代理 /api/ip）
  const ipModal = $("#ipModal");
  const ipBody = $("#ipBody");
  let detailMap = null;
  function closeModal(){ ipModal.classList.remove("active"); if (detailMap) { detailMap.remove(); detailMap = null; } }
  $("#ipClose").addEventListener("click", closeModal);
  ipModal.addEventListener("click", e => { if (e.target === ipModal) closeModal(); });

  function row(label, value, cls) {
    return '<div class="detail-item"><span class="detail-label">' + label + '</span><span class="detail-value ' + (cls||"") + '">' +
      escapeHtml(value == null || value === "" ? "—" : String(value)) + '</span></div>';
  }

  async function openIpDetail(ip){
    ipModal.classList.add("active");
    ipBody.innerHTML = '<div class="text-center py-4 text-gray-400"><i class="fa-solid fa-spinner fa-spin"></i> 加载中…</div>';

    let data = null;
    try {
      const res = await fetch("/api/ip?ip=" + encodeURIComponent(ip));
      data = await res.json().catch(() => null);
    } catch(e) { data = null; }

    if (!data) { ipBody.innerHTML = '<div class="text-red-500 text-center py-4">网络异常</div>'; return; }
    if (data.error) { ipBody.innerHTML = '<div class="text-red-500 text-center py-4">' + escapeHtml(data.error) + '</div>'; return; }

    const loc = data.location || {};
    const comp = data.company || {};
    const asn = data.asn || {};
    const dc = data.datacenter || {};
    const abuse = data.abuse || {};
    const cc = (loc.country_code || "").toLowerCase();
    const lat = loc.latitude, lon = loc.longitude;

    let risk = "—", riskCls = "";
    if (typeof data.risk_score === "number") {
      risk = data.risk_score.toFixed(2) + "%";
      riskCls = data.risk_score > 30 ? "text-red-600 font-bold" : "text-green-600 font-bold";
    } else if (data.is_proxy || data.is_tor || data.is_vpn || data.is_abuser) { risk = "高风险"; riskCls = "text-red-600 font-bold"; }
    else if (data.is_datacenter) { risk = "数据中心"; riskCls = "text-amber-600 font-bold"; }

    let h = "";
    h += '<div class="flex items-center gap-2 border-b pb-2 mb-3"><span class="font-bold text-lg ip-word-break">' + escapeHtml(ip) + '</span>';
    if (cc) h += '<img src="https://ipdata.co/flags/' + cc + '.png" style="width:32px;height:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.2)">';
    h += '</div>';

    h += '<div class="mb-3"><div class="font-semibold text-indigo-700 mb-1">📍 基本信息</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
    h += row("国家", (loc.country||"") + (loc.country_code ? " (" + loc.country_code + ")" : ""));
    h += row("州/省", loc.state || "");
    h += row("城市", loc.city || "");
    h += row("时区", loc.timezone || "");
    h += row("经纬度", (lat && lon) ? (lat + ", " + lon) : "");
    h += row("风控评级", risk, riskCls);
    h += '</div></div>';

    h += '<div class="mb-3"><div class="font-semibold text-emerald-700 mb-1">🏢 运营商 & ASN</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
    h += row("运营商", comp.name || "");
    h += row("类型", comp.type || "");
    h += row("域名", comp.domain || "");
    h += row("ASN", asn.asn || "");
    h += row("ASN 描述", asn.descr || "");
    h += row("ASN 所属", asn.org || "");
    h += row("路由前缀", asn.route || "");
    h += row("ASN 国家", asn.country || "");
    h += '</div></div>';

    if (dc.datacenter) {
      h += '<div class="mb-3"><div class="font-semibold text-amber-700 mb-1">☁️ 数据中心</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
      h += row("名称", dc.datacenter || "");
      h += row("服务商", dc.service || "");
      h += row("区域", dc.scope || "");
      h += row("网络段", dc.network || "");
      h += '</div></div>';
    }

    if (abuse.email) {
      h += '<div class="mb-3"><div class="font-semibold text-red-600 mb-1">⚠️ 滥用举报</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
      h += row("姓名", abuse.name || "");
      h += row("邮箱", abuse.email || "");
      h += row("电话", abuse.phone || "");
      h += row("地址", abuse.address || "");
      h += '</div></div>';
    }

    h += '<div class="mb-3"><div class="font-semibold text-purple-700 mb-1">🛡️ 安全检测</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
    h += row("数据中心", data.is_datacenter ? "是" : "否");
    h += row("代理", data.is_proxy ? "是" : "否");
    h += row("VPN", data.is_vpn ? "是" : "否");
    h += row("Tor", data.is_tor ? "是" : "否");
    h += row("爬虫", data.is_crawler ? "是" : "否");
    h += row("移动网络", data.is_mobile ? "是" : "否");
    h += row("卫星网络", data.is_satellite ? "是" : "否");
    h += row("已知滥用", data.is_abuser ? "是" : "否");
    h += '</div></div>';

    if (lat && lon) {
      h += '<div class="mb-2"><div class="font-semibold text-blue-700 mb-1">🗺️ 地理位置</div>';
      h += '<div id="ipDetailMap" class="map-container"></div></div>';
    }

    ipBody.innerHTML = h;

    if (lat && lon) {
      setTimeout(() => {
        const el = document.getElementById("ipDetailMap");
        if (!el) return;
        try {
          if (detailMap) detailMap.remove();
          detailMap = L.map(el).setView([lat, lon], 8);
          L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(detailMap);
          L.marker([lat, lon]).addTo(detailMap);
        } catch(e){}
      }, 50);
    }
  }
})();
<\/script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

/* =========================================================
 *  后台管理
 * =======================================================*/
function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function loginPage() {
  const html = `<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>后台登录</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<style>
  body{margin:0;min-height:100vh;font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#f6f8fd,#f1f5f9);display:flex;align-items:center;justify-content:center;padding:20px}
  .glass{background:rgba(255,255,255,0.75);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.6);border-radius:22px;box-shadow:0 18px 50px -22px rgba(15,23,42,.28);padding:32px 28px;width:100%;max-width:380px}
  .fld{width:100%;border:1px solid #dfe5f0;border-radius:12px;padding:11px 14px;font-size:14px;outline:none;background:#fbfcfe;transition:.18s}
  .fld:focus{border-color:#6366f1;background:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.12)}
  .btn{width:100%;background:#4f46e5;color:#fff;border:none;border-radius:12px;padding:11px;font-size:14px;font-weight:600;cursor:pointer}
  .btn:hover{background:#4338ca}.btn:disabled{opacity:.6}
  .msg{margin-top:12px;font-size:12.5px;color:#dc2626}
</style></head><body>
<div class="glass">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-11 h-11 rounded-2xl bg-indigo-50 flex items-center justify-center"><i class="fa-solid fa-lock text-indigo-600"></i></div>
    <div><h1 class="text-[17px] font-bold">后台登录</h1><p class="text-xs text-gray-400 mt-0.5">仅限管理员访问</p></div>
  </div>
  <label class="block text-xs font-semibold text-gray-600 mb-1.5">管理员密码</label>
  <input id="pwd" type="password" class="fld" placeholder="请输入密码" autocomplete="current-password">
  <button id="btn" class="btn mt-4">登 录</button>
  <p id="msg" class="msg hidden"></p>
  <div class="mt-6 pt-5 border-t border-gray-100 text-center text-xs text-gray-400">Copyright © 2026 SAK All rights reserved.</div>
</div>
<script>
(function(){
  const pwd = document.getElementById('pwd'), btn = document.getElementById('btn'), msg = document.getElementById('msg');
  function show(t){ msg.textContent = t; msg.classList.remove('hidden'); }
  async function login(){
    const v = pwd.value;
    if (!v) { show('请输入密码'); return; }
    msg.classList.add('hidden'); btn.disabled = true; btn.textContent = '登录中…';
    try {
      const res = await fetch('/api/admin/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ password: v }) });
      const data = await res.json().catch(()=>({}));
      if (res.ok) { location.reload(); return; }
      show(data.error || '登录失败');
    } catch(e) { show('网络异常，请稍后重试'); }
    btn.disabled = false; btn.textContent = '登 录';
  }
  btn.addEventListener('click', login);
  pwd.addEventListener('keydown', e => { if (e.key === 'Enter') login(); });
  pwd.focus();
})();
<\/script>
</body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

async function renderAdmin(request, env) {
  if (!await isAdmin(request, env)) return loginPage();

  const totalTargets = await env.DB.prepare("SELECT COUNT(*) AS c FROM targets").first();
  const totalLogs = await env.DB.prepare("SELECT COUNT(*) AS c FROM tracking_logs").first();
  const uniqueIps = await env.DB.prepare("SELECT COUNT(DISTINCT ip) AS c FROM tracking_logs").first();

  const url = new URL(request.url);
  const filter = (url.searchParams.get("filter_id") || "").trim();

  let logs;
  if (filter) {
    logs = await env.DB.prepare("SELECT * FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 300").bind(filter).all();
  } else {
    logs = await env.DB.prepare("SELECT * FROM tracking_logs ORDER BY opened_at DESC LIMIT 300").all();
  }

  const targetsResult = await env.DB.prepare(
    "SELECT id, image_type, creator_ip, creator_ua, creator_webrtc_ips, creator_fingerprint FROM targets ORDER BY created_at DESC LIMIT 500"
  ).all();
  const targetMap = {};
  for (const t of targetsResult.results) targetMap[t.id] = t;

  let logRows = "";
  for (const r of logs.results) {
    const date = new Date((r.opened_at || "").replace(" ", "T") + "Z").toLocaleString("zh-CN", { hour12: false });
    const geo = [r.country, r.region, r.city].filter(Boolean).join(", ");
    const t = targetMap[r.target_id] || {};
    let isLocal = false;
    const logIp = String(r.ip || "").trim();
    if (t.creator_ip && String(t.creator_ip).trim() === logIp) isLocal = true;
    if (!isLocal && t.creator_webrtc_ips) {
      try { const arr = JSON.parse(t.creator_webrtc_ips); if (Array.isArray(arr) && arr.some(x => String(x).trim() === logIp)) isLocal = true; } catch(e){}
    }
    const cc = (r.country_code || "").toLowerCase();
    const flag = cc ? `<img src="https://ipdata.co/flags/${cc}.png" class="flag-icon" style="width:18px;height:12px">` : "";
    const localBadge = isLocal ? '<span class="local-badge" style="font-size:10px;padding:1px 6px">本地</span>' : "";

    logRows += `<tr class="border-b hover:bg-gray-50 align-top">
      <td class="p-2"><input type="checkbox" class="log-check" data-target-id="${esc(r.target_id)}"></td>
      <td class="p-2 text-xs font-mono whitespace-nowrap">${esc(r.target_id)}</td>
      <td class="p-2 text-xs whitespace-nowrap">${esc(date)}</td>
      <td class="p-2 text-xs max-w-[200px]">
        <div class="flex flex-wrap items-center gap-1">
          <span class="font-mono ip-word-break">${esc(r.ip||"")}</span>${flag}${localBadge}
          <button class="ip-detail text-indigo-500 underline text-[11px]" data-ip="${esc(r.ip||"")}">查询</button>
        </div>
      </td>
      <td class="p-2 text-xs text-gray-600 max-w-[180px] break-words">${esc(geo)}</td>
      <td class="p-2 text-xs text-gray-500 max-w-[180px] break-all">${esc(r.ua||"")}</td>
      <td class="p-2 whitespace-nowrap"><button class="del-log text-red-500 underline text-[11px]" data-id="${r.id}">删除</button></td>
    </tr>`;
  }

  let creatorRows = "";
  for (const [id, info] of Object.entries(targetMap)) {
    const creatorIp = info.creator_ip || "Unknown";
    let webrtcHtml = "—";
    if (info.creator_webrtc_ips) {
      try {
        const arr = JSON.parse(info.creator_webrtc_ips);
        if (Array.isArray(arr) && arr.length) {
          webrtcHtml = arr.map(ip => `<span class="font-mono text-xs">${esc(ip)}</span> <button class="ip-detail text-indigo-500 underline text-[11px]" data-ip="${esc(ip)}">查询</button>`).join(" ");
        }
      } catch(e){}
    }
    let fpId = "—";
    if (info.creator_fingerprint) {
      try { const fp = JSON.parse(info.creator_fingerprint); if (fp && fp.visitorId) fpId = fp.visitorId.slice(0, 14) + "…"; } catch(e){}
    }
    const typeLabel = info.image_type === "video" ? "视频" : (info.image_type === "image" ? "图片" : "像素");

    creatorRows += `<tr class="border-b hover:bg-gray-50 align-top">
      <td class="p-2"><input type="checkbox" class="creator-check" data-creator-id="${esc(id)}"></td>
      <td class="p-2 text-xs font-mono whitespace-nowrap">${esc(id)}<div class="text-[10px] text-gray-400">${typeLabel}</div></td>
      <td class="p-2 text-xs">
        <div class="flex flex-wrap items-center gap-1">
          <span class="font-mono ip-word-break">${esc(creatorIp)}</span>
          <button class="ip-detail text-indigo-500 underline text-[11px]" data-ip="${esc(creatorIp)}">查询</button>
        </div>
      </td>
      <td class="p-2 text-xs text-gray-500 max-w-[180px] break-all">${esc(info.creator_ua||"")}</td>
      <td class="p-2 text-xs max-w-[220px]">${webrtcHtml}</td>
      <td class="p-2 text-xs font-mono text-gray-500">${esc(fpId)}</td>
      <td class="p-2 whitespace-nowrap"><button class="del-target text-red-500 underline text-[11px]" data-id="${esc(id)}">删除</button></td>
    </tr>`;
  }

  const html = `<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>后台管理</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<style>
  body{margin:0;min-height:100vh;font-family:system-ui,-apple-system,sans-serif;background:linear-gradient(135deg,#f6f8fd 0%,#f1f5f9 100%);}
  .glass{background:rgba(255,255,255,0.75);backdrop-filter:blur(20px);border:1px solid rgba(255,255,255,0.6);border-radius:20px;box-shadow:0 6px 28px -12px rgba(15,23,42,.14)}
  .stat{background:white;padding:16px;border-radius:16px;box-shadow:0 1px 3px rgba(0,0,0,0.05);text-align:center;flex:1;min-width:130px}
  .ip-word-break{word-break:break-all;overflow-wrap:anywhere}
  .local-badge{background:#fbbf24;color:#78350f;padding:1px 6px;border-radius:9999px;font-size:10px;font-weight:600}
  .flag-icon{border-radius:2px;box-shadow:0 1px 2px rgba(0,0,0,0.2);vertical-align:middle}
  .map-container{height:260px;width:100%;border-radius:12px;border:1px solid #e5e7eb;margin-top:8px}
  .detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 8px}
  .detail-item{display:flex;justify-content:space-between;padding:2px 0;border-bottom:1px solid #f3f4f6}
  .detail-label{color:#6b7280;font-weight:500}
  .detail-value{font-weight:500;word-break:break-word;text-align:right}
  .btn{padding:8px 14px;border-radius:10px;font-size:12.5px;font-weight:600;cursor:pointer;border:none}
  .btn-danger{background:#fee2e2;color:#b91c1c}.btn-danger:hover{background:#fecaca}
  .btn-soft{background:#eef2ff;color:#4338ca}.btn-soft:hover{background:#e0e7ff}
  .btn-dark{background:#fef3c7;color:#92400e}.btn-dark:hover{background:#fde68a}
  table{border-collapse:collapse;width:100%}
  th{background:#f8fafc;font-size:11.5px;font-weight:700;color:#64748b;text-align:left;padding:9px 8px;white-space:nowrap}
</style></head><body class="p-4">
<div class="max-w-7xl mx-auto space-y-4">

  <div class="flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-lg font-bold flex items-center gap-2"><i class="fa-solid fa-gauge-high text-indigo-600"></i>后台管理</h1>
    <div class="flex gap-2">
      <a href="/" class="btn btn-soft">返回首页</a>
      <button id="logoutBtn" class="btn btn-danger">退出登录</button>
    </div>
  </div>

  <div class="flex flex-wrap gap-3">
    <div class="stat"><div class="text-2xl font-bold text-indigo-600">${totalTargets ? totalTargets.c : 0}</div><div class="text-xs text-gray-500 mt-1">追踪 ID 总数</div></div>
    <div class="stat"><div class="text-2xl font-bold text-emerald-600">${totalLogs ? totalLogs.c : 0}</div><div class="text-xs text-gray-500 mt-1">总访问次数</div></div>
    <div class="stat"><div class="text-2xl font-bold text-amber-600">${uniqueIps ? uniqueIps.c : 0}</div><div class="text-xs text-gray-500 mt-1">独立 IP</div></div>
  </div>

  <div class="glass p-4">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
      <h2 class="font-bold text-[15px]">📋 访问日志</h2>
      <div class="flex flex-wrap gap-2">
        <input id="filterInput" value="${esc(filter)}" placeholder="按追踪 ID 过滤" class="border border-gray-200 rounded-xl px-3 py-1.5 text-xs outline-none focus:border-indigo-400">
        <button id="filterBtn" class="btn btn-soft">筛选</button>
        <button id="delSelected" class="btn btn-dark">删除选中 ID</button>
        <button id="clearLogs" class="btn btn-danger">清空日志</button>
        <button id="clearAll" class="btn btn-danger">清空全部</button>
      </div>
    </div>
    <div class="overflow-x-auto">
      <table>
        <thead><tr><th style="width:32px"><input type="checkbox" id="checkAllLogs"></th><th>ID</th><th>时间</th><th>IP</th><th>地理位置</th><th>User-Agent</th><th>操作</th></tr></thead>
        <tbody>${logRows || '<tr><td colspan="7" class="p-6 text-center text-gray-400 text-sm">暂无记录</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="glass p-4">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
      <h2 class="font-bold text-[15px]">🧑‍💻 追踪 ID 创建者信息</h2>
      <button id="delCreators" class="btn btn-dark">删除选中创建者</button>
    </div>
    <div class="overflow-x-auto">
      <table>
        <thead><tr><th style="width:32px"><input type="checkbox" id="checkAllCreators"></th><th>ID</th><th>创建 IP</th><th>UA</th><th>WebRTC 泄露 IP</th><th>指纹 ID</th><th>操作</th></tr></thead>
        <tbody>${creatorRows || '<tr><td colspan="7" class="p-6 text-center text-gray-400 text-sm">暂无数据</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="text-center text-xs text-gray-400 py-4 space-y-1">
    <div>Copyright © 2026 SAK All rights reserved.</div>
    <div>QQ:3344310554 · E-mail:cnzz666@163.com · Bilibili:SAK _CN</div>
  </div>
</div>

<div id="ipModal" class="modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.5);align-items:center;justify-content:center;z-index:100">
  <div style="background:white;border-radius:1.5rem;padding:1.5rem;max-width:42rem;width:92%;max-height:88vh;overflow-y:auto">
    <div class="flex justify-between items-center mb-3">
      <h3 class="font-bold"><i class="fa-solid fa-circle-info text-indigo-500 mr-2"></i>IP 详细信息</h3>
      <button id="ipClose" class="text-gray-400 hover:text-red-500 text-xl leading-none">&times;</button>
    </div>
    <div id="ipBody"></div>
  </div>
</div>

<script>
(function(){
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  function esc(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }

  $("#logoutBtn").addEventListener("click", async () => { await fetch("/api/admin/logout", { method:"POST" }); location.href = "/admin"; });

  $("#checkAllLogs").addEventListener("change", function(){ $$(".log-check").forEach(cb => cb.checked = this.checked); });
  $("#checkAllCreators").addEventListener("change", function(){ $$(".creator-check").forEach(cb => cb.checked = this.checked); });

  async function post(url, body){
    const res = await fetch(url, { method:"POST", headers: body ? {"Content-Type":"application/json"} : {}, body: body ? JSON.stringify(body) : undefined });
    return res.ok;
  }

  document.addEventListener("click", async e => {
    const delLog = e.target.closest(".del-log");
    if (delLog) {
      if (!confirm("删除这条访问记录？")) return;
      if (await post("/api/admin/delete", { id: parseInt(delLog.dataset.id, 10) })) location.reload(); else alert("删除失败");
      return;
    }
    const delTarget = e.target.closest(".del-target");
    if (delTarget) {
      if (!confirm("删除该追踪 ID 及其全部访问记录？")) return;
      if (await post("/api/admin/delete-target", { id: delTarget.dataset.id })) location.reload(); else alert("删除失败");
      return;
    }
    const ipBtn = e.target.closest(".ip-detail");
    if (ipBtn) {
      const ip = ipBtn.dataset.ip;
      if (!ip || ip === "Unknown") { alert("该 IP 无法查询（Unknown）"); return; }
      openIpDetail(ip);
    }
  });

  $("#delSelected").addEventListener("click", async () => {
    const ids = $$(".log-check:checked").map(cb => cb.dataset.targetId);
    if (!ids.length) { alert("请先勾选要删除的追踪 ID"); return; }
    if (!confirm("确认删除选中的 " + ids.length + " 个追踪 ID 及其全部日志？")) return;
    if (await post("/api/admin/delete-targets", { ids })) location.reload(); else alert("删除失败");
  });
  $("#delCreators").addEventListener("click", async () => {
    const ids = $$(".creator-check:checked").map(cb => cb.dataset.creatorId);
    if (!ids.length) { alert("请先勾选要删除的创建者"); return; }
    if (!confirm("确认删除选中的 " + ids.length + " 个创建者及其全部日志？")) return;
    if (await post("/api/admin/delete-targets", { ids })) location.reload(); else alert("删除失败");
  });

  $("#clearLogs").addEventListener("click", async () => {
    if (!confirm("确认清空全部访问日志？（追踪 ID 会保留）")) return;
    if (await post("/api/admin/clear")) location.reload(); else alert("操作失败");
  });
  $("#clearAll").addEventListener("click", async () => {
    if (!confirm("确认清空全部追踪 ID 及日志？此操作不可恢复！")) return;
    if (await post("/api/admin/clear-targets")) location.reload(); else alert("操作失败");
  });

  $("#filterBtn").addEventListener("click", () => {
    const v = $("#filterInput").value.trim();
    location.href = "/admin" + (v ? "?filter_id=" + encodeURIComponent(v) : "");
  });
  $("#filterInput").addEventListener("keydown", e => { if (e.key === "Enter") $("#filterBtn").click(); });

  const modal = $("#ipModal");
  const body = $("#ipBody");
  let dmap = null;
  function closeModal(){ modal.style.display = "none"; if (dmap) { dmap.remove(); dmap = null; } }
  $("#ipClose").addEventListener("click", closeModal);
  modal.addEventListener("click", e => { if (e.target === modal) closeModal(); });

  function row(label, value, cls) {
    return '<div class="detail-item"><span class="detail-label">' + label + '</span><span class="detail-value ' + (cls||"") + '">' +
      esc(value == null || value === "" ? "—" : String(value)) + '</span></div>';
  }

  async function openIpDetail(ip){
    modal.style.display = "flex";
    body.innerHTML = '<div class="text-center py-4 text-gray-400"><i class="fa-solid fa-spinner fa-spin"></i> 加载中…</div>';

    let data = null;
    try { const res = await fetch("/api/ip?ip=" + encodeURIComponent(ip)); data = await res.json().catch(()=>null); } catch(e){ data = null; }
    if (!data) { body.innerHTML = '<div class="text-red-500 text-center py-4">网络异常</div>'; return; }
    if (data.error) { body.innerHTML = '<div class="text-red-500 text-center py-4">' + esc(data.error) + '</div>'; return; }

    const loc = data.location || {};
    const comp = data.company || {};
    const asn = data.asn || {};
    const dc = data.datacenter || {};
    const abuse = data.abuse || {};
    const cc = (loc.country_code || "").toLowerCase();
    const lat = loc.latitude, lon = loc.longitude;

    let risk = "—", riskCls = "";
    if (typeof data.risk_score === "number") {
      risk = data.risk_score.toFixed(2) + "%";
      riskCls = data.risk_score > 30 ? "text-red-600 font-bold" : "text-green-600 font-bold";
    } else if (data.is_proxy || data.is_tor || data.is_vpn || data.is_abuser) { risk = "高风险"; riskCls = "text-red-600 font-bold"; }
    else if (data.is_datacenter) { risk = "数据中心"; riskCls = "text-amber-600 font-bold"; }

    let h = "";
    h += '<div class="flex items-center gap-2 border-b pb-2 mb-3"><span class="font-bold text-lg ip-word-break">' + esc(ip) + '</span>';
    if (cc) h += '<img src="https://ipdata.co/flags/' + cc + '.png" style="width:32px;height:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.2)">';
    h += '</div>';

    h += '<div class="mb-3"><div class="font-semibold text-indigo-700 mb-1">📍 基本信息</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
    h += row("国家", (loc.country||"") + (loc.country_code ? " (" + loc.country_code + ")" : ""));
    h += row("州/省", loc.state || "");
    h += row("城市", loc.city || "");
    h += row("时区", loc.timezone || "");
    h += row("经纬度", (lat && lon) ? (lat + ", " + lon) : "");
    h += row("风控评级", risk, riskCls);
    h += '</div></div>';

    h += '<div class="mb-3"><div class="font-semibold text-emerald-700 mb-1">🏢 运营商 & ASN</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
    h += row("运营商", comp.name || "");
    h += row("类型", comp.type || "");
    h += row("域名", comp.domain || "");
    h += row("ASN", asn.asn || "");
    h += row("ASN 描述", asn.descr || "");
    h += row("ASN 所属", asn.org || "");
    h += row("路由前缀", asn.route || "");
    h += row("ASN 国家", asn.country || "");
    h += '</div></div>';

    if (dc.datacenter) {
      h += '<div class="mb-3"><div class="font-semibold text-amber-700 mb-1">☁️ 数据中心</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
      h += row("名称", dc.datacenter || ""); h += row("服务商", dc.service || "");
      h += row("区域", dc.scope || ""); h += row("网络段", dc.network || "");
      h += '</div></div>';
    }
    if (abuse.email) {
      h += '<div class="mb-3"><div class="font-semibold text-red-600 mb-1">⚠️ 滥用举报</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
      h += row("姓名", abuse.name || ""); h += row("邮箱", abuse.email || "");
      h += row("电话", abuse.phone || ""); h += row("地址", abuse.address || "");
      h += '</div></div>';
    }

    h += '<div class="mb-3"><div class="font-semibold text-purple-700 mb-1">🛡️ 安全检测</div><div class="detail-grid bg-gray-50 p-3 rounded-xl">';
    h += row("数据中心", data.is_datacenter ? "是" : "否");
    h += row("代理", data.is_proxy ? "是" : "否");
    h += row("VPN", data.is_vpn ? "是" : "否");
    h += row("Tor", data.is_tor ? "是" : "否");
    h += row("爬虫", data.is_crawler ? "是" : "否");
    h += row("移动网络", data.is_mobile ? "是" : "否");
    h += row("卫星网络", data.is_satellite ? "是" : "否");
    h += row("已知滥用", data.is_abuser ? "是" : "否");
    h += '</div></div>';

    if (lat && lon) {
      h += '<div class="mb-2"><div class="font-semibold text-blue-700 mb-1">🗺️ 地理位置</div>';
      h += '<div id="adminIpMap" class="map-container"></div></div>';
    }
    body.innerHTML = h;

    if (lat && lon) {
      setTimeout(() => {
        const el = document.getElementById("adminIpMap");
        if (!el) return;
        try {
          if (dmap) dmap.remove();
          dmap = L.map(el).setView([lat, lon], 8);
          L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(dmap);
          L.marker([lat, lon]).addTo(dmap);
        } catch(e){}
      }, 50);
    }
  }
})();
<\/script>
</body></html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}