// @ts-nocheck
// Cloudflare Worker 邮件/链接追踪器
// 绑定 D1 "DB"，环境变量 ADMIN (管理员密码)，可选 IPAPI_KEY

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

// 是否内网 IP（IPv4 私有段 + IPv6 ULA/链路本地）
function isPrivateIp(ip) {
  if (!ip) return false;
  const s = String(ip).trim();
  if (!s) return false;
  if (s.includes(":")) {
    const l = s.toLowerCase();
    return l === "::1" ||
      l.startsWith("fc") || l.startsWith("fd") ||
      l.startsWith("fe8") || l.startsWith("fe9") ||
      l.startsWith("fea") || l.startsWith("feb");
  }
  const p = s.split(".").map(Number);
  if (p.length !== 4 || p.some(n => isNaN(n))) return false;
  return p[0] === 10 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    p[0] === 127 ||
    (p[0] === 169 && p[1] === 254);
}

// 多 header 兜底取客户端 IP
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

/* ---------- 工具 ---------- */
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

/* ---------- DB ---------- */
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
      burned INTEGER DEFAULT 0,
      opened_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`).run();

  const targetCols = ["pass_hash","pass_salt","image_type","image_url","creator_ip","creator_ua","creator_webrtc_ips","creator_fingerprint"];
  for (const col of targetCols) { try { await env.DB.prepare(`ALTER TABLE targets ADD COLUMN ${col} TEXT`).run(); } catch (e) {} }

  const logCols = ["country_code","region","city","timezone","isp","org","as_text","referer","accept","accept_encoding","sec_ch_ua","sec_ch_ua_platform","sec_ch_ua_mobile"];
  for (const col of logCols) { try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN ${col} TEXT`).run(); } catch (e) {} }
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lat REAL`).run(); } catch (e) {}
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lon REAL`).run(); } catch (e) {}
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN burned INTEGER DEFAULT 0`).run(); } catch (e) {}
}

/* ---------- 追踪像素 ---------- */
async function handlePixel(request, env, ctx, targetId) {
  const target = await env.DB.prepare("SELECT image_type, image_url FROM targets WHERE id = ?").bind(targetId).first();
  if (!target) return transparentPixel();

  const cf = request.cf || {};
  const ip = getClientIp(request);
  const ua = request.headers.get("User-Agent") || "";
  const lat = cf.latitude ? parseFloat(cf.latitude) : null;
  const lon = cf.longitude ? parseFloat(cf.longitude) : null;

  try {
    await env.DB.prepare(`
      INSERT INTO tracking_logs (
        target_id, event_type, ip, country, country_code, region, city, timezone,
        isp, org, as_text, lat, lon, ua, languages, referer, accept, accept_encoding,
        sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile, burned
      ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
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

/* ---------- 生成 ---------- */
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
  const creatorIp = getClientIp(request);
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

/* ---------- 查询 / 统计 ---------- */
async function verifyTargetPassword(env, id, password) {
  if (!id || !password) return { ok: false, code: 400, error: "缺少参数" };
  const target = await env.DB.prepare("SELECT * FROM targets WHERE id = ?").bind(id).first();
  if (!target) return { ok: false, code: 404, error: "追踪 ID 不存在" };
  if (!target.pass_hash || !target.pass_salt) return { ok: false, code: 403, error: "该记录无访问密码" };
  const hash = await hashPassword(password, target.pass_salt);
  if (hash !== target.pass_hash) return { ok: false, code: 401, error: "访问密码错误" };
  return { ok: true, target };
}

function buildCreatorIpSet(target) {
  const s = new Set();
  if (target && target.creator_ip) s.add(String(target.creator_ip).trim());
  if (target && target.creator_webrtc_ips) {
    try {
      const arr = JSON.parse(target.creator_webrtc_ips);
      if (Array.isArray(arr)) arr.forEach(ip => { if (ip) s.add(String(ip).trim()); });
    } catch (e) {}
  }
  return s;
}

async function handleQuery(request, env) {
  const u = new URL(request.url);
  const id = (u.searchParams.get("id") || "").trim();
  const password = u.searchParams.get("password") || "";
  const burn = u.searchParams.get("burn") === "true";

  const check = await verifyTargetPassword(env, id, password);
  if (!check.ok) return jsonResponse({ error: check.error }, check.code);

  const target = check.target;
  const creatorIpSet = buildCreatorIpSet(target);

  const logs = await env.DB.prepare(`
    SELECT id, target_id, event_type, ip, country, country_code, region, city, timezone,
           isp, org, as_text, lat, lon, ua, languages, referer, accept, accept_encoding,
           sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile, burned, opened_at
    FROM tracking_logs
    WHERE target_id = ? AND (burned IS NULL OR burned = 0)
    ORDER BY opened_at DESC LIMIT 500
  `).bind(id).all();

  const results = logs.results.map(log => ({
    ...log,
    is_local: creatorIpSet.has(String(log.ip || "").trim())
  }));

  if (burn && results.length > 0) {
    await env.DB.prepare(
      "UPDATE tracking_logs SET burned = 1 WHERE target_id = ? AND (burned IS NULL OR burned = 0)"
    ).bind(id).run();
  }

  return jsonResponse({
    id,
    mediaType: target.image_type || "default",
    mediaUrl: target.image_url || "",
    createdAt: target.created_at || null,
    burnedCount: burn ? results.length : 0,
    logs: results
  });
}

async function handleStats(request, env) {
  const u = new URL(request.url);
  const id = (u.searchParams.get("id") || "").trim();
  const password = u.searchParams.get("password") || "";
  const check = await verifyTargetPassword(env, id, password);
  if (!check.ok) return jsonResponse({ error: check.error }, check.code);

  const total = await env.DB.prepare(
    "SELECT COUNT(*) AS c FROM tracking_logs WHERE target_id = ? AND (burned IS NULL OR burned = 0)"
  ).bind(id).first();
  const uniqueIp = await env.DB.prepare(
    "SELECT COUNT(DISTINCT ip) AS c FROM tracking_logs WHERE target_id = ? AND (burned IS NULL OR burned = 0)"
  ).bind(id).first();
  const latest = await env.DB.prepare(
    "SELECT opened_at FROM tracking_logs WHERE target_id = ? AND (burned IS NULL OR burned = 0) ORDER BY opened_at DESC LIMIT 1"
  ).bind(id).first();

  return jsonResponse({
    total: total ? total.c : 0,
    uniqueIps: uniqueIp ? uniqueIp.c : 0,
    latestOpen: latest ? latest.opened_at : null
  });
}

/* ---------- IP 详情（服务端代理） ---------- */
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

/* ---------- 后台登录（无状态 cookie，不依赖 D1 会话表） ---------- */
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

/* ---------- 后台操作 ---------- */
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

/* ---------- 瓦片 ---------- */
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

/* ---------- 配置提示 ---------- */
function setupNotice() {
  const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>配置未完成</title>
<style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;font-family:system-ui,sans-serif;background:#0b1120;color:#e2e8f0}
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
 *  首页
 * =======================================================*/
function renderHome(env) {
  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>邮件追踪器</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<script src="https://cdn.jsdelivr.net/npm/@fingerprintjs/fingerprintjs@3/dist/fp.min.js"><\/script>
<style>
  *{-webkit-tap-highlight-color:transparent}
  body{margin:0;font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;
       background:radial-gradient(1200px 600px at 50% -10%,#e8edff 0%,#f6f8fc 45%,#f1f5f9 100%);min-height:100vh;color:#0f172a}
  .card{background:#fff;border:1px solid #e9edf5;border-radius:20px;box-shadow:0 6px 28px -12px rgba(15,23,42,.14)}
  .fld{width:100%;border:1px solid #dfe5f0;border-radius:12px;padding:10px 13px;font-size:14px;outline:none;background:#fbfcfe;transition:.18s}
  .fld:focus{border-color:#6366f1;background:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.12)}
  .lbl{font-size:12.5px;font-weight:600;color:#475569;margin-bottom:6px;display:block}
  .btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;font-weight:600;font-size:14px;border-radius:12px;padding:10px 20px;border:none;cursor:pointer;transition:.16s}
  .btn:active{transform:translateY(1px)}
  .btn-primary{background:#4f46e5;color:#fff}.btn-primary:hover{background:#4338ca}
  .btn-ghost{background:#eef2ff;color:#4338ca}.btn-ghost:hover{background:#e0e7ff}
  .btn-soft{background:#ecfdf5;color:#047857}.btn-soft:hover{background:#d1fae5}
  .btn:disabled{opacity:.55;cursor:not-allowed}
  .tabbar{display:inline-flex;background:#eef2f8;border-radius:12px;padding:3px;gap:3px}
  .tabbar button{border:none;background:transparent;font-size:13.5px;font-weight:600;color:#64748b;padding:7px 18px;border-radius:9px;cursor:pointer;transition:.16s}
  .tabbar button.on{background:#fff;color:#4338ca;box-shadow:0 1px 5px rgba(15,23,42,.1)}
  .opt{display:flex;align-items:center;gap:8px;font-size:13.5px;color:#334155;padding:9px 13px;border:1px solid #e6ebf3;border-radius:11px;cursor:pointer;transition:.15s;background:#fbfcfe}
  .opt:hover{border-color:#c7d2fe;background:#f8faff}
  .opt input{accent-color:#4f46e5;margin:0}.opt.on{border-color:#a5b4fc;background:#eef2ff}
  .ip-addr{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all;overflow-wrap:anywhere;line-height:1.45}
  .local-badge{background:#fef3c7;color:#92400e;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:700;white-space:nowrap}
  .burned-badge{background:#fee2e2;color:#991b1b;padding:1px 8px;border-radius:999px;font-size:10.5px;font-weight:700;white-space:nowrap}
  .flag{width:20px;height:14px;border-radius:2px;box-shadow:0 1px 3px rgba(0,0,0,.18);vertical-align:-1px}
  .tl{position:relative;padding-left:20px}
  .tl::before{content:"";position:absolute;left:5px;top:6px;bottom:6px;width:2px;background:#e6ebf3;border-radius:2px}
  .tl-item{position:relative;padding:7px 0}
  .tl-item::before{content:"";position:absolute;left:-19px;top:14px;width:8px;height:8px;border-radius:50%;background:#6366f1;box-shadow:0 0 0 2.5px #fff}
  /* 关键修复：弹窗 z-index 高于 Leaflet 地图（Leaflet 默认 400~700），避免地图遮挡弹窗 */
  .modal{position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(3px);display:none;align-items:center;justify-content:center;padding:14px;z-index:9999}
  .modal.on{display:flex}
  .modal-box{background:#fff;border-radius:18px;width:100%;max-width:620px;max-height:88vh;overflow:auto;position:relative;z-index:1}
  .dgrid{display:grid;grid-template-columns:1fr;gap:0}
  @media(min-width:520px){.dgrid{grid-template-columns:1fr 1fr;gap:0 16px}}
  .drow{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px dashed #eef2f8;font-size:13px}
  .drow span:first-child{color:#64748b;flex-shrink:0}
  .drow span:last-child{text-align:right;word-break:break-word;font-weight:500;min-width:0}
  .mapbox{height:260px;width:100%;border-radius:12px;border:1px solid #e6ebf3;margin-top:8px}
  .sect-title{font-size:13px;font-weight:700;margin:14px 0 6px;display:flex;align-items:center;gap:6px}
  a{color:inherit}
</style>
</head>
<body>
<div class="max-w-3xl mx-auto px-4 py-8 sm:py-12 space-y-5">

  <div class="card p-5 sm:p-7">
    <div class="flex items-center gap-2 mb-1">
      <i class="fa-solid fa-envelope-open-text text-indigo-600"></i>
      <h1 class="text-lg sm:text-xl font-bold">邮件追踪器</h1>
    </div>
    <p class="text-xs sm:text-[13px] text-slate-500 leading-relaxed mb-6">
      生成邮件追踪代码，支持1x1像素图片，自定义图片，自定义视频追踪，对方打开邮件即可查看对方IP/UA信息，记录对方打开次数，以时间轴显示。
      目前已实现自动标记本地查看，方便过滤和筛选。
      且每个ID都有独立访问密码，防止他人恶意查询。
    </p>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div>
        <label class="lbl">追踪 ID <span class="text-slate-400 font-normal">（4–32 位字母/数字/_/-）</span></label>
        <input id="customId" class="fld" placeholder="例如：mail-2026" autocomplete="off" spellcheck="false">
      </div>
      <div>
        <label class="lbl">访问密码 <span class="text-slate-400 font-normal">（4–64 位，查询时使用）</span></label>
        <div class="relative">
          <input id="password" type="password" class="fld pr-10" placeholder="设置一个只有你知道的密码" autocomplete="new-password">
          <button type="button" id="pwdEye" class="absolute right-2 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 px-2">
            <i class="fa-regular fa-eye"></i>
          </button>
        </div>
      </div>
    </div>

    <div class="mt-6">
      <label class="lbl">追踪媒体类型</label>
      <div class="tabbar" id="kindTabs">
        <button type="button" data-kind="image" class="on"><i class="fa-regular fa-image mr-1"></i>图片</button>
        <button type="button" data-kind="video"><i class="fa-solid fa-video mr-1"></i>视频</button>
      </div>
    </div>

    <div id="imageOpts" class="mt-3 space-y-2">
      <label class="opt on"><input type="radio" name="imageMode" value="default" checked> 默认 1×1 像素（隐藏，最不易被察觉）</label>
      <label class="opt"><input type="radio" name="imageMode" value="url"> 自定义图片 URL</label>
      <label class="opt"><input type="radio" name="imageMode" value="upload"> 上传图片（推荐）</label>
    </div>

    <div id="videoOpts" class="mt-3 space-y-2 hidden">
      <label class="opt on"><input type="radio" name="videoMode" value="upload" checked> 上传视频（推荐）</label>
      <label class="opt"><input type="radio" name="videoMode" value="url"> 自定义视频 URL</label>
    </div>

    <div id="urlBox" class="mt-3 hidden">
      <input id="mediaUrl" class="fld" placeholder="https://…" autocomplete="off" spellcheck="false">
    </div>
    <div id="fileBox" class="mt-3 hidden">
      <input id="mediaFile" type="file" class="fld py-2.5">
      <p id="fileHint" class="text-[11.5px] text-slate-400 mt-1.5"></p>
    </div>

    <div class="mt-6 flex flex-wrap gap-3">
      <button id="genBtn" class="btn btn-primary flex-1 sm:flex-none">
        <i class="fa-solid fa-wand-magic-sparkles"></i> 生成追踪代码
      </button>
    </div>

    <div id="result" class="mt-5 hidden">
      <div class="rounded-2xl border border-indigo-100 bg-indigo-50/50 p-4">
        <div class="flex items-center justify-between gap-3 mb-2 flex-wrap">
          <span class="text-[13px] font-semibold text-indigo-900">
            追踪 ID：<span id="trackId" class="ip-addr text-indigo-600"></span>
          </span>
          <button id="copyBtn" class="btn btn-ghost !py-1.5 !px-3 !text-[12.5px]">
            <i class="fa-regular fa-copy"></i> 复制
          </button>
        </div>
        <textarea id="codeOut" readonly rows="3"
          class="w-full text-[12px] font-mono bg-white border border-indigo-100 rounded-xl p-3 resize-none outline-none"></textarea>
        <p class="text-[11.5px] text-slate-500 mt-2">请妥善保管追踪 ID 与访问密码，丢失后无法找回记录。</p>
      </div>
    </div>
  </div>

  <div class="card p-5 sm:p-7">
    <div class="flex items-center gap-2 mb-5">
      <i class="fa-solid fa-magnifying-glass text-emerald-600"></i>
      <h2 class="text-lg font-bold">查询记录</h2>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
      <div>
        <label class="lbl">追踪 ID</label>
        <input id="qId" class="fld" placeholder="输入追踪 ID" autocomplete="off" spellcheck="false">
      </div>
      <div>
        <label class="lbl">访问密码</label>
        <input id="qPwd" type="password" class="fld" placeholder="输入访问密码" autocomplete="current-password">
      </div>
    </div>

    <div class="mt-5 flex flex-wrap gap-3">
      <button id="qBtn" class="btn btn-primary"><i class="fa-solid fa-magnifying-glass"></i> 查询</button>
      <button id="sBtn" class="btn btn-soft"><i class="fa-solid fa-chart-simple"></i> 统计</button>
      <button id="burnBtn" class="btn btn-ghost"><i class="fa-solid fa-fire"></i> 查询并清除</button>
    </div>

    <div id="stats" class="mt-4 hidden text-[13px] text-slate-600 bg-slate-50 border border-slate-100 rounded-xl px-4 py-3"></div>
    <div id="qResult" class="mt-5 space-y-4"></div>
  </div>

  <footer class="text-center text-[11.5px] text-slate-400 leading-relaxed py-6 space-y-1">
    <div><a href="/admin" class="hover:text-indigo-500 underline decoration-dotted">后台管理</a></div>
    <div>Copyright © 2026 SAK All rights reserved.</div>
    <div class="break-words px-2">
      QQ:3344310554 · E-mail:cnzz666@163.com ·
      <a href="https://b23.tv/8fCttY7" target="_blank" rel="noopener noreferrer" class="text-indigo-500 hover:text-indigo-600">Bilibili:SAK_CN</a>
    </div>
  </footer>
</div>

<div id="ipModal" class="modal">
  <div class="modal-box">
    <div class="flex items-center justify-between px-5 py-4 border-b border-slate-100 sticky top-0 bg-white rounded-t-2xl">
      <h3 class="font-bold text-[15px]"><i class="fa-solid fa-circle-info text-indigo-500 mr-2"></i>IP 详细信息</h3>
      <button id="ipClose" class="text-slate-400 hover:text-red-500 text-2xl leading-none px-1">&times;</button>
    </div>
    <div id="ipBody" class="px-5 py-4"></div>
  </div>
</div>

<script>
(function () {
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  function escapeHtml(s){ return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;"); }

  function isPrivateIp(ip) {
    if (!ip) return false;
    const s = String(ip).trim();
    if (!s) return false;
    if (s.includes(":")) {
      const l = s.toLowerCase();
      return l === "::1" || l.startsWith("fc") || l.startsWith("fd") ||
        l.startsWith("fe8") || l.startsWith("fe9") || l.startsWith("fea") || l.startsWith("feb");
    }
    const p = s.split(".").map(Number);
    if (p.length !== 4 || p.some(n => isNaN(n))) return false;
    return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || p[0] === 127 || (p[0] === 169 && p[1] === 254);
  }

  let creatorWebRTC = [], creatorFingerprint = null;
  (async function collect(){
    try {
      if (window.FingerprintJS) { const fp = await FingerprintJS.load(); creatorFingerprint = await fp.get(); }
    } catch(e){}
    try {
      const ips = new Set();
      const pc = new RTCPeerConnection({ iceServers: [
        { urls: "stun:stun.chat.bilibili.com:3478" },
        { urls: "stun:stun.hitv.com:3478" },
        { urls: "stun:stun.miwifi.com:3478" },
        { urls: "stun:stun.l.google.com:19302" }
      ]});
      pc.createDataChannel("");
      pc.onicecandidate = (e) => {
        if (e.candidate && e.candidate.candidate) {
          const m = e.candidate.candidate.match(/([0-9]{1,3}(\\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/i);
          if (m && m[1] && m[1] !== "0.0.0.0" && m[1] !== "127.0.0.1") ips.add(m[1]);
        }
      };
      await new Promise((resolve) => {
        pc.onicegatheringstatechange = () => { if (pc.iceGatheringState === 'complete') resolve(); };
        pc.createOffer().then(o => pc.setLocalDescription(o)).catch(()=>{});
        setTimeout(resolve, 2500);
      });
      creatorWebRTC = Array.from(ips);
    } catch(e){}
  })();

  $("#pwdEye").addEventListener("click", () => {
    const el = $("#password");
    const isPwd = el.type === "password";
    el.type = isPwd ? "text" : "password";
    $("#pwdEye").innerHTML = isPwd ? '<i class="fa-regular fa-eye-slash"></i>' : '<i class="fa-regular fa-eye"></i>';
  });

  let kind = "image";
  function currentMode() {
    if (kind === "image") {
      const r = document.querySelector('input[name="imageMode"]:checked');
      const v = r ? r.value : "default";
      return v === "default" ? "default" : (v === "url" ? "image-url" : "image-upload");
    }
    const r = document.querySelector('input[name="videoMode"]:checked');
    const v = r ? r.value : "upload";
    return v === "url" ? "video-url" : "video-upload";
  }
  function refreshUI() {
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
    btn.disabled = true;
    btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 处理中…';
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
    finally { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-wand-magic-sparkles"></i> 生成追踪代码'; }
  });

  $("#copyBtn").addEventListener("click", async () => {
    const ta = $("#codeOut");
    try {
      await navigator.clipboard.writeText(ta.value);
      $("#copyBtn").innerHTML = '<i class="fa-solid fa-check"></i> 已复制';
      setTimeout(() => { $("#copyBtn").innerHTML = '<i class="fa-regular fa-copy"></i> 复制'; }, 1500);
    } catch {
      ta.select(); document.execCommand("copy");
    }
  });

  const mapPool = {};
  function fmtTime(s) {
    if (!s) return "";
    const d = new Date(s.replace(" ", "T") + "Z");
    if (isNaN(d)) return s;
    return d.toLocaleString("zh-CN", { hour12: false });
  }

  async function doQuery(burn) {
    const id = $("#qId").value.trim();
    const pwd = $("#qPwd").value;
    const box = $("#qResult");
    if (!id || !pwd) { box.innerHTML = '<p class="text-[13px] text-red-500">请填写追踪 ID 和访问密码</p>'; return; }
    box.innerHTML = '<p class="text-[13px] text-slate-400"><i class="fa-solid fa-spinner fa-spin mr-1"></i>查询中…</p>';

    try {
      const res = await fetch("/api/query?id=" + encodeURIComponent(id) +
        "&password=" + encodeURIComponent(pwd) + "&burn=" + (burn ? "true" : "false"));
      const data = await res.json();
      if (!res.ok || data.error) {
        box.innerHTML = '<p class="text-[13px] text-red-500">' + escapeHtml(data.error || "查询失败") + '</p>';
        return;
      }
      const logs = data.logs || [];
      if (logs.length === 0) {
        box.innerHTML = '<p class="text-[13px] text-slate-400">暂无访问记录' + (burn ? '（已清除）' : '') + '</p>';
        return;
      }

      const groups = new Map();
      for (const log of logs) {
        const ip = log.ip || "Unknown";
        if (!groups.has(ip)) groups.set(ip, []);
        groups.get(ip).push(log);
      }

      let html = "";
      const mapIds = [];
      let idx = 0;

      if (burn) {
        html += '<div class="rounded-xl bg-amber-50 border border-amber-200 text-amber-800 text-[12.5px] px-3 py-2">已清除 ' + (data.burnedCount || logs.length) + ' 条记录</div>';
      }

      for (const [ip, items] of groups) {
        const first = items[0];
        const isLocal = items.some(x => x.is_local === true);
        const place = [first.country, first.region, first.city].filter(Boolean).join(" · ");
        const cc = (first.country_code || "").toLowerCase();
        const mapId = "m" + (idx++);
        mapIds.push({ id: mapId, lat: first.lat, lon: first.lon, ip, city: first.city, country: first.country });

        html += '<div class="rounded-2xl border border-slate-200 bg-slate-50/60 p-4 overflow-hidden">';
        html += '<div class="flex flex-wrap items-start gap-x-3 gap-y-2">';
        html += '<div class="min-w-0 flex-1">';
        html += '<div class="flex flex-wrap items-center gap-x-2 gap-y-1">';
        html += '<span class="ip-addr text-[14px] sm:text-[15px] font-bold text-indigo-700">' + escapeHtml(ip) + '</span>';
        if (cc) html += '<img class="flag" src="https://ipdata.co/flags/' + cc + '.png" alt="" loading="lazy">';
        if (isLocal) html += '<span class="local-badge"><i class="fa-solid fa-house mr-0.5"></i>本地查看</span>';
        html += '</div>';
        if (place) html += '<div class="text-[12px] text-slate-500 mt-1 break-words">' + escapeHtml(place) + '</div>';
        html += '</div>';
        html += '<div class="flex items-center gap-2 shrink-0">';
        html += '<span class="text-[11.5px] text-slate-400 whitespace-nowrap">' + items.length + ' 次</span>';
        html += '<button class="ip-btn btn btn-ghost !py-1 !px-2.5 !text-[12px]" data-ip="' + escapeHtml(ip) + '">详情</button>';
        html += '</div></div>';

        if (first.lat && first.lon) html += '<div id="' + mapId + '" class="mapbox"></div>';

        html += '<div class="tl mt-3">';
        for (const log of items) {
          html += '<div class="tl-item">';
          html += '<div class="flex flex-wrap items-center gap-2">';
          html += '<span class="text-[11.5px] text-slate-400">' + fmtTime(log.opened_at) + '</span>';
          if (log.is_local) html += '<span class="local-badge">本地</span>';
          html += '</div>';
          if (log.ua) html += '<div class="text-[11.5px] text-slate-500 mt-1 break-all leading-relaxed">' + escapeHtml(log.ua) + '</div>';
          if (log.referer) html += '<div class="text-[11px] text-slate-400 mt-0.5 break-all">来源：' + escapeHtml(log.referer) + '</div>';
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
          const map = L.map(m.id, { zoomControl: true, attributionControl: false }).setView([m.lat, m.lon], 6);
          L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 18 }).addTo(map);
          L.marker([m.lat, m.lon]).addTo(map)
            .bindPopup(escapeHtml(m.ip) + "<br>" + escapeHtml([m.city, m.country].filter(Boolean).join(", ")));
          mapPool[m.id] = map;
        } catch(e){}
      }
      box.querySelectorAll(".ip-btn").forEach(btn => {
        btn.addEventListener("click", () => openIpDetail(btn.dataset.ip));
      });
    } catch (e) {
      box.innerHTML = '<p class="text-[13px] text-red-500">查询失败：' + escapeHtml(e.message) + '</p>';
    }
  }

  $("#qBtn").addEventListener("click", () => doQuery(false));
  $("#burnBtn").addEventListener("click", () => {
    if (!confirm("查询后将自动删除该ID下的所有记录，再次查询将失效，确认继续？")) return;
    doQuery(true);
  });

  $("#sBtn").addEventListener("click", async () => {
    const id = $("#qId").value.trim();
    const pwd = $("#qPwd").value;
    const box = $("#stats");
    if (!id || !pwd) { box.textContent = "请填写追踪 ID 和访问密码"; box.classList.remove("hidden"); return; }
    try {
      const res = await fetch("/api/stats?id=" + encodeURIComponent(id) + "&password=" + encodeURIComponent(pwd));
      const d = await res.json();
      box.classList.remove("hidden");
      if (!res.ok || d.error) { box.innerHTML = '<span class="text-red-500">' + escapeHtml(d.error) + '</span>'; return; }
      box.innerHTML =
        '<span class="font-semibold text-slate-700">总访问</span> <b class="text-indigo-600">' + d.total + '</b> 次　·　' +
        '<span class="font-semibold text-slate-700">独立 IP</span> <b class="text-emerald-600">' + d.uniqueIps + '</b> 个　·　' +
        '<span class="font-semibold text-slate-700">最近一次</span> ' + (d.latestOpen ? fmtTime(d.latestOpen) : "无");
    } catch (e) {
      box.classList.remove("hidden");
      box.innerHTML = '<span class="text-red-500">统计失败</span>';
    }
  });

  const ipModal = $("#ipModal");
  const ipBody = $("#ipBody");
  let detailMap = null;
  function closeModal() { ipModal.classList.remove("on"); if (detailMap) { detailMap.remove(); detailMap = null; } }
  $("#ipClose").addEventListener("click", closeModal);
  ipModal.addEventListener("click", e => { if (e.target === ipModal) closeModal(); });

  function row(label, value, cls) {
    return '<div class="drow"><span>' + label + '</span><span class="' + (cls||"") + '">' +
      escapeHtml(value == null || value === "" ? "—" : String(value)) + '</span></div>';
  }

  async function openIpDetail(ip) {
    ipModal.classList.add("on");
    ipBody.innerHTML = '<div class="text-center py-10 text-slate-400"><i class="fa-solid fa-spinner fa-spin"></i></div>';

    let data = null;
    try {
      const res = await fetch("/api/ip?ip=" + encodeURIComponent(ip));
      data = await res.json().catch(() => null);
    } catch (e) { data = null; }

    if (!data) { ipBody.innerHTML = '<div class="text-[13px] text-red-500 py-6 text-center">网络异常</div>'; return; }
    if (data.error) { ipBody.innerHTML = '<div class="text-[13px] text-red-500 py-6 text-center">' + escapeHtml(data.error) + '</div>'; return; }

    const loc = data.location || {};
    const comp = data.company || {};
    const asn = data.asn || {};
    const dc = data.datacenter || {};
    const abuse = data.abuse || {};
    const cc = (loc.country_code || "").toLowerCase();
    const lat = loc.latitude, lon = loc.longitude;

    let riskText = "—", riskCls = "";
    if (typeof data.risk_score === "number") {
      riskText = data.risk_score.toFixed(1) + "%";
      riskCls = data.risk_score > 30 ? "text-red-600 font-bold" : "text-emerald-600 font-bold";
    }

    let h = "";
    h += '<div class="flex items-center gap-3 pb-3 border-b border-slate-100">';
    h += '<span class="ip-addr text-[15px] font-bold text-slate-800">' + escapeHtml(ip) + '</span>';
    if (cc) h += '<img src="https://ipdata.co/flags/' + cc + '.png" class="flag" style="width:28px;height:20px">';
    h += '</div>';

    h += '<div class="sect-title text-indigo-700"><i class="fa-solid fa-location-dot"></i>基本信息</div><div class="dgrid">';
    h += row("国家/地区", (loc.country || "") + (loc.country_code ? " (" + loc.country_code + ")" : ""));
    h += row("省/州", loc.state || "");
    h += row("城市", loc.city || "");
    h += row("时区", loc.timezone || "");
    h += row("经纬度", (lat && lon) ? (lat + ", " + lon) : "");
    h += '<div class="drow"><span>风险评分</span><span class="' + riskCls + '">' + riskText + '</span></div>';
    h += '</div>';

    h += '<div class="sect-title text-emerald-700"><i class="fa-solid fa-building"></i>运营商 / ASN</div><div class="dgrid">';
    h += row("运营商", comp.name || "");
    h += row("类型", comp.type || "");
    h += row("域名", comp.domain || "");
    h += row("ASN", asn.asn || "");
    h += row("ASN 描述", asn.descr || "");
    h += row("ASN 组织", asn.org || "");
    h += row("路由前缀", asn.route || "");
    h += row("ASN 国家", asn.country || "");
    h += '</div>';

    if (dc.datacenter) {
      h += '<div class="sect-title text-amber-700"><i class="fa-solid fa-cloud"></i>数据中心</div><div class="dgrid">';
      h += row("名称", dc.datacenter || "");
      h += row("服务商", dc.service || "");
      h += row("范围", dc.scope || "");
      h += row("网段", dc.network || "");
      h += '</div>';
    }
    if (abuse.email) {
      h += '<div class="sect-title text-red-600"><i class="fa-solid fa-triangle-exclamation"></i>滥用举报</div><div class="dgrid">';
      h += row("姓名", abuse.name || "");
      h += row("邮箱", abuse.email || "");
      h += row("电话", abuse.phone || "");
      h += row("地址", abuse.address || "");
      h += '</div>';
    }

    h += '<div class="sect-title text-purple-700"><i class="fa-solid fa-shield-halved"></i>安全检测</div><div class="dgrid">';
    h += row("数据中心", data.is_datacenter ? "是" : "否");
    h += row("代理", data.is_proxy ? "是" : "否");
    h += row("VPN", data.is_vpn ? "是" : "否");
    h += row("Tor", data.is_tor ? "是" : "否");
    h += row("爬虫", data.is_crawler ? "是" : "否");
    h += row("移动网络", data.is_mobile ? "是" : "否");
    h += row("卫星网络", data.is_satellite ? "是" : "否");
    h += row("已知滥用", data.is_abuser ? "是" : "否");
    h += '</div>';

    if (lat && lon) {
      h += '<div class="sect-title text-blue-700"><i class="fa-solid fa-map"></i>地理位置</div>';
      h += '<div id="ipDetailMap" class="mapbox"></div>';
    }

    ipBody.innerHTML = h;

    if (lat && lon) {
      setTimeout(() => {
        const el = document.getElementById("ipDetailMap");
        if (!el) return;
        try {
          if (detailMap) detailMap.remove();
          detailMap = L.map(el).setView([lat, lon], 9);
          L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "" }).addTo(detailMap);
          L.marker([lat, lon]).addTo(detailMap);
        } catch (e) {}
      }, 60);
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
<html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>邮件追踪器后台登录</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<style>
  *{-webkit-tap-highlight-color:transparent}
  body{margin:0;min-height:100vh;font-family:system-ui,-apple-system,sans-serif;
       background:radial-gradient(1000px 500px at 50% -15%,#e5eaff 0%,#f4f7fc 50%,#eef2f8 100%);
       display:flex;align-items:center;justify-content:center;padding:20px}
  .box{width:100%;max-width:380px;background:#fff;border:1px solid #e9edf5;border-radius:22px;
       box-shadow:0 18px 50px -22px rgba(15,23,42,.28);padding:32px 28px}
  .fld{width:100%;border:1px solid #dfe5f0;border-radius:12px;padding:11px 14px;font-size:14px;outline:none;background:#fbfcfe;transition:.18s}
  .fld:focus{border-color:#6366f1;background:#fff;box-shadow:0 0 0 3px rgba(99,102,241,.12)}
  .btn{width:100%;background:#4f46e5;color:#fff;border:none;border-radius:12px;padding:11px;font-size:14px;font-weight:600;cursor:pointer;transition:.16s}
  .btn:hover{background:#4338ca}.btn:disabled{opacity:.6;cursor:not-allowed}
  .msg{margin-top:12px;font-size:12.5px;color:#dc2626}
</style></head><body>
<div class="box">
  <div class="flex items-center gap-3 mb-6">
    <div class="w-11 h-11 rounded-2xl bg-indigo-50 flex items-center justify-center">
      <i class="fa-solid fa-lock text-indigo-600"></i>
    </div>
    <div><h1 class="text-[17px] font-bold">邮件追踪器后台登录</h1><p class="text-[11.5px] text-slate-400 mt-0.5">请输入管理员密码以继续</p></div>
  </div>
  <label class="block text-[12.5px] font-semibold text-slate-600 mb-1.5">管理员密码</label>
  <input id="pwd" type="password" class="fld" placeholder="请输入密码" autocomplete="current-password">
  <button id="btn" class="btn mt-4">登 录</button>
  <p id="msg" class="msg hidden"></p>
  <div class="mt-6 pt-5 border-t border-slate-100 text-center text-[11px] text-slate-400">Copyright © 2026 SAK All rights reserved.</div>
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
  const totalBurned = await env.DB.prepare("SELECT COUNT(*) AS c FROM tracking_logs WHERE burned = 1").first();
  const uniqueIps = await env.DB.prepare("SELECT COUNT(DISTINCT ip) AS c FROM tracking_logs WHERE (burned IS NULL OR burned = 0)").first();

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

  function isPrivate(ip) {
    if (!ip) return false;
    const s = String(ip).trim();
    if (!s) return false;
    if (s.includes(":")) {
      const l = s.toLowerCase();
      return l === "::1" || l.startsWith("fc") || l.startsWith("fd") ||
        l.startsWith("fe8") || l.startsWith("fe9") || l.startsWith("fea") || l.startsWith("feb");
    }
    const p = s.split(".").map(Number);
    if (p.length !== 4 || p.some(n => isNaN(n))) return false;
    return p[0] === 10 || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
      (p[0] === 192 && p[1] === 168) || p[0] === 127 || (p[0] === 169 && p[1] === 254);
  }

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
    const flag = cc ? `<img src="https://ipdata.co/flags/${cc}.png" class="flag" style="width:16px;height:11px" alt="">` : "";
    const localBadge = isLocal ? '<span class="local-badge">本地</span>' : "";
    const burnedBadge = Number(r.burned) === 1 ? '<span class="burned-badge">用户已删除</span>' : "";

    logRows += `<tr class="border-b border-slate-100 hover:bg-slate-50/70 align-top">
      <td class="p-2"><input type="checkbox" class="log-check" data-target-id="${esc(r.target_id)}"></td>
      <td class="p-2 text-[11.5px] font-mono whitespace-nowrap">${esc(r.target_id)}</td>
      <td class="p-2 text-[11.5px] text-slate-500 whitespace-nowrap">${esc(date)}</td>
      <td class="p-2 text-[11.5px] max-w-[200px]">
        <div class="flex flex-wrap items-center gap-1">
          <span class="ip-addr">${esc(r.ip || "")}</span>${flag}${localBadge}${burnedBadge}
          <button class="ip-detail text-indigo-500 hover:text-indigo-700 text-[11px] underline" data-ip="${esc(r.ip || "")}">查询</button>
        </div>
      </td>
      <td class="p-2 text-[11.5px] text-slate-600 max-w-[180px] break-words">${esc(geo)}</td>
      <td class="p-2 text-[11.5px] text-slate-500 max-w-[180px] break-all">${esc(r.ua || "")}</td>
      <td class="p-2 whitespace-nowrap">
        <button class="del-log text-red-500 hover:text-red-700 text-[11px] underline" data-id="${r.id}">删除</button>
      </td>
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
          const priv = arr.filter(x => x && isPrivate(x));
          const pub = arr.filter(x => x && !isPrivate(x));
          let parts = [];
          if (priv.length) {
            parts.push(priv.map(ip =>
              `<span class="text-blue-600 font-mono text-[11px] mr-1">内网: ${esc(ip)}</span>` +
              `<button class="ip-detail text-indigo-500 hover:text-indigo-700 text-[11px] underline mr-2" data-ip="${esc(ip)}">查询</button>`
            ).join(""));
          }
          if (pub.length) {
            parts.push(pub.map(ip =>
              `<span class="text-purple-600 font-mono text-[11px] mr-1">公网: ${esc(ip)}</span>` +
              `<button class="ip-detail text-indigo-500 hover:text-indigo-700 text-[11px] underline mr-2" data-ip="${esc(ip)}">查询</button>`
            ).join(""));
          }
          webrtcHtml = parts.join("<br>") || "—";
        }
      } catch (e) {}
    }

    let fpId = "—";
    if (info.creator_fingerprint) {
      try { const fp = JSON.parse(info.creator_fingerprint); if (fp && fp.visitorId) fpId = fp.visitorId.slice(0, 14) + "…"; } catch(e){}
    }
    const typeLabel = info.image_type === "video" ? "视频" : (info.image_type === "image" ? "图片" : "1x1像素");

    creatorRows += `<tr class="border-b border-slate-100 hover:bg-slate-50/70 align-top">
      <td class="p-2"><input type="checkbox" class="creator-check" data-creator-id="${esc(id)}"></td>
      <td class="p-2 text-[11.5px] font-mono whitespace-nowrap">${esc(id)}<div class="text-[10px] text-slate-400">${typeLabel}</div></td>
      <td class="p-2 text-[11.5px]">
        <div class="flex flex-wrap items-center gap-1">
          <span class="ip-addr">${esc(creatorIp)}</span>
          <button class="ip-detail text-indigo-500 hover:text-indigo-700 text-[11px] underline" data-ip="${esc(creatorIp)}">查询</button>
        </div>
      </td>
      <td class="p-2 text-[11.5px] text-slate-500 max-w-[180px] break-all">${esc(info.creator_ua || "")}</td>
      <td class="p-2 text-[11.5px] max-w-[260px]">${webrtcHtml}</td>
      <td class="p-2 text-[11.5px] font-mono text-slate-500">${esc(fpId)}</td>
      <td class="p-2 whitespace-nowrap">
        <button class="del-target text-red-500 hover:text-red-700 text-[11px] underline" data-id="${esc(id)}">删除</button>
      </td>
    </tr>`;
  }

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>后台管理</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<style>
  *{-webkit-tap-highlight-color:transparent}
  body{margin:0;background:#f6f8fc;font-family:system-ui,-apple-system,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;color:#0f172a}
  .card{background:#fff;border:1px solid #e9edf5;border-radius:18px;box-shadow:0 4px 22px -12px rgba(15,23,42,.12)}
  .stat{flex:1 1 130px;min-width:130px;background:#fff;border:1px solid #e9edf5;border-radius:16px;padding:16px;text-align:center}
  .btn{display:inline-flex;align-items:center;gap:5px;font-size:12.5px;font-weight:600;border:none;border-radius:10px;padding:8px 14px;cursor:pointer;transition:.15s}
  .btn:active{transform:translateY(1px)}
  .btn-danger{background:#fee2e2;color:#b91c1c}.btn-danger:hover{background:#fecaca}
  .btn-dark{background:#fef3c7;color:#92400e}.btn-dark:hover{background:#fde68a}
  .btn-soft{background:#eef2ff;color:#4338ca}.btn-soft:hover{background:#e0e7ff}
  .ip-addr{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all;overflow-wrap:anywhere}
  .local-badge{background:#fef3c7;color:#92400e;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700;white-space:nowrap}
  .burned-badge{background:#fee2e2;color:#991b1b;padding:1px 7px;border-radius:999px;font-size:10px;font-weight:700;white-space:nowrap}
  .flag{border-radius:2px;box-shadow:0 1px 3px rgba(0,0,0,.18);vertical-align:-1px}
  table{border-collapse:collapse;width:100%}
  th{background:#f8fafc;font-size:11.5px;font-weight:700;color:#64748b;text-align:left;padding:9px 8px;white-space:nowrap}
  /* 关键修复：弹窗 z-index 高于 Leaflet 地图，避免地图遮挡弹窗 */
  .modal{position:fixed;inset:0;background:rgba(15,23,42,.55);backdrop-filter:blur(3px);display:none;align-items:center;justify-content:center;padding:14px;z-index:9999}
  .modal.on{display:flex}
  .modal-box{background:#fff;border-radius:18px;width:100%;max-width:620px;max-height:88vh;overflow:auto;position:relative;z-index:1}
  .dgrid{display:grid;grid-template-columns:1fr}
  @media(min-width:520px){.dgrid{grid-template-columns:1fr 1fr;gap:0 16px}}
  .drow{display:flex;justify-content:space-between;gap:12px;padding:6px 0;border-bottom:1px dashed #eef2f8;font-size:13px}
  .drow span:first-child{color:#64748b;flex-shrink:0}
  .drow span:last-child{text-align:right;word-break:break-word;font-weight:500;min-width:0}
  .mapbox{height:260px;width:100%;border-radius:12px;border:1px solid #e6ebf3;margin-top:8px}
  .sect-title{font-size:13px;font-weight:700;margin:14px 0 6px;display:flex;align-items:center;gap:6px}
</style>
</head>
<body class="p-3 sm:p-5">
<div class="max-w-7xl mx-auto space-y-4">

  <div class="flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-lg font-bold flex items-center gap-2">
      <i class="fa-solid fa-gauge-high text-indigo-600"></i>后台管理
    </h1>
    <div class="flex gap-2">
      <a href="/" class="btn btn-soft"><i class="fa-solid fa-house"></i> 返回首页</a>
      <button id="logoutBtn" class="btn btn-danger"><i class="fa-solid fa-right-from-bracket"></i> 退出登录</button>
    </div>
  </div>

  <div class="flex flex-wrap gap-3">
    <div class="stat"><div class="text-2xl font-bold text-indigo-600">${totalTargets ? totalTargets.c : 0}</div><div class="text-[11.5px] text-slate-500 mt-1">追踪 ID 总数</div></div>
    <div class="stat"><div class="text-2xl font-bold text-emerald-600">${totalLogs ? totalLogs.c : 0}</div><div class="text-[11.5px] text-slate-500 mt-1">总访问次数</div></div>
    <div class="stat"><div class="text-2xl font-bold text-red-600">${totalBurned ? totalBurned.c : 0}</div><div class="text-[11.5px] text-slate-500 mt-1">用户已删除</div></div>
    <div class="stat"><div class="text-2xl font-bold text-amber-600">${uniqueIps ? uniqueIps.c : 0}</div><div class="text-[11.5px] text-slate-500 mt-1">独立 IP</div></div>
  </div>

  <div class="card p-4">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
      <h2 class="font-bold text-[15px]"><i class="fa-solid fa-list-ul text-indigo-500 mr-1.5"></i>访问日志（含已删除）</h2>
      <div class="flex flex-wrap gap-2">
        <input id="filterInput" value="${esc(filter)}" placeholder="按追踪 ID 过滤"
               class="border border-slate-200 rounded-xl px-3 py-1.5 text-[12.5px] outline-none focus:border-indigo-400">
        <button id="filterBtn" class="btn btn-soft">筛选</button>
        <button id="delSelected" class="btn btn-dark">删除选中 ID</button>
        <button id="clearLogs" class="btn btn-danger">清空日志</button>
        <button id="clearAll" class="btn btn-danger">清空全部</button>
      </div>
    </div>
    <div class="overflow-x-auto">
      <table>
        <thead><tr>
          <th style="width:32px"><input type="checkbox" id="checkAllLogs"></th>
          <th>ID</th><th>时间</th><th>IP</th><th>地理位置</th><th>User-Agent</th><th>操作</th>
        </tr></thead>
        <tbody>${logRows || '<tr><td colspan="7" class="p-6 text-center text-slate-400 text-[13px]">暂无记录</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <div class="card p-4">
    <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
      <h2 class="font-bold text-[15px]"><i class="fa-solid fa-user-secret text-emerald-500 mr-1.5"></i>追踪 ID 创建者信息</h2>
      <button id="delCreators" class="btn btn-dark">删除选中创建者</button>
    </div>
    <div class="overflow-x-auto">
      <table>
        <thead><tr>
          <th style="width:32px"><input type="checkbox" id="checkAllCreators"></th>
          <th>ID</th><th>创建 IP</th><th>UA</th><th>WebRTC 泄露 IP</th><th>指纹 ID</th><th>操作</th>
        </tr></thead>
        <tbody>${creatorRows || '<tr><td colspan="7" class="p-6 text-center text-slate-400 text-[13px]">暂无数据</td></tr>'}</tbody>
      </table>
    </div>
  </div>

  <footer class="text-center text-[11.5px] text-slate-400 py-5 leading-relaxed space-y-1">
    <div>Copyright © 2026 SAK All rights reserved.</div>
    <div class="break-words px-2">
      QQ:3344310554 · E-mail:cnzz666@163.com ·
      <a href="https://b23.tv/8fCttY7" target="_blank" rel="noopener noreferrer" class="text-indigo-500">Bilibili:SAK_CN</a>
    </div>
  </footer>
</div>

<div id="ipModal" class="modal">
  <div class="modal-box">
    <div class="flex items-center justify-between px-5 py-4 border-b border-slate-100 sticky top-0 bg-white rounded-t-2xl">
      <h3 class="font-bold text-[15px]"><i class="fa-solid fa-circle-info text-indigo-500 mr-2"></i>IP 详细信息</h3>
      <button id="ipClose" class="text-slate-400 hover:text-red-500 text-2xl leading-none px-1">&times;</button>
    </div>
    <div id="ipBody" class="px-5 py-4"></div>
  </div>
</div>

<script>
(function () {
  const $ = s => document.querySelector(s);
  const $$ = s => Array.from(document.querySelectorAll(s));
  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  $("#logoutBtn").addEventListener("click", async () => {
    await fetch("/api/admin/logout", { method: "POST" });
    location.href = "/admin";
  });

  $("#checkAllLogs").addEventListener("change", function () {
    $$(".log-check").forEach(cb => cb.checked = this.checked);
  });
  $("#checkAllCreators").addEventListener("change", function () {
    $$(".creator-check").forEach(cb => cb.checked = this.checked);
  });

  async function post(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: body ? { "Content-Type": "application/json" } : {},
      body: body ? JSON.stringify(body) : undefined
    });
    return res.ok;
  }

  document.addEventListener("click", async e => {
    const delLog = e.target.closest(".del-log");
    if (delLog) {
      if (!confirm("永久删除这条访问记录？")) return;
      if (await post("/api/admin/delete", { id: parseInt(delLog.dataset.id, 10) })) location.reload();
      else alert("删除失败");
      return;
    }
    const delTarget = e.target.closest(".del-target");
    if (delTarget) {
      if (!confirm("删除该追踪 ID 及其全部访问记录？")) return;
      if (await post("/api/admin/delete-target", { id: delTarget.dataset.id })) location.reload();
      else alert("删除失败");
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
    if (await post("/api/admin/delete-targets", { ids })) location.reload();
    else alert("删除失败");
  });

  $("#delCreators").addEventListener("click", async () => {
    const ids = $$(".creator-check:checked").map(cb => cb.dataset.creatorId);
    if (!ids.length) { alert("请先勾选要删除的创建者"); return; }
    if (!confirm("确认删除选中的 " + ids.length + " 个创建者及其全部日志？")) return;
    if (await post("/api/admin/delete-targets", { ids })) location.reload();
    else alert("删除失败");
  });

  $("#clearLogs").addEventListener("click", async () => {
    if (!confirm("确认清空全部访问日志？（追踪 ID 会保留）")) return;
    if (await post("/api/admin/clear")) location.reload();
    else alert("操作失败");
  });

  $("#clearAll").addEventListener("click", async () => {
    if (!confirm("确认清空全部追踪 ID 及日志？此操作不可恢复！")) return;
    if (await post("/api/admin/clear-targets")) location.reload();
    else alert("操作失败");
  });

  $("#filterBtn").addEventListener("click", () => {
    const v = $("#filterInput").value.trim();
    location.href = "/admin" + (v ? "?filter_id=" + encodeURIComponent(v) : "");
  });
  $("#filterInput").addEventListener("keydown", e => { if (e.key === "Enter") $("#filterBtn").click(); });

  const modal = $("#ipModal");
  const body = $("#ipBody");
  let dmap = null;
  function closeModal() {
    modal.classList.remove("on");
    if (dmap) { dmap.remove(); dmap = null; }
  }
  $("#ipClose").addEventListener("click", closeModal);
  modal.addEventListener("click", e => { if (e.target === modal) closeModal(); });

  function row(label, value, cls) {
    return '<div class="drow"><span>' + label + '</span><span class="' + (cls || "") + '">' +
      esc(value == null || value === "" ? "—" : String(value)) + '</span></div>';
  }

  async function openIpDetail(ip) {
    modal.classList.add("on");
    body.innerHTML = '<div class="text-center py-10 text-slate-400"><i class="fa-solid fa-spinner fa-spin"></i></div>';

    let data = null;
    try {
      const res = await fetch("/api/ip?ip=" + encodeURIComponent(ip));
      data = await res.json().catch(() => null);
    } catch (e) { data = null; }

    if (!data) { body.innerHTML = '<div class="text-[13px] text-red-500 py-6 text-center">网络异常</div>'; return; }
    if (data.error) { body.innerHTML = '<div class="text-[13px] text-red-500 py-6 text-center">' + esc(data.error) + '</div>'; return; }

    const loc = data.location || {};
    const comp = data.company || {};
    const asn = data.asn || {};
    const dc = data.datacenter || {};
    const abuse = data.abuse || {};
    const cc = (loc.country_code || "").toLowerCase();
    const lat = loc.latitude, lon = loc.longitude;

    let riskText = "—", riskCls = "";
    if (typeof data.risk_score === "number") {
      riskText = data.risk_score.toFixed(1) + "%";
      riskCls = data.risk_score > 30 ? "text-red-600 font-bold" : "text-emerald-600 font-bold";
    }

    let h = "";
    h += '<div class="flex items-center gap-3 pb-3 border-b border-slate-100">';
    h += '<span class="ip-addr text-[15px] font-bold text-slate-800">' + esc(ip) + '</span>';
    if (cc) h += '<img src="https://ipdata.co/flags/' + cc + '.png" class="flag" style="width:28px;height:20px">';
    h += '</div>';

    h += '<div class="sect-title text-indigo-700"><i class="fa-solid fa-location-dot"></i>基本信息</div><div class="dgrid">';
    h += row("国家/地区", (loc.country || "") + (loc.country_code ? " (" + loc.country_code + ")" : ""));
    h += row("省/州", loc.state || "");
    h += row("城市", loc.city || "");
    h += row("时区", loc.timezone || "");
    h += row("经纬度", (lat && lon) ? (lat + ", " + lon) : "");
    h += '<div class="drow"><span>风险评分</span><span class="' + riskCls + '">' + riskText + '</span></div>';
    h += '</div>';

    h += '<div class="sect-title text-emerald-700"><i class="fa-solid fa-building"></i>运营商 / ASN</div><div class="dgrid">';
    h += row("运营商", comp.name || "");
    h += row("类型", comp.type || "");
    h += row("域名", comp.domain || "");
    h += row("ASN", asn.asn || "");
    h += row("ASN 描述", asn.descr || "");
    h += row("ASN 组织", asn.org || "");
    h += row("路由前缀", asn.route || "");
    h += row("ASN 国家", asn.country || "");
    h += '</div>';

    if (dc.datacenter) {
      h += '<div class="sect-title text-amber-700"><i class="fa-solid fa-cloud"></i>数据中心</div><div class="dgrid">';
      h += row("名称", dc.datacenter || "");
      h += row("服务商", dc.service || "");
      h += row("范围", dc.scope || "");
      h += row("网段", dc.network || "");
      h += '</div>';
    }
    if (abuse.email) {
      h += '<div class="sect-title text-red-600"><i class="fa-solid fa-triangle-exclamation"></i>滥用举报</div><div class="dgrid">';
      h += row("姓名", abuse.name || "");
      h += row("邮箱", abuse.email || "");
      h += row("电话", abuse.phone || "");
      h += row("地址", abuse.address || "");
      h += '</div>';
    }

    h += '<div class="sect-title text-purple-700"><i class="fa-solid fa-shield-halved"></i>安全检测</div><div class="dgrid">';
    h += row("数据中心", data.is_datacenter ? "是" : "否");
    h += row("代理", data.is_proxy ? "是" : "否");
    h += row("VPN", data.is_vpn ? "是" : "否");
    h += row("Tor", data.is_tor ? "是" : "否");
    h += row("爬虫", data.is_crawler ? "是" : "否");
    h += row("移动网络", data.is_mobile ? "是" : "否");
    h += row("卫星网络", data.is_satellite ? "是" : "否");
    h += row("已知滥用", data.is_abuser ? "是" : "否");
    h += '</div>';

    if (lat && lon) {
      h += '<div class="sect-title text-blue-700"><i class="fa-solid fa-map"></i>地理位置</div>';
      h += '<div id="adminMap" class="mapbox"></div>';
    }
    body.innerHTML = h;

    if (lat && lon) {
      setTimeout(() => {
        const el = document.getElementById("adminMap");
        if (!el) return;
        try {
          if (dmap) dmap.remove();
          dmap = L.map(el).setView([lat, lon], 9);
          L.tileLayer("/tile/{z}/{x}/{y}.png", { maxZoom: 18, attribution: "" }).addTo(dmap);
          L.marker([lat, lon]).addTo(dmap);
        } catch (e) {}
      }, 60);
    }
  }
})();
<\/script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}