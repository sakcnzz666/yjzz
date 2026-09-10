// @ts-nocheck
// Cloudflare Worker 邮件追踪器

const IMAGE_HOST = "https://tc.ilqx.dpdns.org";
const IMAGE_UPLOAD_PATH = "/upload";
const MAX_UPLOAD_SIZE = 5 * 1024 * 1024; // 5MB
const ALLOWED_IMAGE_TYPES = ['image/jpeg','image/png','image/gif','image/webp','image/bmp','image/svg+xml','image/avif'];
const ALLOWED_VIDEO_TYPES = ['video/mp4','video/webm','video/ogg','video/quicktime','video/x-msvideo','video/x-matroska'];

let DB_INIT_CACHE = false; // 内存缓存，已初始化则跳过检查

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ============ 1. 环境变量检查 ============
    const hasAdmin = typeof env.ADMIN === 'string' && env.ADMIN.trim().length > 0;
    const hasIPKey = typeof env.IPAPI_KEY === 'string' && env.IPAPI_KEY.trim().length > 0;

    // ============ 2. D1 数据库检查 ============
    let hasDB = false;
    let dbError = null;
    if (env.DB) {
      try {
        await env.DB.prepare("SELECT 1 AS ok").first();
        hasDB = true;
      } catch (e) {
        dbError = "D1 数据库访问失败: " + (e.message || String(e));
      }
    } else {
      dbError = "未绑定 D1 数据库（绑定变量名必须为 DB）";
    }

    // ============ 3. 数据库初始化状态检查 ============
    let needsInit = false;
    if (hasDB && !DB_INIT_CACHE) {
      try {
        const row = await env.DB.prepare(
          "SELECT name FROM sqlite_master WHERE type='table' AND name='targets'"
        ).first();
        needsInit = !row;
        if (row) DB_INIT_CACHE = true;
      } catch (e) {
        dbError = "D1 初始化检测失败: " + (e.message || String(e));
        hasDB = false;
      }
    }

    // ============ 4. 配置不完整 → 显示配置检查页 ============
    if (!hasAdmin || !hasDB) {
      return renderSetupPage(hasAdmin, hasDB, hasIPKey, dbError);
    }

    // ============ 5. 数据库未初始化 → 显示部署页 ============
    if (needsInit) {
      if (path === "/api/init" && request.method === "POST") {
        try {
          await initDB(env);
          DB_INIT_CACHE = true;
          return jsonResponse({ success: true });
        } catch (e) {
          return jsonResponse({ error: e.message || String(e) }, 500);
        }
      }
      return renderDeployPage();
    }

    // ============ 6. 正常路由 ============
    if (path === "/" || path === "/index.html") return renderHome(request, env);
    if (path.startsWith("/pixel/")) {
      const id = path.split("/")[2];
      if (!id) return notFound();
      return handlePixel(request, env, ctx, id);
    }
    if (path === "/api/config") return handleConfig(env);
    if (path === "/api/generate") return handleGenerate(request, env);
    if (path === "/api/query") return handleQuery(request, env);
    if (path === "/api/stats") return handleStats(request, env);
    if (path === "/api/admin/delete") return handleAdminDelete(request, env);
    if (path === "/api/admin/clear") return handleAdminClear(request, env);
    if (path === "/api/admin/delete-target") return handleAdminDeleteTarget(request, env);
    if (path === "/api/admin/delete-targets") return handleAdminDeleteTargets(request, env);
    if (path === "/api/admin/clear-targets") return handleAdminClearTargets(request, env);
    if (path === "/api/admin/delete-creators") return handleAdminDeleteCreators(request, env);
    if (path === "/admin/logout") return handleAdminLogout(request, env);
    if (path === "/admin") return renderAdmin(request, env);
    if (path.match(/^\/tile\/\d+\/\d+\/\d+\.png$/)) return handleTile(request);
    return notFound();
  }
};

function notFound() {
  return new Response("Not Found", { status: 404 });
}

// ---------- 配置检查页 ----------
function renderSetupPage(hasAdmin, hasDB, hasIPKey, dbError) {
  const checkIcon = (ok) => ok
    ? '<div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-green-500 text-white font-bold text-lg">✓</div>'
    : '<div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-red-500 text-white font-bold text-lg">✗</div>';

  const html = `<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>配置检查</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;}
  .glass{background:rgba(255,255,255,0.96);backdrop-filter:blur(20px);}
  code{background:#f3f4f6;padding:1px 6px;border-radius:4px;font-size:0.85em;}
</style>
</head>
<body class="flex items-center justify-center p-4">
<div class="glass rounded-3xl shadow-2xl p-8 w-full max-w-2xl">
  <div class="text-center mb-6">
    <div class="inline-flex items-center justify-center w-20 h-20 bg-amber-100 rounded-3xl mb-4">
      <span class="text-4xl">⚙️</span>
    </div>
    <h1 class="text-2xl font-bold text-gray-800">配置检查</h1>
    <p class="text-sm text-gray-500 mt-1">请先完成以下配置，否则无法使用</p>
  </div>

  <!-- ADMIN -->
  <div class="flex items-start gap-3 p-4 rounded-2xl border-2 ${hasAdmin ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'} mb-3">
    ${checkIcon(hasAdmin)}
    <div class="flex-1 min-w-0">
      <div class="font-bold text-gray-800">ADMIN 环境变量（必填）</div>
      <div class="text-sm mt-1 ${hasAdmin ? 'text-green-700' : 'text-red-700'}">${hasAdmin ? '已配置 ✓' : '未配置 ✗'}</div>
      ${!hasAdmin ? `
      <div class="text-xs text-gray-700 mt-3 bg-white rounded-xl p-3 border">
        <p class="font-semibold mb-2">配置步骤：</p>
        <ol class="list-decimal list-inside space-y-1 leading-relaxed">
          <li>Cloudflare Dashboard → Workers &amp; Pages</li>
          <li>选择你的 Worker → <b>Settings</b> → <b>Variables and Secrets</b></li>
          <li>点击 <b>Add</b>，名称填 <code>ADMIN</code>，值为你的管理员密码</li>
          <li>类型选 <b>Text</b> 或 <b>Secret</b>，保存</li>
          <li><b class="text-red-600">⚠️ 回到 Worker 编辑页，点击一次 Save and Deploy（关键！变量需要重新部署才生效）</b></li>
        </ol>
      </div>` : ''}
    </div>
  </div>

  <!-- DB -->
  <div class="flex items-start gap-3 p-4 rounded-2xl border-2 ${hasDB ? 'border-green-200 bg-green-50' : 'border-red-200 bg-red-50'} mb-3">
    ${checkIcon(hasDB)}
    <div class="flex-1 min-w-0">
      <div class="font-bold text-gray-800">D1 数据库绑定（必填）</div>
      <div class="text-sm mt-1 ${hasDB ? 'text-green-700' : 'text-red-700'}">${hasDB ? '已绑定 ✓' : '未绑定 ✗'}</div>
      ${dbError ? `<div class="text-xs text-red-600 mt-1 break-all">${dbError}</div>` : ''}
      ${!hasDB ? `
      <div class="text-xs text-gray-700 mt-3 bg-white rounded-xl p-3 border">
        <p class="font-semibold mb-2">配置步骤：</p>
        <ol class="list-decimal list-inside space-y-1 leading-relaxed">
          <li>Cloudflare Dashboard → <b>Workers &amp; Pages</b> → <b>D1</b></li>
          <li>点击 <b>Create database</b> 创建一个新的数据库</li>
          <li>回到你的 Worker → <b>Settings</b> → <b>Bindings</b>（绑定）</li>
          <li>点击 <b>Add binding</b> → 选择 <b>D1 database</b></li>
          <li>变量名必须填 <code>DB</code>（大写），选择刚才创建的数据库，保存</li>
          <li><b class="text-red-600">⚠️ 重新部署 Worker 后刷新本页</b></li>
        </ol>
      </div>` : ''}
    </div>
  </div>

  <!-- IPAPI_KEY（可选） -->
  <div class="flex items-start gap-3 p-4 rounded-2xl border-2 ${hasIPKey ? 'border-green-200 bg-green-50' : 'border-blue-200 bg-blue-50'} mb-3">
    ${hasIPKey
      ? '<div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-green-500 text-white font-bold text-lg">✓</div>'
      : '<div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-blue-500 text-white font-bold text-lg">i</div>'}
    <div class="flex-1 min-w-0">
      <div class="font-bold text-gray-800">IPAPI_KEY 环境变量 <span class="text-xs font-normal text-gray-500">（可选）</span></div>
      <div class="text-sm mt-1 ${hasIPKey ? 'text-green-700' : 'text-blue-700'}">${hasIPKey ? '已配置 ✓' : '未配置，IP 详情功能可能受限'}</div>
      <div class="text-xs text-gray-500 mt-1">变量名 <code>IPAPI_KEY</code>，用于 ipapi.is 查询 IP 详细信息，不填也能用。</div>
    </div>
  </div>

  <div class="mt-6 text-center">
    <button onclick="location.reload(true)" class="bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-3 px-8 rounded-xl transition">🔄 重新检查</button>
  </div>

  <div class="mt-6 pt-4 border-t text-center text-xs text-gray-400 leading-relaxed">
    Copyright © 2026 <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK</a> All rights reserved.<br>
    QQ: 3344310554 · E-mail: <a href="mailto:cnzz666@163.com" class="hover:text-indigo-500">cnzz666@163.com</a> · Bilibili: <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK _CN</a>
  </div>
</div>
</body></html>`;
  return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// ---------- 部署确认页 ----------
function renderDeployPage() {
  const html = `<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>准备就绪</title>
<script src="https://cdn.tailwindcss.com"></script>
<style>
  body{background:linear-gradient(135deg,#10b981 0%,#059669 100%);min-height:100vh;}
  .glass{background:rgba(255,255,255,0.96);backdrop-filter:blur(20px);}
  @keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,0.7);}50%{box-shadow:0 0 0 18px rgba(34,197,94,0);}}
  .pulse-btn{animation:pulse 2s infinite;}
</style>
</head>
<body class="flex items-center justify-center p-4">
<div class="glass rounded-3xl shadow-2xl p-8 w-full max-w-2xl">
  <div class="text-center mb-6">
    <div class="inline-flex items-center justify-center w-20 h-20 bg-green-100 rounded-full mb-4">
      <span class="text-4xl">🎉</span>
    </div>
    <h1 class="text-3xl font-bold text-gray-800">环境检查通过</h1>
    <p class="text-sm text-gray-500 mt-2">所有配置已就绪，点击下方按钮初始化数据库</p>
  </div>

  <div class="space-y-3 mb-6">
    <div class="flex items-center gap-3 p-4 rounded-2xl border-2 border-green-200 bg-green-50">
      <div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-green-500 text-white font-bold text-lg">✓</div>
      <div class="flex-1 font-medium text-gray-800">ADMIN 环境变量已配置</div>
    </div>
    <div class="flex items-center gap-3 p-4 rounded-2xl border-2 border-green-200 bg-green-50">
      <div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-green-500 text-white font-bold text-lg">✓</div>
      <div class="flex-1 font-medium text-gray-800">D1 数据库已绑定</div>
    </div>
    <div class="flex items-center gap-3 p-4 rounded-2xl border-2 border-amber-200 bg-amber-50">
      <div class="flex-shrink-0 w-9 h-9 rounded-full flex items-center justify-center bg-amber-500 text-white font-bold text-lg">!</div>
      <div class="flex-1 font-medium text-gray-800">数据库尚未初始化（点击下方按钮完成）</div>
    </div>
  </div>

  <button id="deployBtn" class="pulse-btn w-full text-white font-bold py-4 px-6 rounded-2xl text-lg transition" style="background:linear-gradient(135deg,#10b981,#059669);">
    🚀 开始部署
  </button>
  <div id="deployStatus" class="mt-4 text-center hidden text-sm"></div>

  <div class="mt-6 pt-4 border-t text-center text-xs text-gray-400 leading-relaxed">
    Copyright © 2026 <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK</a> All rights reserved.<br>
    QQ: 3344310554 · E-mail: <a href="mailto:cnzz666@163.com" class="hover:text-indigo-500">cnzz666@163.com</a> · Bilibili: <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK _CN</a>
  </div>
</div>
<script>
document.getElementById('deployBtn').addEventListener('click', async function(){
  const btn = this;
  const status = document.getElementById('deployStatus');
  btn.disabled = true;
  btn.textContent = '⏳ 部署中...';
  try{
    const res = await fetch('/api/init', { method: 'POST' });
    const data = await res.json();
    if(data.success){
      btn.textContent = '✅ 部署成功，正在跳转...';
      btn.style.background = 'linear-gradient(135deg,#22c55e,#16a34a)';
      status.innerHTML = '<span class="text-green-600">初始化完成，即将进入首页…</span>';
      status.classList.remove('hidden');
      setTimeout(()=>{ location.href = '/'; }, 900);
    } else {
      status.innerHTML = '<span class="text-red-500">部署失败: ' + (data.error || '未知错误') + '</span>';
      status.classList.remove('hidden');
      btn.disabled = false;
      btn.textContent = '🚀 重试部署';
    }
  }catch(e){
    status.innerHTML = '<span class="text-red-500">请求失败: ' + e.message + '</span>';
    status.classList.remove('hidden');
    btn.disabled = false;
    btn.textContent = '🚀 重试部署';
  }
});
</script>
</body></html>`;
  return new Response(html, { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// ---------- 数据库初始化 ----------
async function initDB(env) {
  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS targets (
      id TEXT PRIMARY KEY,
      media_type TEXT DEFAULT 'pixel',
      media_url TEXT,
      password_hash TEXT,
      creator_ip TEXT,
      creator_ua TEXT,
      creator_webrtc_ips TEXT,
      creator_fingerprint TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

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

  await env.DB.prepare(`
    CREATE TABLE IF NOT EXISTS admin_sessions (
      token TEXT PRIMARY KEY,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `).run();

  const logColumns = [
    "country_code","region","city","timezone","isp","org",
    "as_text","referer","accept","accept_encoding",
    "sec_ch_ua","sec_ch_ua_platform","sec_ch_ua_mobile"
  ];
  for (const col of logColumns) {
    try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN ${col} TEXT`).run(); } catch (e) {}
  }
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lat REAL`).run(); } catch(e) {}
  try { await env.DB.prepare(`ALTER TABLE tracking_logs ADD COLUMN lon REAL`).run(); } catch(e) {}

  const targetColumns = [
    "media_type","media_url","password_hash","creator_ip",
    "creator_ua","creator_webrtc_ips","creator_fingerprint"
  ];
  for (const col of targetColumns) {
    try { await env.DB.prepare(`ALTER TABLE targets ADD COLUMN ${col} TEXT DEFAULT ''`).run(); } catch (e) {}
  }
}

// ---------- 工具函数 ----------
function generateShortId() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  return Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join('');
}

function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function sha256(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" }
  });
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

function isImageType(file) {
  if (!file || !file.type) return false;
  return ALLOWED_IMAGE_TYPES.includes(file.type.toLowerCase());
}

function isVideoType(file) {
  if (!file || !file.type) return false;
  return ALLOWED_VIDEO_TYPES.includes(file.type.toLowerCase());
}

async function getIpInfo(ip) {
  if (!ip || ip === "Unknown" || ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
    return null;
  }
  try {
    const resp = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`);
    if (!resp.ok) return null;
    const data = await resp.json();
    if (data.status === "success") {
      return {
        country: data.country || "",
        countryCode: data.countryCode || "",
        region: data.regionName || "",
        city: data.city || "",
        timezone: data.timezone || "",
        isp: data.isp || "",
        org: data.org || "",
        as_text: data.as || "",
        lat: data.lat || null,
        lon: data.lon || null
      };
    }
    return null;
  } catch {
    return null;
  }
}

async function uploadImageToHost(file) {
  const formData = new FormData();
  formData.append("file", file, file.name || "file");
  const resp = await fetch(IMAGE_HOST + IMAGE_UPLOAD_PATH, {
    method: "POST",
    body: formData
  });
  if (!resp.ok) throw new Error(`上传失败 HTTP ${resp.status}`);
  const result = await resp.json();
  if (Array.isArray(result) && result.length > 0 && result[0].src) {
    return IMAGE_HOST + result[0].src;
  }
  throw new Error("图床响应格式异常");
}

async function verifyAccess(env, id, password) {
  if (!id || !password) return { error: "缺少参数", status: 400 };
  const target = await env.DB.prepare(
    "SELECT password_hash, creator_ip, creator_webrtc_ips FROM targets WHERE id = ?"
  ).bind(id).first();
  if (!target) return { error: "追踪ID不存在", status: 404 };
  const hash = await sha256(password);
  if (hash !== target.password_hash) return { error: "访问密码错误", status: 403 };
  return { target };
}

// ---------- 图片/视频追踪 ----------
async function handlePixel(request, env, ctx, targetId) {
  const target = await env.DB.prepare(
    "SELECT media_type, media_url FROM targets WHERE id = ?"
  ).bind(targetId).first();

  const mediaType = target?.media_type || "pixel";
  const mediaUrl = target?.media_url || "";
  const range = request.headers.get("Range");

  let shouldLog = true;
  if (mediaType === "video" && range && !range.startsWith("bytes=0-")) {
    shouldLog = false;
  }

  if (shouldLog) {
    const ip = request.headers.get("CF-Connecting-IP") || "Unknown";
    const country = request.cf?.country || "";
    const ua = request.headers.get("User-Agent") || "";
    const languages = request.headers.get("Accept-Language") || "";
    const referer = request.headers.get("Referer") || "";
    const accept = request.headers.get("Accept") || "";
    const acceptEncoding = request.headers.get("Accept-Encoding") || "";
    const secChUa = request.headers.get("Sec-Ch-Ua") || "";
    const secChUaPlatform = request.headers.get("Sec-Ch-Ua-Platform") || "";
    const secChUaMobile = request.headers.get("Sec-Ch-Ua-Mobile") || "";

    const ipInfo = await getIpInfo(ip);

    await env.DB.prepare(`
      INSERT INTO tracking_logs (
        target_id, event_type, ip, country, country_code, region, city, timezone, isp, org, as_text, lat, lon,
        ua, languages, referer, accept, accept_encoding, sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile
      ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      targetId, ip,
      ipInfo?.country || country || "",
      ipInfo?.countryCode || "",
      ipInfo?.region || "",
      ipInfo?.city || "",
      ipInfo?.timezone || "",
      ipInfo?.isp || "",
      ipInfo?.org || "",
      ipInfo?.as_text || "",
      ipInfo?.lat || null,
      ipInfo?.lon || null,
      ua, languages, referer, accept, acceptEncoding,
      secChUa, secChUaPlatform, secChUaMobile
    ).run();
  }

  if (mediaType === "pixel" || !mediaUrl) {
    const pixel = "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==";
    const imgBuffer = Uint8Array.from(atob(pixel), c => c.charCodeAt(0));
    return new Response(imgBuffer, {
      headers: {
        "Content-Type": "image/gif",
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
      }
    });
  }

  try {
    const fetchHeaders = {};
    if (range) fetchHeaders["Range"] = range;
    const mediaResp = await fetch(mediaUrl, { headers: fetchHeaders });
    if (!mediaResp.ok && mediaResp.status !== 206) throw new Error("媒体获取失败");

    const newHeaders = new Headers();
    mediaResp.headers.forEach((v, k) => {
      const lk = k.toLowerCase();
      if (!['content-encoding', 'transfer-encoding', 'connection'].includes(lk)) {
        newHeaders.set(k, v);
      }
    });
    newHeaders.set('Cache-Control', 'no-cache, no-store, must-revalidate');
    newHeaders.set('Access-Control-Allow-Origin', '*');

    return new Response(mediaResp.body, {
      status: mediaResp.status,
      headers: newHeaders
    });
  } catch (e) {
    const pixel = "R0lGODlhAQABAIAAAP///wAAACH5BAEAAAAALAAAAAABAAEAAAICRAEAOw==";
    const imgBuffer = Uint8Array.from(atob(pixel), c => c.charCodeAt(0));
    return new Response(imgBuffer, {
      headers: {
        "Content-Type": "image/gif",
        "Cache-Control": "no-cache, no-store, must-revalidate"
      }
    });
  }
}

function handleConfig(env) {
  return jsonResponse({ ipapiKey: env.IPAPI_KEY || "" });
}

// ---------- 生成 ----------
async function handleGenerate(request, env) {
  if (request.method !== "POST") return jsonResponse({ error: "Method Not Allowed" }, 405);

  let formData;
  try {
    formData = await request.formData();
  } catch {
    return jsonResponse({ error: "Invalid FormData" }, 400);
  }

  const id = (formData.get("id") || "").trim();
  const password = (formData.get("password") || "").trim();
  const mediaKind = formData.get("mediaKind") || "image";
  const mediaSource = formData.get("mediaSource") || "pixel";
  const mediaUrl = (formData.get("mediaUrl") || "").trim();
  const mediaFile = formData.get("mediaFile");
  const webrtcIps = formData.get("webrtcIps") || "[]";
  const fingerprint = formData.get("fingerprint") || "";
  const creatorIp = request.headers.get("CF-Connecting-IP") || "Unknown";
  const creatorUa = request.headers.get("User-Agent") || "";

  if (id.length < 4) return jsonResponse({ error: "追踪ID至少需要4位" }, 400);
  if (!/^[A-Za-z0-9_-]+$/.test(id)) return jsonResponse({ error: "追踪ID只能包含字母、数字、-和_" }, 400);
  if (password.length < 4) return jsonResponse({ error: "访问密码至少需要4位" }, 400);

  const existing = await env.DB.prepare("SELECT id FROM targets WHERE id = ?").bind(id).first();
  if (existing) return jsonResponse({ error: "该追踪ID已被占用，请更换" }, 400);

  let finalMediaType = "pixel";
  let finalMediaUrl = "";

  if (mediaKind === "image") {
    if (mediaSource === "pixel") {
      finalMediaType = "pixel";
    } else if (mediaSource === "url") {
      if (!mediaUrl) return jsonResponse({ error: "请输入图片URL" }, 400);
      if (!/^https?:\/\//i.test(mediaUrl)) return jsonResponse({ error: "URL必须以 http(s):// 开头" }, 400);
      finalMediaType = "image";
      finalMediaUrl = mediaUrl;
    } else if (mediaSource === "upload") {
      if (!mediaFile || mediaFile.size === 0) return jsonResponse({ error: "请选择图片文件" }, 400);
      if (mediaFile.size > MAX_UPLOAD_SIZE) return jsonResponse({ error: "图片大小不能超过5MB" }, 400);
      if (!isImageType(mediaFile)) return jsonResponse({ error: "文件不是有效的图片格式" }, 400);
      try {
        finalMediaUrl = await uploadImageToHost(mediaFile);
        finalMediaType = "image";
      } catch (e) {
        return jsonResponse({ error: "图片上传失败: " + e.message }, 500);
      }
    } else {
      return jsonResponse({ error: "无效的图片来源" }, 400);
    }
  } else if (mediaKind === "video") {
    if (mediaSource === "url") {
      if (!mediaUrl) return jsonResponse({ error: "请输入视频URL" }, 400);
      if (!/^https?:\/\//i.test(mediaUrl)) return jsonResponse({ error: "URL必须以 http(s):// 开头" }, 400);
      finalMediaType = "video";
      finalMediaUrl = mediaUrl;
    } else if (mediaSource === "upload") {
      if (!mediaFile || mediaFile.size === 0) return jsonResponse({ error: "请选择视频文件" }, 400);
      if (mediaFile.size > MAX_UPLOAD_SIZE) return jsonResponse({ error: "视频大小不能超过5MB" }, 400);
      if (!isVideoType(mediaFile)) return jsonResponse({ error: "文件不是有效的视频格式" }, 400);
      try {
        finalMediaUrl = await uploadImageToHost(mediaFile);
        finalMediaType = "video";
      } catch (e) {
        return jsonResponse({ error: "视频上传失败: " + e.message }, 500);
      }
    } else {
      return jsonResponse({ error: "无效的视频来源" }, 400);
    }
  } else {
    return jsonResponse({ error: "无效的媒体类型" }, 400);
  }

  const passwordHash = await sha256(password);
  const origin = new URL(request.url).origin;

  let trackingImg;
  if (finalMediaType === "pixel") {
    trackingImg = `<img src="${origin}/pixel/${id}" width="1" height="1" style="display:none" alt="" />`;
  } else if (finalMediaType === "video") {
    trackingImg = `<video src="${origin}/pixel/${id}" controls preload="metadata" style="max-width:100%;height:auto;"></video>`;
  } else {
    trackingImg = `<img src="${origin}/pixel/${id}" style="max-width:100%;height:auto;" alt="" />`;
  }

  await env.DB.prepare(
    `INSERT INTO targets (id, media_type, media_url, password_hash, creator_ip, creator_ua, creator_webrtc_ips, creator_fingerprint)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(id, finalMediaType, finalMediaUrl, passwordHash, creatorIp, creatorUa, webrtcIps, fingerprint).run();

  return jsonResponse({
    id,
    trackingImg,
    emailHtml: `<div>${trackingImg}</div>`
  });
}

// ---------- 查询 ----------
async function handleQuery(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const password = url.searchParams.get("password");
  const burn = url.searchParams.get("burn") === "true";

  const verify = await verifyAccess(env, id, password);
  if (verify.error) return jsonResponse({ error: verify.error }, verify.status);

  let creatorIps = [];
  if (verify.target) {
    if (verify.target.creator_ip) creatorIps.push(verify.target.creator_ip);
    if (verify.target.creator_webrtc_ips) {
      try {
        const webrtc = JSON.parse(verify.target.creator_webrtc_ips);
        if (Array.isArray(webrtc)) creatorIps.push(...webrtc);
      } catch (e) {}
    }
  }
  const creatorIpSet = new Set(creatorIps.filter(ip => ip && ip !== "Unknown"));

  const logs = await env.DB.prepare(
    `SELECT id, target_id, event_type, ip, country, country_code, region, city, timezone, isp, org, as_text, lat, lon,
     ua, languages, referer, accept, accept_encoding, sec_ch_ua, sec_ch_ua_platform, sec_ch_ua_mobile, opened_at
     FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC`
  ).bind(id).all();

  const results = logs.results.map(log => {
    const isLocal = creatorIpSet.has(log.ip);
    return { ...log, is_local: isLocal };
  });

  if (burn && results.length > 0) {
    await env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(id).run();
  }

  return jsonResponse(results);
}

// ---------- 统计 ----------
async function handleStats(request, env) {
  const url = new URL(request.url);
  const id = url.searchParams.get("id");
  const password = url.searchParams.get("password");

  const verify = await verifyAccess(env, id, password);
  if (verify.error) return jsonResponse({ error: verify.error }, verify.status);

  const total = await env.DB.prepare("SELECT COUNT(*) as count FROM tracking_logs WHERE target_id = ?").bind(id).first();
  const uniqueIp = await env.DB.prepare("SELECT COUNT(DISTINCT ip) as count FROM tracking_logs WHERE target_id = ?").bind(id).first();
  const latest = await env.DB.prepare("SELECT opened_at FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 1").bind(id).first();

  return jsonResponse({
    total: total?.count || 0,
    uniqueIps: uniqueIp?.count || 0,
    latestOpen: latest?.opened_at || null
  });
}

// ---------- 后台管理 API ----------
async function checkAdmin(request, env) {
  const token = getCookie(request, "admin_session");
  if (!token) return false;
  const session = await env.DB.prepare("SELECT token FROM admin_sessions WHERE token = ?").bind(token).first();
  return !!session;
}

async function createAdminSession(env) {
  await env.DB.prepare("DELETE FROM admin_sessions").run();
  const token = generateToken();
  await env.DB.prepare("INSERT INTO admin_sessions (token) VALUES (?)").bind(token).run();
  return token;
}

async function handleAdminLogout(request, env) {
  const token = getCookie(request, "admin_session");
  if (token) {
    await env.DB.prepare("DELETE FROM admin_sessions WHERE token = ?").bind(token).run();
  }
  return new Response(null, {
    status: 302,
    headers: {
      "Location": "/admin",
      "Set-Cookie": "admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    }
  });
}

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
  if (!ids || !Array.isArray(ids) || ids.length === 0) return jsonResponse({ error: "No ids provided" }, 400);
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

async function handleAdminDeleteCreators(request, env) {
  if (!await checkAdmin(request, env)) return jsonResponse({ error: "Unauthorized" }, 401);
  const { ids } = await request.json();
  if (!ids || !Array.isArray(ids) || ids.length === 0) return jsonResponse({ error: "No ids provided" }, 400);
  for (const id of ids) {
    await env.DB.prepare("DELETE FROM tracking_logs WHERE target_id = ?").bind(id).run();
    await env.DB.prepare("DELETE FROM targets WHERE id = ?").bind(id).run();
  }
  return jsonResponse({ success: true });
}

// ---------- 地图瓦片反代 ----------
async function handleTile(request) {
  const url = new URL(request.url);
  const parts = url.pathname.split('/');
  const z = parts[2];
  const x = parts[3];
  const y = parts[4].split('.')[0];
  const tileUrl = `https://a.tile.openstreetmap.org/${z}/${x}/${y}.png`;
  const resp = await fetch(tileUrl, {
    headers: {
      'Referer': request.url,
      'User-Agent': request.headers.get('User-Agent') || 'Mozilla/5.0'
    }
  });
  const newHeaders = new Headers(resp.headers);
  newHeaders.set('Access-Control-Allow-Origin', '*');
  newHeaders.set('Cache-Control', 'public, max-age=86400');
  return new Response(resp.body, { status: resp.status, headers: newHeaders });
}

// ---------- 首页 ----------
function renderHome(request, env) {
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
  <script src="https://openfpcdn.io/fingerprintjs/v3/iife.min.js"><\/script>
  <style>
    body { background: linear-gradient(135deg, #f6f8fd 0%, #f1f5f9 100%); font-family: system-ui, -apple-system, sans-serif; }
    .glass { background: rgba(255, 255, 255, 0.7); backdrop-filter: blur(20px); border: 1px solid rgba(255, 255, 255, 0.5); }
    .timeline { border-left: 2px solid #e5e7eb; padding-left: 1rem; margin-left: 1rem; }
    .timeline-item { position: relative; padding: 0.5rem 0; }
    .timeline-item::before { content: ''; position: absolute; left: -1.35rem; top: 0.8rem; width: 0.75rem; height: 0.75rem; background: #6366f1; border-radius: 50%; border: 2px solid white; box-shadow: 0 0 0 2px #6366f1; }
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center; z-index: 100; }
    .modal.active { display: flex; }
    .modal-content { background: white; border-radius: 1.5rem; padding: 1.5rem; max-width: 42rem; width: 92%; max-height: 85vh; overflow-y: auto; }
    .map-container { height: 300px; width: 100%; border-radius: 0.75rem; margin-top: 0.5rem; border: 1px solid #e5e7eb; }
    .ip-word-break { word-break: break-all; overflow-wrap: anywhere; }
    .local-badge { background: #fbbf24; color: #78350f; padding: 0.1rem 0.5rem; border-radius: 9999px; font-size: 0.65rem; font-weight: 600; margin-left: 0.5rem; display: inline-block; }
    .flag-icon { width: 22px; height: 16px; border-radius: 2px; box-shadow: 0 1px 2px rgba(0,0,0,0.2); margin-left: 4px; vertical-align: middle; }
    .detail-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4px 8px; }
    .detail-item { display: flex; justify-content: space-between; padding: 2px 0; border-bottom: 1px solid #f3f4f6; gap: 8px; }
    .detail-label { color: #6b7280; font-weight: 500; white-space: nowrap; }
    .detail-value { font-weight: 500; word-break: break-word; text-align: right; }
    @media (max-width: 640px) { .detail-grid { grid-template-columns: 1fr; } }
  </style>
</head>
<body class="min-h-screen p-4">
  <div class="max-w-6xl mx-auto space-y-6 pt-8">
    <div class="glass rounded-2xl p-6 shadow-sm">
      <h1 class="text-2xl font-bold mb-4 flex items-center"><i class="fa-solid fa-envelope-open-text text-indigo-600 mr-2"></i>邮件追踪器</h1>
      <p class="text-sm text-gray-500 mb-6">生成追踪代码，粘贴到邮件HTML源码中。对方打开后即可记录详细访问信息，并自动标记"本地查看"。</p>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
        <div>
          <label class="text-sm font-medium">自定义追踪ID（4位以上，字母数字-_）</label>
          <input id="customId" class="w-full border p-2 rounded-xl mt-1" placeholder="例如：abc12345">
        </div>
        <div>
          <label class="text-sm font-medium">访问密码（4位以上，查询时必填）</label>
          <input id="accessPass" type="password" class="w-full border p-2 rounded-xl mt-1" placeholder="设置访问密码">
        </div>
      </div>

      <div class="mb-4">
        <label class="text-sm font-medium block mb-2">追踪媒体类型</label>
        <div class="flex flex-wrap gap-4 mb-3">
          <label class="flex items-center gap-1 cursor-pointer">
            <input type="radio" name="mediaKind" value="image" checked onchange="onKindChange()"> <span>图片</span>
          </label>
          <label class="flex items-center gap-1 cursor-pointer">
            <input type="radio" name="mediaKind" value="video" onchange="onKindChange()"> <span>视频</span>
          </label>
        </div>

        <div id="imageOptions" class="space-y-2">
          <div class="flex flex-wrap gap-4">
            <label class="flex items-center gap-1 cursor-pointer"><input type="radio" name="imageSource" value="pixel" checked onchange="onSourceChange()"> 默认1x1像素（隐藏）</label>
            <label class="flex items-center gap-1 cursor-pointer"><input type="radio" name="imageSource" value="url" onchange="onSourceChange()"> 自定义URL</label>
            <label class="flex items-center gap-1 cursor-pointer"><input type="radio" name="imageSource" value="upload" onchange="onSourceChange()"> 上传图片（推荐，≤5MB）</label>
          </div>
        </div>

        <div id="videoOptions" class="space-y-2 hidden">
          <div class="flex flex-wrap gap-4">
            <label class="flex items-center gap-1 cursor-pointer"><input type="radio" name="videoSource" value="url" checked onchange="onSourceChange()"> 自定义URL</label>
            <label class="flex items-center gap-1 cursor-pointer"><input type="radio" name="videoSource" value="upload" onchange="onSourceChange()"> 上传视频（推荐，≤5MB）</label>
          </div>
        </div>

        <div id="urlInputBox" class="hidden mt-3">
          <input id="mediaUrl" class="w-full border p-2 rounded-xl" placeholder="输入媒体URL（需支持外链）">
        </div>
        <div id="uploadInputBox" class="hidden mt-3">
          <input id="mediaFile" type="file" class="w-full border p-2 rounded-xl">
          <p class="text-xs text-gray-400 mt-1">仅支持图片/视频格式，大小不超过5MB</p>
        </div>
      </div>

      <button id="genBtn" class="bg-indigo-600 text-white font-medium py-2.5 px-6 rounded-xl hover:bg-indigo-700 transition-colors w-full md:w-auto">生成追踪代码</button>
      <div id="result" class="mt-4 hidden">
        <p class="text-sm font-medium">将以下代码粘贴到邮件的 HTML 源码中：</p>
        <textarea id="imgCode" class="w-full h-20 p-2 border rounded-xl font-mono text-sm resize-none" readonly></textarea>
        <p class="text-xs mt-1 text-gray-400">追踪ID：<span id="trackId" class="font-bold text-indigo-600"></span></p>
        <button id="copyBtn" class="mt-2 bg-gray-200 hover:bg-gray-300 px-3 py-1 rounded-xl text-sm">复制代码</button>
      </div>
    </div>

    <div class="glass rounded-2xl p-6 shadow-sm">
      <h2 class="text-xl font-bold mb-4 flex items-center"><i class="fa-solid fa-magnifying-glass text-emerald-600 mr-2"></i>查询记录</h2>
      <div class="grid grid-cols-1 md:grid-cols-3 gap-2 mb-4">
        <input id="queryId" placeholder="输入追踪ID" class="border p-2 rounded-xl">
        <input id="queryPass" type="password" placeholder="输入访问密码" class="border p-2 rounded-xl">
        <div class="flex gap-2">
          <button id="queryBtn" class="bg-emerald-600 text-white font-medium py-2.5 px-4 rounded-xl hover:bg-emerald-700 transition-colors flex-1">查询</button>
          <button id="statsBtn" class="bg-blue-600 text-white font-medium py-2.5 px-4 rounded-xl hover:bg-blue-700 transition-colors flex-1">统计</button>
        </div>
      </div>
      <div id="statsResult" class="text-sm text-gray-600 mb-4 hidden"></div>
      <div id="queryResult" class="space-y-4 text-sm"></div>
    </div>

    <div class="text-center text-xs text-gray-400 py-4 leading-relaxed">
      Copyright © 2026 <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK</a> All rights reserved.<br>
      QQ: 3344310554 · E-mail: <a href="mailto:cnzz666@163.com" class="hover:text-indigo-500">cnzz666@163.com</a> · Bilibili: <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK _CN</a>
      <div class="mt-2"><a href="/admin" class="text-gray-300 hover:text-gray-500">管理员入口</a></div>
    </div>
  </div>

  <div id="ipModal" class="modal">
    <div class="modal-content">
      <div class="flex justify-between items-center mb-3">
        <h3 class="font-bold text-lg"><i class="fa-solid fa-circle-info text-indigo-500 mr-2"></i>IP 详细信息</h3>
        <button onclick="document.getElementById('ipModal').classList.remove('active')" class="text-gray-400 hover:text-red-500 text-xl">&times;</button>
      </div>
      <div id="ipModalBody"></div>
    </div>
  </div>

  <script>
    const mapInstances = {};
    let IPAPI_KEY = '';

    fetch('/api/config').then(r => r.json()).then(d => { IPAPI_KEY = d.ipapiKey || ''; }).catch(()=>{});

    let creatorWebRTC = [];
    let creatorFingerprint = null;
    (async function collectCreatorInfo() {
      try {
        const fp = await FingerprintJS.load();
        const result = await fp.get();
        creatorFingerprint = result;
      } catch(e) {}
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
          pc.createOffer().then(o => pc.setLocalDescription(o));
          setTimeout(resolve, 2500);
        });
        creatorWebRTC = Array.from(ips);
      } catch(e) {}
    })();

    function getCurrentKind() {
      return document.querySelector('input[name="mediaKind"]:checked').value;
    }
    function getCurrentSource() {
      const kind = getCurrentKind();
      if (kind === 'image') return document.querySelector('input[name="imageSource"]:checked').value;
      return document.querySelector('input[name="videoSource"]:checked').value;
    }

    function onKindChange() {
      const kind = getCurrentKind();
      document.getElementById('imageOptions').classList.toggle('hidden', kind !== 'image');
      document.getElementById('videoOptions').classList.toggle('hidden', kind !== 'video');
      onSourceChange();
    }

    function onSourceChange() {
      const source = getCurrentSource();
      document.getElementById('urlInputBox').classList.toggle('hidden', source !== 'url');
      document.getElementById('uploadInputBox').classList.toggle('hidden', source !== 'upload');
      const fileInput = document.getElementById('mediaFile');
      const kind = getCurrentKind();
      if (kind === 'image') fileInput.setAttribute('accept', 'image/*');
      else fileInput.setAttribute('accept', 'video/*');
      fileInput.value = '';
    }
    onSourceChange();

    document.getElementById('copyBtn')?.addEventListener('click', function() {
      const code = document.getElementById('imgCode');
      code.select();
      document.execCommand('copy');
      alert('已复制到剪贴板');
    });

    document.getElementById('genBtn').addEventListener('click', async () => {
      const id = document.getElementById('customId').value.trim();
      const password = document.getElementById('accessPass').value.trim();
      const kind = getCurrentKind();
      const source = getCurrentSource();
      const mediaUrl = document.getElementById('mediaUrl').value.trim();
      const mediaFile = document.getElementById('mediaFile').files[0];

      if (id.length < 4) { alert('追踪ID至少需要4位'); return; }
      if (password.length < 4) { alert('访问密码至少需要4位'); return; }

      if (source === 'upload' && mediaFile) {
        if (mediaFile.size > 5 * 1024 * 1024) { alert('文件大小不能超过5MB'); return; }
      }

      const formData = new FormData();
      formData.append('id', id);
      formData.append('password', password);
      formData.append('mediaKind', kind);
      formData.append('mediaSource', source);
      if (source === 'url') formData.append('mediaUrl', mediaUrl);
      if (source === 'upload' && mediaFile) formData.append('mediaFile', mediaFile);
      formData.append('webrtcIps', JSON.stringify(creatorWebRTC));
      if (creatorFingerprint) formData.append('fingerprint', JSON.stringify(creatorFingerprint));

      const btn = document.getElementById('genBtn');
      btn.disabled = true;
      btn.textContent = '生成中...';

      try {
        const res = await fetch('/api/generate', { method: 'POST', body: formData });
        const data = await res.json();
        if (data.error) { alert('错误: ' + data.error); return; }
        document.getElementById('imgCode').value = data.trackingImg;
        document.getElementById('trackId').innerText = data.id;
        document.getElementById('result').classList.remove('hidden');
      } catch(e) {
        alert('请求失败: ' + e.message);
      } finally {
        btn.disabled = false;
        btn.textContent = '生成追踪代码';
      }
    });

    async function queryData() {
      const id = document.getElementById('queryId').value.trim();
      const password = document.getElementById('queryPass').value.trim();
      const container = document.getElementById('queryResult');
      if (!id) { container.innerHTML = '<p class="text-red-500">请输入追踪ID</p>'; return; }
      if (!password) { container.innerHTML = '<p class="text-red-500">请输入访问密码</p>'; return; }
      container.innerHTML = '<p class="text-gray-400"><i class="fa-solid fa-spinner fa-spin"></i> 查询中...</p>';

      try {
        const res = await fetch('/api/query?id=' + encodeURIComponent(id) + '&password=' + encodeURIComponent(password));
        const logs = await res.json();
        if (logs.error) { container.innerHTML = '<p class="text-red-500">' + logs.error + '</p>'; return; }
        if (!Array.isArray(logs) || logs.length === 0) {
          container.innerHTML = '<p class="text-gray-400">暂无记录</p>';
          return;
        }

        const groups = {};
        logs.forEach(log => {
          const ip = log.ip || 'Unknown';
          if (!groups[ip]) groups[ip] = [];
          groups[ip].push(log);
        });

        let html = '';
        for (const [ip, items] of Object.entries(groups)) {
          const first = items[0];
          const lat = first.lat;
          const lon = first.lon;
          const city = first.city || '';
          const region = first.region || '';
          const country = first.country || '';
          const countryCode = first.country_code || '';
          const timezone = first.timezone || '';
          const isp = first.isp || '';
          const org = first.org || '';
          const asText = first.as_text || '';
          const isLocal = items.some(item => item.is_local === true);

          html += '<div class="bg-gray-50 border border-gray-200 rounded-xl p-4 mb-4">';
          html += '<div class="flex items-start justify-between mb-3 flex-wrap gap-2">';
          html += '<div class="min-w-0 flex-1"><span class="font-mono font-bold text-indigo-700 text-base ip-word-break">' + ip + '</span>';
          if (countryCode) {
            html += ' <img src="https://ipdata.co/flags/' + countryCode.toLowerCase() + '.png" class="flag-icon" />';
          }
          html += '<div class="text-gray-500 text-xs mt-1 ip-word-break">' + country + ' ' + city + '</div>';
          if (isLocal) html += '<span class="local-badge"><i class="fa-solid fa-house mr-1"></i>本地查看</span>';
          html += '<span class="text-xs text-gray-400 ml-2">（共 ' + items.length + ' 次打开）</span></div>';
          html += '<div class="flex-shrink-0">';
          html += '<button class="ip-detail-btn text-indigo-500 hover:text-indigo-700 text-sm font-medium underline" data-ip="' + ip + '" data-country="' + country + '" data-region="' + region + '" data-city="' + city + '" data-lat="' + lat + '" data-lon="' + lon + '" data-timezone="' + timezone + '" data-isp="' + isp + '" data-org="' + org + '" data-as="' + asText + '" data-countrycode="' + countryCode + '"><i class="fa-solid fa-magnifying-glass mr-1"></i>详情</button>';
          html += '</div></div>';

          if (lat && lon) {
            html += '<div class="text-xs text-gray-500 mb-2 ip-word-break">📍 ' + [city, region, country].filter(Boolean).join(', ') + ' | 时区: ' + timezone + ' | ISP: ' + isp + ' ' + org + (asText ? ' | AS: ' + asText : '') + '</div>';
            html += '<div id="map_' + ip.replace(/[.:]/g, '_') + '" class="map-container"></div>';
          } else {
            html += '<div class="text-xs text-gray-400">🌐 地理位置未获取到</div>';
          }

          html += '<div class="timeline mt-3">';
          items.forEach(log => {
            const date = new Date(log.opened_at + 'Z').toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
            html += '<div class="timeline-item">';
            html += '<span class="text-xs text-gray-400">' + date + '</span>';
            if (log.is_local) html += '<span class="local-badge text-[10px] ml-1"><i class="fa-solid fa-house"></i> 本地</span>';
            html += '<div class="text-xs text-gray-600 break-all mt-1">UA: ' + (log.ua || '?') + '</div>';
            if (log.referer) html += '<div class="text-xs text-gray-400 break-all">Referer: ' + log.referer + '</div>';
            if (log.sec_ch_ua) html += '<div class="text-xs text-gray-400 break-all">Sec-CH-UA: ' + log.sec_ch_ua + '</div>';
            html += '</div>';
          });
          html += '</div></div>';
        }
        container.innerHTML = html;

        document.querySelectorAll('.ip-detail-btn').forEach(btn => {
          btn.addEventListener('click', function(e) {
            e.stopPropagation();
            const ip = this.dataset.ip;
            const geo = {
              country: this.dataset.country, region: this.dataset.region, city: this.dataset.city,
              lat: this.dataset.lat, lon: this.dataset.lon, timezone: this.dataset.timezone,
              isp: this.dataset.isp, org: this.dataset.org, as: this.dataset.as,
              countryCode: this.dataset.countrycode
            };
            showIPDetail(ip, geo);
          });
        });

        setTimeout(() => {
          for (const [ip, items] of Object.entries(groups)) {
            const first = items[0];
            if (first.lat && first.lon) {
              const mapId = 'map_' + ip.replace(/[.:]/g, '_');
              const mapContainer = document.getElementById(mapId);
              if (mapContainer) {
                if (mapInstances[mapId]) { mapInstances[mapId].remove(); delete mapInstances[mapId]; }
                const map = L.map(mapId).setView([first.lat, first.lon], 4);
                L.tileLayer('/tile/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '&copy; OpenStreetMap' }).addTo(map);
                L.marker([first.lat, first.lon]).addTo(map).bindPopup('IP: ' + ip + '<br>' + first.city + ', ' + first.country);
                mapInstances[mapId] = map;
              }
            }
          }
        }, 100);
      } catch(e) {
        container.innerHTML = '<p class="text-red-500">查询失败：' + e.message + '</p>';
      }
    }

    document.getElementById('queryBtn').addEventListener('click', queryData);

    document.getElementById('statsBtn').addEventListener('click', async () => {
      const id = document.getElementById('queryId').value.trim();
      const password = document.getElementById('queryPass').value.trim();
      const statsDiv = document.getElementById('statsResult');
      if (!id) { statsDiv.innerHTML = '<span class="text-red-500">请输入追踪ID</span>'; statsDiv.classList.remove('hidden'); return; }
      if (!password) { statsDiv.innerHTML = '<span class="text-red-500">请输入访问密码</span>'; statsDiv.classList.remove('hidden'); return; }
      try {
        const res = await fetch('/api/stats?id=' + encodeURIComponent(id) + '&password=' + encodeURIComponent(password));
        const data = await res.json();
        if (data.error) { statsDiv.innerHTML = '<span class="text-red-500">' + data.error + '</span>'; statsDiv.classList.remove('hidden'); return; }
        statsDiv.innerHTML = '📊 总打开: <strong>' + data.total + '</strong> 次，独立IP: <strong>' + data.uniqueIps + '</strong> 个，最近打开: ' + (data.latestOpen ? new Date(data.latestOpen + 'Z').toLocaleString('zh-CN') : '无');
        statsDiv.classList.remove('hidden');
      } catch(e) {
        statsDiv.innerHTML = '<span class="text-red-500">统计失败</span>';
        statsDiv.classList.remove('hidden');
      }
    });

    async function showIPDetail(ip, fallbackGeo = {}) {
      const body = document.getElementById('ipModalBody');
      body.innerHTML = '<div class="text-center py-4"><i class="fa-solid fa-spinner fa-spin"></i> 加载中...</div>';
      document.getElementById('ipModal').classList.add('active');

      let data = null;
      try {
        let url = 'https://api.ipapi.is/?q=' + encodeURIComponent(ip);
        if (IPAPI_KEY) url += '&key=' + encodeURIComponent(IPAPI_KEY);
        const res = await fetch(url);
        if (res.ok) data = await res.json();
      } catch(e) {}

      if (!data || data.error) {
        body.innerHTML = '<div class="text-red-500">无法获取IP详细信息，请稍后重试。</div>';
        return;
      }

      const loc = data.location || {};
      const comp = data.company || {};
      const asn = data.asn || {};
      const dc = data.datacenter || {};
      const abuse = data.abuse || {};

      const countryCode = loc.country_code || fallbackGeo.countryCode || '';
      const country = loc.country || fallbackGeo.country || '未知';
      const region = loc.state || fallbackGeo.region || '';
      const city = loc.city || fallbackGeo.city || '';
      const timezone = loc.timezone || fallbackGeo.timezone || '未知';
      const lat = loc.latitude || fallbackGeo.lat || null;
      const lon = loc.longitude || fallbackGeo.lon || null;

      let risk = '未知';
      if (data.risk_score !== undefined) {
        risk = parseFloat(data.risk_score).toFixed(2) + '% ' + (data.risk_score > 30 ? '⚠️ 高风险' : '低风险');
      } else if (data.is_proxy || data.is_tor || data.is_vpn || data.is_abuser) {
        risk = '⚠️ 高风险';
      } else if (data.is_datacenter) {
        risk = '🏢 数据中心';
      }

      let html = '<div class="space-y-3 text-sm">';
      html += '<div class="flex items-center gap-2 border-b pb-2 flex-wrap"><span class="font-bold text-base ip-word-break">' + ip + '</span>';
      if (countryCode) {
        html += ' <img src="https://ipdata.co/flags/' + countryCode.toLowerCase() + '.png" style="width:32px;height:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.2);" />';
      }
      html += '</div>';

      html += '<div><div class="font-semibold text-indigo-700">📍 基本信息</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
      html += '<div class="detail-item"><span class="detail-label">国家</span><span class="detail-value">' + country + ' (' + countryCode + ')</span></div>';
      html += '<div class="detail-item"><span class="detail-label">州/省</span><span class="detail-value">' + region + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">城市</span><span class="detail-value">' + city + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">时区</span><span class="detail-value">' + timezone + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">经纬度</span><span class="detail-value">' + (lat && lon ? lat + ', ' + lon : '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">风控评级</span><span class="detail-value font-bold ' + (risk.includes('高风险') ? 'text-red-600' : 'text-green-600') + '">' + risk + '</span></div>';
      html += '</div></div>';

      html += '<div><div class="font-semibold text-emerald-700">🏢 运营商 & ASN</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
      html += '<div class="detail-item"><span class="detail-label">运营商</span><span class="detail-value">' + (comp.name || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">类型</span><span class="detail-value">' + (comp.type || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">域名</span><span class="detail-value">' + (comp.domain || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">ASN</span><span class="detail-value">' + (asn.asn || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">ASN 描述</span><span class="detail-value">' + (asn.descr || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">ASN 所属</span><span class="detail-value">' + (asn.org || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">路由前缀</span><span class="detail-value">' + (asn.route || '未知') + '</span></div>';
      html += '</div></div>';

      if (dc.datacenter) {
        html += '<div><div class="font-semibold text-amber-700">☁️ 数据中心</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
        html += '<div class="detail-item"><span class="detail-label">数据中心</span><span class="detail-value">' + (dc.datacenter || '未知') + '</span></div>';
        html += '<div class="detail-item"><span class="detail-label">服务商</span><span class="detail-value">' + (dc.service || '未知') + '</span></div>';
        html += '<div class="detail-item"><span class="detail-label">区域</span><span class="detail-value">' + (dc.scope || '未知') + '</span></div>';
        html += '</div></div>';
      }

      if (abuse.email) {
        html += '<div><div class="font-semibold text-red-600">⚠️ 滥用举报</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
        html += '<div class="detail-item"><span class="detail-label">姓名</span><span class="detail-value">' + (abuse.name || '未知') + '</span></div>';
        html += '<div class="detail-item"><span class="detail-label">邮箱</span><span class="detail-value">' + abuse.email + '</span></div>';
        html += '<div class="detail-item"><span class="detail-label">电话</span><span class="detail-value">' + (abuse.phone || '未知') + '</span></div>';
        html += '</div></div>';
      }

      html += '<div><div class="font-semibold text-purple-700">🛡️ 安全检测</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
      html += '<div class="detail-item"><span class="detail-label">数据中心</span><span class="detail-value">' + (data.is_datacenter ? '🏢 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">代理</span><span class="detail-value">' + (data.is_proxy ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">VPN</span><span class="detail-value">' + (data.is_vpn ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">Tor</span><span class="detail-value">' + (data.is_tor ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">爬虫</span><span class="detail-value">' + (data.is_crawler ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="detail-label">移动网络</span><span class="detail-value">' + (data.is_mobile ? '📱 是' : '✅ 否') + '</span></div>';
      html += '</div></div>';

      if (lat && lon) {
        html += '<div><div class="font-semibold text-blue-700">🗺️ 地理位置</div>';
        html += '<div id="ipDetailMap" class="map-container" style="height:280px;"></div></div>';
      }

      html += '</div>';
      body.innerHTML = html;

      if (lat && lon) {
        setTimeout(() => {
          const mapContainer = document.getElementById('ipDetailMap');
          if (mapContainer) {
            const map = L.map(mapContainer).setView([lat, lon], 8);
            L.tileLayer('/tile/{z}/{x}/{y}.png', { maxZoom: 19, attribution: '&copy; OpenStreetMap' }).addTo(map);
            L.marker([lat, lon]).addTo(map).bindPopup('IP: ' + ip + '<br>' + city + ', ' + country);
          }
        }, 50);
      }
    }

    document.getElementById('ipModal').addEventListener('click', function(e) {
      if (e.target === this) this.classList.remove('active');
    });
  <\/script>
</body>
</html>`;
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// ---------- 后台管理页面 ----------
async function renderAdmin(request, env) {
  if (!await checkAdmin(request, env)) {
    const url = new URL(request.url);
    const error = url.searchParams.get("error");

    if (request.method === "POST") {
      const fd = await request.formData();
      const pwd = fd.get("password");
      if (pwd === env.ADMIN) {
        const token = await createAdminSession(env);
        return new Response(null, {
          status: 302,
          headers: {
            "Location": "/admin",
            "Set-Cookie": `admin_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400`
          }
        });
      }
      return new Response(null, { status: 302, headers: { "Location": "/admin?error=1" } });
    }

    return new Response(`<!DOCTYPE html>
<html lang="zh"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>管理员登录</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<style>
  body { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
  .glass { background: rgba(255,255,255,0.95); backdrop-filter: blur(20px); }
  .shake { animation: shake 0.4s; }
  @keyframes shake { 0%,100%{transform:translateX(0)} 25%{transform:translateX(-6px)} 75%{transform:translateX(6px)} }
</style>
</head>
<body class="flex items-center justify-center p-4">
  <div class="glass rounded-3xl shadow-2xl p-8 w-full max-w-md">
    <div class="text-center mb-6">
      <div class="inline-flex items-center justify-center w-16 h-16 rounded-2xl mb-4" style="background: linear-gradient(135deg, #6366f1, #8b5cf6);">
        <svg class="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/>
        </svg>
      </div>
      <h1 class="text-2xl font-bold text-gray-800">管理员登录</h1>
      <p class="text-sm text-gray-500 mt-1">请输入管理密码</p>
    </div>
    <form method="POST">
      <input name="password" type="password" placeholder="管理密码" autofocus
        class="w-full border-2 border-gray-200 rounded-xl p-3 focus:border-indigo-500 focus:outline-none transition ${error ? 'border-red-300 shake' : ''}">
      ${error ? '<p class="text-red-500 text-xs mt-2 ml-1">密码错误，请重试</p>' : ''}
      <button class="w-full text-white py-3 rounded-xl font-medium mt-4 hover:shadow-lg transition" style="background: linear-gradient(135deg, #6366f1, #8b5cf6);">登 录</button>
    </form>
    <div class="text-center text-xs text-gray-400 mt-6">
      Copyright © 2026 <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK</a> All rights reserved.
    </div>
  </div>
</body>
</html>`, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  }

  const totalTargets = await env.DB.prepare("SELECT COUNT(*) as count FROM targets").first();
  const totalLogs = await env.DB.prepare("SELECT COUNT(*) as count FROM tracking_logs").first();
  const uniqueIps = await env.DB.prepare("SELECT COUNT(DISTINCT ip) as count FROM tracking_logs").first();

  const url = new URL(request.url);
  const filter = url.searchParams.get("filter_id") || "";
  let logs;
  if (filter) {
    logs = await env.DB.prepare("SELECT * FROM tracking_logs WHERE target_id = ? ORDER BY opened_at DESC LIMIT 200").bind(filter).all();
  } else {
    logs = await env.DB.prepare("SELECT * FROM tracking_logs ORDER BY opened_at DESC LIMIT 200").all();
  }

  const targetsResult = await env.DB.prepare("SELECT id, media_type, media_url, creator_ip, creator_ua, creator_webrtc_ips, creator_fingerprint FROM targets").all();
  const targetMap = {};
  for (const t of targetsResult.results) {
    targetMap[t.id] = t;
  }

  let rows = "";
  for (let r of logs.results) {
    const date = new Date(r.opened_at + 'Z').toLocaleString('zh-CN');
    const geo = [r.country, r.region, r.city].filter(Boolean).join(', ');
    const targetInfo = targetMap[r.target_id] || {};
    let isLocal = false;
    if (targetInfo.creator_ip && r.ip === targetInfo.creator_ip) isLocal = true;
    if (!isLocal && targetInfo.creator_webrtc_ips) {
      try {
        const webrtc = JSON.parse(targetInfo.creator_webrtc_ips);
        if (Array.isArray(webrtc) && webrtc.includes(r.ip)) isLocal = true;
      } catch(e) {}
    }
    const localBadge = isLocal ? '<span class="ml-1 bg-yellow-200 text-yellow-800 px-2 py-0.5 rounded-full text-[10px]">本地</span>' : '';
    const countryCode = r.country_code || '';
    const flagHtml = countryCode ? `<img src="https://ipdata.co/flags/${countryCode.toLowerCase()}.png" style="width:18px;height:12px;margin-left:4px;border-radius:2px;vertical-align:middle;" />` : '';
    rows += `<tr class="border-b hover:bg-gray-50">
      <td class="p-2"><input type="checkbox" class="target-checkbox" data-target-id="${r.target_id}"></td>
      <td class="p-2 text-xs font-mono">${r.target_id}</td>
      <td class="p-2 text-xs">打开</td>
      <td class="p-2 text-xs">${date}</td>
      <td class="p-2 text-xs font-mono" style="word-break:break-all;max-width:180px;">${r.ip} ${flagHtml} ${localBadge} <button class="admin-ip-detail text-indigo-500 underline text-xs" data-ip="${r.ip}" data-country="${r.country}" data-region="${r.region}" data-city="${r.city}" data-lat="${r.lat}" data-lon="${r.lon}" data-timezone="${r.timezone}" data-isp="${r.isp}" data-org="${r.org}" data-as="${r.as_text}" data-countrycode="${countryCode}">🔍</button></td>
      <td class="p-2 text-xs">${geo}</td>
      <td class="p-2 text-xs">${r.timezone || ''}</td>
      <td class="p-2 text-xs max-w-[150px] break-all">${(r.ua || '').substring(0, 60)}</td>
      <td class="p-2"><button class="del-btn text-red-500 text-xs underline" data-id="${r.id}">删除</button></td>
    </tr>`;
  }

  let creatorRows = "";
  for (const [id, info] of Object.entries(targetMap)) {
    let webrtcArray = [];
    try { webrtcArray = info.creator_webrtc_ips ? JSON.parse(info.creator_webrtc_ips) : []; } catch(e) {}
    const webrtcStr = webrtcArray.length > 0 ? webrtcArray.map(ip =>
      `<span class="font-mono">${ip}</span> <button class="admin-ip-detail text-indigo-500 underline text-xs" data-ip="${ip}" data-country="" data-region="" data-city="" data-lat="" data-lon="" data-timezone="" data-isp="" data-org="" data-as="" data-countrycode="">🔍</button>`
    ).join(' ') : '无';
    let fpId = 'N/A';
    try {
      const fp = info.creator_fingerprint ? JSON.parse(info.creator_fingerprint) : null;
      fpId = fp ? (fp.visitorId || 'N/A') : 'N/A';
    } catch(e) {}
    const creatorIp = info.creator_ip || 'Unknown';
    const mediaLabel = info.media_type === 'video' ? '视频' : (info.media_type === 'image' ? '图片' : '像素');
    creatorRows += `<tr class="border-b hover:bg-gray-50">
      <td class="p-2"><input type="checkbox" class="creator-checkbox" data-creator-id="${id}"></td>
      <td class="p-2 text-xs font-mono">${id}</td>
      <td class="p-2 text-xs">${mediaLabel}</td>
      <td class="p-2 text-xs font-mono" style="word-break:break-all;">${creatorIp} <button class="admin-ip-detail text-indigo-500 underline text-xs" data-ip="${creatorIp}" data-country="" data-region="" data-city="" data-lat="" data-lon="" data-timezone="" data-isp="" data-org="" data-as="" data-countrycode="">🔍</button></td>
      <td class="p-2 text-xs max-w-[200px] break-all">${(info.creator_ua || '').substring(0, 60)}</td>
      <td class="p-2 text-xs" style="word-break:break-all;">${webrtcStr}</td>
      <td class="p-2 text-xs font-mono">${fpId.substring(0, 12)}</td>
      <td class="p-2"><button class="del-target-btn text-red-500 text-xs underline" data-id="${id}">删除</button></td>
    </tr>`;
  }

  return new Response(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>后台管理</title>
<script src="https://cdn.tailwindcss.com"><\/script>
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"><\/script>
<style>
  .ip-word-break{word-break:break-all;overflow-wrap:anywhere;}
  .stat-card{background:white;padding:1rem;border-radius:1rem;box-shadow:0 1px 3px rgba(0,0,0,0.05);text-align:center;flex:1;min-width:120px;}
  .detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:4px 8px;}
  .detail-item{display:flex;justify-content:space-between;padding:2px 0;border-bottom:1px solid #f3f4f6;gap:8px;}
  @media (max-width: 640px) { .detail-grid{grid-template-columns:1fr;} }
</style>
</head>
<body class="bg-gray-100 p-4">
  <div class="max-w-7xl mx-auto">
    <div class="flex justify-between items-center mb-6 flex-wrap gap-3">
      <h1 class="text-2xl font-bold text-gray-800">📊 后台管理</h1>
      <a href="/admin/logout" class="bg-gray-200 hover:bg-gray-300 px-4 py-2 rounded-xl text-sm">退出登录</a>
    </div>

    <div class="flex flex-wrap gap-4 mb-6">
      <div class="stat-card"><div class="text-2xl font-bold text-indigo-600">${totalTargets?.count || 0}</div><div class="text-xs text-gray-500">追踪ID总数</div></div>
      <div class="stat-card"><div class="text-2xl font-bold text-emerald-600">${totalLogs?.count || 0}</div><div class="text-xs text-gray-500">总打开次数</div></div>
      <div class="stat-card"><div class="text-2xl font-bold text-amber-600">${uniqueIps?.count || 0}</div><div class="text-xs text-gray-500">独立IP数</div></div>
    </div>

    <div class="bg-white rounded-2xl p-4 shadow-sm">
      <h2 class="text-lg font-bold mb-4">📋 追踪日志</h2>
      <div class="flex flex-wrap gap-2 mb-4">
        <input id="filterInput" value="${filter}" placeholder="按ID过滤" class="border p-2 rounded flex-1 min-w-[150px]">
        <button id="filterBtn" class="bg-indigo-100 px-3 rounded hover:bg-indigo-200">筛选</button>
        <button id="clearAllBtn" class="bg-red-100 text-red-600 px-3 rounded hover:bg-red-200">清空全部日志</button>
        <button id="clearTargetsBtn" class="bg-red-200 text-red-700 px-3 rounded hover:bg-red-300">清空所有ID</button>
        <button id="deleteSelectedBtn" class="bg-red-300 text-red-800 px-3 rounded hover:bg-red-400">删除选中ID</button>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm"><thead class="bg-gray-50"><tr><th class="p-2"><input type="checkbox" id="selectAll"></th><th class="p-2">ID</th><th class="p-2">类型</th><th class="p-2">时间</th><th class="p-2">IP</th><th class="p-2">地理位置</th><th class="p-2">时区</th><th class="p-2">UA</th><th class="p-2">操作</th></tr></thead><tbody>${rows}</tbody></table>
      </div>
    </div>

    <div class="bg-white rounded-2xl p-4 shadow-sm mt-6">
      <h2 class="text-lg font-bold mb-2">🧑‍💻 追踪ID创建者信息</h2>
      <div class="flex flex-wrap gap-2 mb-4">
        <button id="deleteSelectedCreatorsBtn" class="bg-red-300 text-red-800 px-3 rounded hover:bg-red-400">删除选中创建者</button>
      </div>
      <div class="overflow-x-auto">
        <table class="w-full text-sm"><thead class="bg-gray-50"><tr><th class="p-2"><input type="checkbox" id="selectAllCreators"></th><th class="p-2">ID</th><th class="p-2">类型</th><th class="p-2">创建IP</th><th class="p-2">UA</th><th class="p-2">WebRTC IP</th><th class="p-2">指纹ID</th><th class="p-2">操作</th></tr></thead><tbody>${creatorRows}</tbody></table>
      </div>
    </div>

    <div class="text-center text-xs text-gray-400 mt-8 leading-relaxed">
      Copyright © 2026 <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK</a> All rights reserved.<br>
      QQ: 3344310554 · E-mail: <a href="mailto:cnzz666@163.com" class="hover:text-indigo-500">cnzz666@163.com</a> · Bilibili: <a href="https://b23.tv/8fCttY7" target="_blank" class="hover:text-indigo-500">SAK _CN</a>
    </div>
  </div>

  <div id="ipModal" style="display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.5);align-items:center;justify-content:center;z-index:100;">
    <div style="background:white;border-radius:1.5rem;padding:1.5rem;max-width:42rem;width:92%;max-height:85vh;overflow-y:auto;">
      <div style="display:flex;justify-content:space-between;margin-bottom:0.5rem;"><h3 style="font-weight:bold;"><i class="fa-solid fa-circle-info text-indigo-500 mr-2"></i>IP 详细信息</h3><button onclick="document.getElementById('ipModal').style.display='none'" style="font-size:1.5rem;line-height:1;">&times;</button></div>
      <div id="ipModalBody"></div>
    </div>
  </div>

  <script>
    let IPAPI_KEY = '';
    fetch('/api/config').then(r=>r.json()).then(d=>{IPAPI_KEY=d.ipapiKey||'';}).catch(()=>{});

    document.getElementById('selectAll').addEventListener('change', function() {
      document.querySelectorAll('.target-checkbox').forEach(cb => cb.checked = this.checked);
    });
    document.getElementById('selectAllCreators').addEventListener('change', function() {
      document.querySelectorAll('.creator-checkbox').forEach(cb => cb.checked = this.checked);
    });

    document.getElementById('deleteSelectedBtn').addEventListener('click', async function() {
      const checked = document.querySelectorAll('.target-checkbox:checked');
      if (checked.length === 0) { alert('请至少选择一个ID'); return; }
      if (!confirm('确认删除选中的 ' + checked.length + ' 个追踪ID及其所有日志？')) return;
      const ids = Array.from(new Set(Array.from(checked).map(cb => cb.dataset.targetId)));
      try {
        const res = await fetch('/api/admin/delete-targets', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
        if (res.ok) location.reload(); else alert('删除失败');
      } catch(e) { alert('请求失败'); }
    });

    document.getElementById('deleteSelectedCreatorsBtn').addEventListener('click', async function() {
      const checked = document.querySelectorAll('.creator-checkbox:checked');
      if (checked.length === 0) { alert('请至少选择一个创建者'); return; }
      if (!confirm('确认删除选中的 ' + checked.length + ' 个创建者及其所有相关日志？')) return;
      const ids = Array.from(new Set(Array.from(checked).map(cb => cb.dataset.creatorId)));
      try {
        const res = await fetch('/api/admin/delete-creators', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
        if (res.ok) location.reload(); else alert('删除失败');
      } catch(e) { alert('请求失败'); }
    });

    document.getElementById('clearTargetsBtn').addEventListener('click', async function() {
      if (!confirm('⚠️ 确认清空所有追踪ID及其日志？此操作不可撤销！')) return;
      try {
        const res = await fetch('/api/admin/clear-targets', { method: 'POST' });
        if (res.ok) location.reload(); else alert('操作失败');
      } catch(e) { alert('请求失败'); }
    });

    document.getElementById('clearAllBtn').addEventListener('click', async function() {
      if (!confirm('清空所有日志记录？')) return;
      try {
        const res = await fetch('/api/admin/clear', { method: 'POST' });
        if (res.ok) location.reload(); else alert('操作失败');
      } catch(e) { alert('请求失败'); }
    });

    document.getElementById('filterBtn').addEventListener('click', function() {
      const v = document.getElementById('filterInput').value.trim();
      location.href = '/admin' + (v ? '?filter_id=' + encodeURIComponent(v) : '');
    });

    document.querySelectorAll('.del-btn').forEach(b => b.onclick = async function() {
      if (!confirm('删除此条日志？')) return;
      const id = parseInt(this.dataset.id);
      await fetch('/api/admin/delete', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({id}) });
      location.reload();
    });

    document.querySelectorAll('.del-target-btn').forEach(b => b.onclick = async function() {
      if (!confirm('删除该追踪ID及其所有日志？')) return;
      const id = this.dataset.id;
      await fetch('/api/admin/delete-target', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({id}) });
      location.reload();
    });

    async function showAdminIPDetail(ip, fallback) {
      const body = document.getElementById('ipModalBody');
      body.innerHTML = '<div class="text-center py-4"><i class="fa-solid fa-spinner fa-spin"></i> 加载中...</div>';
      document.getElementById('ipModal').style.display = 'flex';

      let data = null;
      try {
        let url = 'https://api.ipapi.is/?q=' + encodeURIComponent(ip);
        if (IPAPI_KEY) url += '&key=' + encodeURIComponent(IPAPI_KEY);
        const res = await fetch(url);
        if (res.ok) data = await res.json();
      } catch(e) {}

      if (!data || data.error) {
        body.innerHTML = '<div class="text-red-500">无法获取IP详细信息，请稍后重试。</div>';
        return;
      }

      const loc = data.location || {};
      const comp = data.company || {};
      const asn = data.asn || {};
      const dc = data.datacenter || {};
      const abuse = data.abuse || {};

      const countryCode = loc.country_code || fallback.countryCode || '';
      const country = loc.country || fallback.country || '未知';
      const region = loc.state || fallback.region || '';
      const city = loc.city || fallback.city || '';
      const timezone = loc.timezone || fallback.timezone || '未知';
      const lat = loc.latitude || fallback.lat || null;
      const lon = loc.longitude || fallback.lon || null;

      let risk = '未知';
      if (data.risk_score !== undefined) {
        risk = parseFloat(data.risk_score).toFixed(2) + '% ' + (data.risk_score > 30 ? '⚠️ 高风险' : '低风险');
      } else if (data.is_proxy || data.is_tor || data.is_vpn || data.is_abuser) {
        risk = '⚠️ 高风险';
      } else if (data.is_datacenter) {
        risk = '🏢 数据中心';
      }

      let html = '<div class="space-y-3 text-sm">';
      html += '<div class="flex items-center gap-2 border-b pb-2 flex-wrap"><span class="font-bold text-base ip-word-break">' + ip + '</span>';
      if (countryCode) html += ' <img src="https://ipdata.co/flags/' + countryCode.toLowerCase() + '.png" style="width:32px;height:24px;border-radius:4px;box-shadow:0 1px 3px rgba(0,0,0,0.2);" />';
      html += '</div>';

      html += '<div><div class="font-semibold text-indigo-700">📍 基本信息</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
      html += '<div class="detail-item"><span class="text-gray-600">国家</span><span class="font-medium">' + country + ' (' + countryCode + ')</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">州/省</span><span class="font-medium">' + region + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">城市</span><span class="font-medium">' + city + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">时区</span><span class="font-medium">' + timezone + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">经纬度</span><span class="font-medium">' + (lat && lon ? lat + ', ' + lon : '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">风控评级</span><span class="font-bold ' + (risk.includes('高风险') ? 'text-red-600' : 'text-green-600') + '">' + risk + '</span></div>';
      html += '</div></div>';

      html += '<div><div class="font-semibold text-emerald-700">🏢 运营商 & ASN</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
      html += '<div class="detail-item"><span class="text-gray-600">运营商</span><span class="font-medium">' + (comp.name || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">类型</span><span class="font-medium">' + (comp.type || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">域名</span><span class="font-medium">' + (comp.domain || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">ASN</span><span class="font-medium">' + (asn.asn || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">ASN 描述</span><span class="font-medium">' + (asn.descr || '未知') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">路由前缀</span><span class="font-medium">' + (asn.route || '未知') + '</span></div>';
      html += '</div></div>';

      if (dc.datacenter) {
        html += '<div><div class="font-semibold text-amber-700">☁️ 数据中心</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
        html += '<div class="detail-item"><span class="text-gray-600">数据中心</span><span class="font-medium">' + (dc.datacenter || '未知') + '</span></div>';
        html += '<div class="detail-item"><span class="text-gray-600">服务商</span><span class="font-medium">' + (dc.service || '未知') + '</span></div>';
        html += '</div></div>';
      }

      if (abuse.email) {
        html += '<div><div class="font-semibold text-red-600">⚠️ 滥用举报</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
        html += '<div class="detail-item"><span class="text-gray-600">邮箱</span><span class="font-medium">' + abuse.email + '</span></div>';
        html += '<div class="detail-item"><span class="text-gray-600">电话</span><span class="font-medium">' + (abuse.phone || '未知') + '</span></div>';
        html += '</div></div>';
      }

      html += '<div><div class="font-semibold text-purple-700">🛡️ 安全检测</div><div class="bg-gray-50 p-3 rounded-xl mt-1 detail-grid">';
      html += '<div class="detail-item"><span class="text-gray-600">数据中心</span><span class="font-medium">' + (data.is_datacenter ? '🏢 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">代理</span><span class="font-medium">' + (data.is_proxy ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">VPN</span><span class="font-medium">' + (data.is_vpn ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '<div class="detail-item"><span class="text-gray-600">Tor</span><span class="font-medium">' + (data.is_tor ? '⚠️ 是' : '✅ 否') + '</span></div>';
      html += '</div></div>';

      if (lat && lon) {
        html += '<div><div class="font-semibold text-blue-700">🗺️ 地理位置</div>';
        html += '<div id="adminIpMap" style="height:280px;width:100%;border-radius:0.75rem;margin-top:0.5rem;border:1px solid #e5e7eb;"></div></div>';
      }

      html += '</div>';
      body.innerHTML = html;

      if (lat && lon) {
        setTimeout(() => {
          const mapContainer = document.getElementById('adminIpMap');
          if (mapContainer) {
            const map = L.map(mapContainer).setView([lat, lon], 8);
            L.tileLayer('/tile/{z}/{x}/{y}.png', { maxZoom: 19 }).addTo(map);
            L.marker([lat, lon]).addTo(map).bindPopup('IP: ' + ip + '<br>' + city + ', ' + country);
          }
        }, 50);
      }
    }

    document.querySelectorAll('.admin-ip-detail').forEach(btn => {
      btn.addEventListener('click', function(e) {
        e.stopPropagation();
        const ip = this.dataset.ip;
        if (!ip || ip === 'Unknown') { alert('无效IP'); return; }
        const fallback = {
          country: this.dataset.country, region: this.dataset.region, city: this.dataset.city,
          lat: this.dataset.lat, lon: this.dataset.lon, timezone: this.dataset.timezone,
          isp: this.dataset.isp, org: this.dataset.org, as: this.dataset.as,
          countryCode: this.dataset.countrycode
        };
        showAdminIPDetail(ip, fallback);
      });
    });

    document.getElementById('ipModal').addEventListener('click', function(e) {
      if (e.target === this) this.style.display = 'none';
    });
  <\/script>
</body></html>`, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}