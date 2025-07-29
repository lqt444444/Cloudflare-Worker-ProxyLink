// 监听 fetch 事件，处理所有进入 Worker 的请求
addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request).catch(err => {
    console.error('Worker Uncaught Error:', err.message, err.stack);
    return new Response('Internal Server Error: ' + err.message, { status: 500 });
  }));
});

// =================================================================================
// 配置区域
// =================================================================================

const KV_NAMESPACE = LINK_STORAGE;
const ADMIN_PASSWORD = 'admin123';
const ADMIN_COOKIE_NAME = 'admin-session';
const ADMIN_SESSION_KEY = 'a-very-secret-key-for-admin-session';

// =================================================================================
// 核心请求处理器
// =================================================================================

async function handleRequest(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  
  if (path === '/') {
    return new Response(getHomePage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (path.startsWith('/admin') || path === '/generate' || path === '/list-links' || path === '/logout') {
    return handleAdminRoutes(request);
  }

  return handleProxyRequest(request);
}

// =================================================================================
// 后台管理模块 (无改动，保持原样)
// =================================================================================
async function handleAdminRoutes(request) {
  const url = new URL(request.url);
  const path = url.pathname;
  const isAdmin = await isAdminAuthenticated(request);

  if (path === '/logout') {
    const headers = new Headers();
    headers.set('Location', `https://${url.hostname}/admin`);
    headers.set('Set-Cookie', `${ADMIN_COOKIE_NAME}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Lax`);
    return new Response(null, { status: 302, headers: headers });
  }

  if (path === '/admin') {
    if (request.method === 'GET') {
      return new Response(getAdminLoginPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    if (request.method === 'POST') {
      const formData = await request.formData();
      if (formData.get('password') === ADMIN_PASSWORD) {
        const headers = new Headers();
        headers.set('Location', `https://${url.hostname}/generate`);
        headers.set('Set-Cookie', `${ADMIN_COOKIE_NAME}=${ADMIN_SESSION_KEY}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Lax`);
        return new Response(null, { status: 302, headers: headers });
      }
      return new Response(getAdminLoginPage('密码错误'), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
  }

  if (!isAdmin) {
    return Response.redirect(`https://${url.hostname}/admin`, 302);
  }

  if (path === '/generate') {
    if (request.method === 'POST') {
      return handleGenerateLink(request);
    }
    return new Response(getLinkGeneratorPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  if (path === '/list-links') {
    if (request.method === 'POST') {
      await handleDeleteLink(request);
      return Response.redirect(`https://${url.hostname}/list-links`, 303);
    }
    return handleListLinks(request);
  }
  
  return new Response('后台页面未找到', { status: 404 });
}

async function isAdminAuthenticated(request) {
  const cookie = request.headers.get('Cookie') || '';
  return cookie.includes(`${ADMIN_COOKIE_NAME}=${ADMIN_SESSION_KEY}`);
}

async function handleGenerateLink(request) {
  const formData = await request.formData();
  const targetUrl = formData.get('targetUrl');
  const linkPassword = formData.get('linkPassword') || generateRandomString(8);
  const lifeTime = parseInt(formData.get('lifeTime') || '3600', 10);

  const normalizedUrl = normalizeUrl(targetUrl);
  if (!normalizedUrl) {
    return new Response(getLinkGeneratorPage('无效的目标URL'), { status: 400, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }

  const randomPath = generateRandomString(6);
  const workerDomain = new URL(request.url).hostname;
  const link = `https://${workerDomain}/${randomPath}`;

  const now = Date.now();
  const expires = lifeTime > 0 ? now + lifeTime * 1000 : null; 

  const data = {
    target: normalizedUrl,
    password: linkPassword,
    expires: expires,
    created: now,
  };

  try {
    await KV_NAMESPACE.put(`link:${randomPath}`, JSON.stringify(data), {
        expiration: expires ? Math.floor(expires / 1000) : undefined
    });
    console.log(`链接已创建: ${link}, 目标: ${normalizedUrl}, 有效期: ${lifeTime}秒`);
  } catch (err) {
    console.error('KV写入错误:', err.message);
    return new Response(getLinkGeneratorPage('创建链接失败，请检查KV配置'), { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
  
  return new Response(getLinkGeneratedPage(link, linkPassword, expires), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
}

async function handleListLinks(request) {
  try {
    const list = await KV_NAMESPACE.list({ prefix: 'link:' });
    let links = await Promise.all(list.keys.map(async (key) => {
      const data = await KV_NAMESPACE.get(key.name, { type: 'json' });
      if (data) {
        return {
          path: key.name.replace('link:', ''),
          target: data.target,
          password: data.password,
          created: new Date(data.created).toLocaleString('zh-CN'),
          expires: data.expires ? new Date(data.expires).toLocaleString('zh-CN') : '永不',
        };
      }
      return null;
    }));
    links = links.filter(Boolean);
    links.sort((a, b) => new Date(b.created) - new Date(a.created));
    return new Response(getLinkListPage(links), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  } catch (err) {
    console.error('KV列表错误:', err.message);
    return new Response(renderPage('错误', '<h1>获取链接列表失败</h1>'), { status: 500, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
}

async function handleDeleteLink(request) {
  const formData = await request.formData();
  const path = formData.get('path');
  if (path) {
    try {
      await KV_NAMESPACE.delete(`link:${path}`);
      console.log(`管理员手动删除链接: link:${path}`);
    } catch (err) {
      console.error('KV删除错误:', err.message);
    }
  }
}

// =================================================================================
// 代理访问模块
// =================================================================================

async function handleProxyRequest(request) {
  const url = new URL(request.url);
  const pathParts = url.pathname.split('/').filter(p => p);
  if (pathParts.length === 0) {
    return new Response('无效的代理路径', { status: 400 });
  }

  const proxyId = pathParts[0];
  const key = `link:${proxyId}`;
  let data;
  try {
    data = await KV_NAMESPACE.get(key, { type: 'json' });
  } catch (err) {
    console.error('KV读取错误:', err.message);
    return new Response('访问链接数据时出错', { status: 500 });
  }

  if (!data) {
    return new Response('链接已失效或不存在', { status: 404 });
  }
  
  const authCookieName = `link-auth-${proxyId}`;
  const cookie = request.headers.get('Cookie') || '';
  const isAuthenticated = cookie.includes(`${authCookieName}=true`);

  if (data.password && !isAuthenticated) {
    if (request.method === 'POST') {
      const formData = await request.formData();
      if (formData.get('password') === data.password) {
        const headers = new Headers();
        headers.set('Location', request.url);
        headers.set('Set-Cookie', `${authCookieName}=true; Path=/${proxyId}; Max-Age=600; HttpOnly; Secure; SameSite=Lax`);
        return new Response(null, { status: 302, headers: headers });
      } else {
        return new Response(getPasswordPage(url.pathname, '密码错误'), { status: 401, headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
      }
    }
    return new Response(getPasswordPage(url.pathname), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
  }
  
  return proxyContent(request, data, proxyId);
}

/**
 * 【已重构】核心反向代理函数
 */
async function proxyContent(request, linkData, proxyId) {
    const originalUrl = new URL(request.url);
    const workerDomain = originalUrl.hostname;
    const pathParts = originalUrl.pathname.split('/').filter(p => p);

    let targetUrl;
    
    // 【重构】解析代理请求URL
    // 格式: /<proxyId>/<hostname>/<path> 或 /<proxyId>/
    if (pathParts.length < 2) {
        // 访问根路径, e.g., /d3tp0l
        targetUrl = new URL(linkData.target);
    } else {
        // 访问页面内资源, e.g., /d3tp0l/www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png
        const targetHost = pathParts[1];
        const targetPath = '/' + pathParts.slice(2).join('/');
        targetUrl = new URL(`https://${targetHost}${targetPath}`);
    }
    targetUrl.search = originalUrl.search;
    targetUrl.hash = originalUrl.hash;

    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('Host', targetUrl.hostname);
    requestHeaders.set('Referer', new URL(linkData.target).origin);

    try {
        const response = await fetch(targetUrl.toString(), {
            method: request.method,
            headers: requestHeaders,
            body: request.body,
            redirect: 'manual',
        });

        const responseHeaders = new Headers(response.headers);
        responseHeaders.delete('Content-Security-Policy');
        responseHeaders.delete('X-Frame-Options');
        responseHeaders.delete('Strict-Transport-Security');

        const rewriter = new UrlRewriter(proxyId, workerDomain, targetUrl.toString());

        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('Location');
            if (location) {
                const rewrittenLocation = rewriter.rewriteUrl(location);
                if (rewrittenLocation) {
                    responseHeaders.set('Location', rewrittenLocation);
                }
                return new Response(null, {
                    status: response.status,
                    headers: responseHeaders,
                });
            }
        }
        
        // 【修复】正确处理响应流和头信息
        // 创建一个全新的、独立的响应对象，用于后续的转换
        const finalResponse = new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: responseHeaders,
        });

        const contentType = response.headers.get('content-type') || '';
        if (contentType.includes('text/html')) {
            return rewriter.transform(finalResponse);
        }

        return finalResponse;

    } catch (err) {
        console.error(`代理抓取错误: ${targetUrl.toString()}`, err.message, err.stack);
        return new Response(`代理请求失败: ${err.message}`, { status: 502 });
    }
}

// =================================================================================
// 辅助函数和类
// =================================================================================

function generateRandomString(length) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return result;
}

function normalizeUrl(inputUrl) {
  try {
    if (!/^[a-zA-Z]+:\/\//.test(inputUrl)) {
      inputUrl = 'https://' + inputUrl;
    }
    return new URL(inputUrl).toString();
  } catch (e) {
    console.error('无效的 URL:', inputUrl);
    return null;
  }
}

class UrlRewriter {
    constructor(proxyId, workerDomain, baseOrigin) {
        this.proxyId = proxyId;
        this.workerDomain = workerDomain;
        this.baseOrigin = baseOrigin; // 当前页面的源，用于解析相对路径
    }

    element(element) {
        const attributes = ['href', 'src', 'action', 'data-src', 'srcset'];
        attributes.forEach(attr => {
            let originalUrl = element.getAttribute(attr);
            if (originalUrl) {
                if (attr === 'srcset') {
                    let rewrittenSrcset = originalUrl.split(',').map(part => {
                        let [url, descriptor] = part.trim().split(/\s+/);
                        const rewritten = this.rewriteUrl(url);
                        return rewritten ? (rewritten + (descriptor ? ` ${descriptor}` : '')) : url;
                    }).join(', ');
                    element.setAttribute(attr, rewrittenSrcset);
                } else {
                    const rewritten = this.rewriteUrl(originalUrl);
                    if (rewritten) {
                        element.setAttribute(attr, rewritten);
                    }
                }
            }
        });
    }

    /**
     * 【重构】统一的URL重写逻辑
     */
    rewriteUrl(url) {
        if (!url || url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:')) {
            return null;
        }
        try {
            // 解析URL，如果是相对路径，会基于当前页面源进行解析
            const absoluteUrl = new URL(url, this.baseOrigin);
            
            // 统一格式: /<proxyId>/<hostname>/<path>
            const proxiedPath = `/${this.proxyId}/${absoluteUrl.hostname}${absoluteUrl.pathname}${absoluteUrl.search}${absoluteUrl.hash}`;
            
            return `https://${this.workerDomain}${proxiedPath}`;
        } catch (e) {
            console.error('URL 重写错误:', url, e.message);
            return url; // 出错时返回原始URL
        }
    }

    // HTMLRewriter需要一个transform方法
    transform(response) {
        const rewriter = new HTMLRewriter()
            .on('a, link, img, script, form, source', this);
        return rewriter.transform(response);
    }
}

// =================================================================================
// HTML 页面模板 (无改动)
// =================================================================================

const inlineCss = `<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background-color:#f4f5f7;margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{background-color:white;padding:2rem 3rem;border-radius:.5rem;box-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -2px rgba(0,0,0,.05);width:100%;max-width:48rem;box-sizing:border-box}h1{font-size:1.5rem;font-weight:600;margin-bottom:1.5rem;text-align:center;color:#111827}.error{color:#ef4444;background-color:#fee2e2;padding:.75rem 1rem;border-radius:.375rem;margin-bottom:1rem;text-align:center}label{display:block;font-size:.875rem;font-weight:500;color:#374151;margin-bottom:.5rem}input[type=text],input[type=password],select{margin-top:.25rem;width:100%;padding:.6rem;border:1px solid #d1d5db;border-radius:.375rem;outline:none;box-sizing:border-box}input:focus,select:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.25)}button{width:100%;background-color:#3b82f6;color:white;padding:.75rem;border-radius:.375rem;border:none;cursor:pointer;font-weight:600;margin-top:1.5rem}button:hover{background-color:#2563eb}a{color:#3b82f6;text-decoration:none;text-align:center;display:block;margin-top:1rem}a:hover{text-decoration:underline}table{width:100%;border-collapse:collapse;margin-top:1.5rem;table-layout:fixed}th,td{padding:.75rem;border:1px solid #e5e7eb;text-align:left;font-size:.875rem;word-break:break-all}th{background-color:#f9fafb;font-weight:600}.font-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace}.text-red{color:#ef4444}.button-delete{background-color:transparent;color:#ef4444;padding:.25rem .5rem;border:1px solid #ef4444;border-radius:.375rem;cursor:pointer;margin-top:0;font-size:.75rem}.button-delete:hover{background-color:#fee2e2}.nav{display:flex;gap:1rem;justify-content:center;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid #e5e7eb}.nav a{margin-top:0;font-weight:500}</style>`;

function renderPage(title, bodyContent) {
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title} - 临时代理服务</title>${inlineCss}</head><body><div class="container">${bodyContent}</div></body></html>`;
}

function getHomePage() {
  return renderPage('欢迎', `<h1>临时链接代理服务</h1><p style="text-align:center;color:#6b7280;">这是一个基于 Cloudflare Worker 的临时链接代理工具。</p><a href="/admin" style="display:inline-block;width:auto;background-color:#3b82f6;color:white;padding:.75rem 2rem;border-radius:.375rem;text-decoration:none;margin-top:2rem;margin-left:50%;transform:translateX(-50%);">前往后台管理</a>`);
}

function getAdminLoginPage(error = '') {
  return renderPage('管理员登录', `<h1>管理员登录</h1>${error ? `<p class="error">${error}</p>` : ''}<form method="POST" action="/admin"><div><label for="password">密码</label><input type="password" name="password" id="password" required></div><button type="submit">登录</button></form>`);
}

const adminNav = `<div class="nav"><a href="/generate">生成新链接</a><a href="/list-links">管理所有链接</a><a href="/logout">退出登录</a></div>`;

function getLinkGeneratorPage(error = '') {
  return renderPage('链接生成器', `${adminNav}<h1>链接生成器</h1>${error ? `<p class="error">${error}</p>` : ''}<form method="POST" action="/generate"><div><label for="targetUrl">目标 URL</label><input type="text" name="targetUrl" id="targetUrl" placeholder="example.com" required></div><div style="margin-top:1rem"><label for="linkPassword">访问密码 (可选，留空则自动生成)</label><input type="password" name="linkPassword" id="linkPassword"></div><div style="margin-top:1rem"><label for="lifeTime">链接有效期</label><select name="lifeTime" id="lifeTime"><option value="600">10 分钟</option><option value="3600" selected>1 小时</option><option value="86400">1 天</option><option value="604800">7 天</option><option value="0">永不</option></select></div><button type="submit">生成链接</button></form>`);
}

function getLinkGeneratedPage(link, password, expires) {
  return renderPage('链接已生成', `${adminNav}<h1>链接已生成</h1><p>您的代理链接: <a href="${link}" target="_blank">${link}</a></p><p>访问密码: <span class="font-mono">${password}</span></p><p>过期时间: ${expires ? new Date(expires).toLocaleString('zh-CN') : '永不'}</p>`);
}

function getLinkListPage(links) {
  const tableBody = links.map(link => `<tr><td><a href="/${link.path}" target="_blank">/${link.path}</a></td><td>${link.target}</td><td class="font-mono">${link.password}</td><td>${link.created}</td><td>${link.expires}</td><td><form method="POST" action="/list-links" onsubmit="return confirm('确定要删除这个链接吗？');"><input type="hidden" name="path" value="${link.path}"><button type="submit" class="button-delete">删除</button></form></td></tr>`).join('');
  return renderPage('链接管理', `${adminNav}<h1>链接管理</h1>${links.length === 0 ? '<p>当前没有有效的链接。</p>' : `<table><colgroup><col style="width: 15%;"><col style="width: 30%;"><col style="width: 15%;"><col style="width: 15%;"><col style="width: 15%;"><col style="width: 10%;"></colgroup><thead><tr><th>代理路径</th><th>目标URL</th><th>密码</th><th>创建于</th><th>过期于</th><th>操作</th></tr></thead><tbody>${tableBody}</tbody></table>`}`);
}

function getPasswordPage(path, error = '') {
  return renderPage('需要密码', `<h1>需要密码访问</h1><p style="text-align:center;color:#6b7280;">此链接已被加密，请输入密码以继续。</p>${error ? `<p class="error">${error}</p>` : ''}<form method="POST" action="${path}"><div><label for="password">链接密码</label><input type="password" name="password" id="password" required></div><button type="submit">提交</button></form>`);
}
