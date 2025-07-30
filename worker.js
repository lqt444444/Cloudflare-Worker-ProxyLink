/**
 * Cloudflare Worker for a High-Security Temporary Proxy Link Service
 *
 * Final Version: Reverted Rewriter & Feature Retention
 * - REVERTED: HTML rewriter and core proxy logic have been reverted to the original version to resolve compatibility issues.
 * - RETAINED: "Custom Path" and "Access Count" features are fully functional.
 * - NOTE: The proxy logic reversion re-enables the "open proxy" characteristic of the original script.
 */

// =================================================================================
// 主入口 (ESM 模块标准)
// =================================================================================

export default {
    async fetch(request, env, ctx) {
        try {
            return await handleRequest(request, env, ctx);
        } catch (err) {
            console.error('Worker Uncaught Error:', err.message, err.stack);
            return new Response('Internal Server Error', { status: 500 });
        }
    }
};

// =================================================================================
// 核心请求路由器
// =================================================================================

async function handleRequest(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/') {
        return htmlResponse(getHomePage());//返回主页
    }
//三个管理员可访问路径
    if (path.startsWith('/admin') || path === '/generate' || path === '/list-links' || path === '/logout') {
        return handleAdminRoutes(request, env);
    }

    return handleProxyRequest(request, env, ctx);
}

// =================================================================================
// 后台管理模块
// =================================================================================
async function handleAdminRoutes(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/logout') {//退出登录 
        const sessionToken = getCookie(request, 'admin-session-token');
        if (sessionToken) {
            await env.LINK_STORAGE.delete(`session:${sessionToken}`).catch(e => console.error("Session deletion failed", e));
        }
        const headers = new Headers();
        headers.set('Location', `https://${url.hostname}/admin`);
        headers.set('Set-Cookie', `admin-session-token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`);
        return new Response(null, { status: 302, headers: headers });
    }

    if (path === '/admin' && request.method === 'POST') {//登录界面
        const formData = await request.formData();
        if (formData.get('password') === env.ADMIN_PASSWORD) {//ADMIN_PASSWORD这个就是环境变量需要设置的，记得加
            const sessionToken = crypto.randomUUID();
            const expires = Date.now() + 3600 * 1000;//免密时间
            await env.LINK_STORAGE.put(`session:${sessionToken}`, JSON.stringify({ expires }), { expirationTtl: 3600 });
            const headers = new Headers();
            headers.set('Location', `https://${url.hostname}/generate`);
            headers.set('Set-Cookie', `admin-session-token=${sessionToken}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict`);
            return new Response(null, { status: 302, headers: headers });
        }
        return htmlResponse(getAdminLoginPage('密码错误'), 401);
    }

    const isAdmin = await isAdminAuthenticated(request, env);

    if (path === '/admin') {
        return htmlResponse(getAdminLoginPage());
    }

    if (!isAdmin) {
      return Response.redirect(`https://${url.hostname}/admin`, 302);
    }

    if (path === '/generate') {//新建链接
      if (request.method === 'POST') {
        return handleGenerateLink(request, env);
      }
      return htmlResponse(getLinkGeneratorPage());
    }

    if (path === '/list-links') {//管理
      if (request.method === 'POST') {
        await handleDeleteLink(request, env);
        return Response.redirect(`https://${url.hostname}/list-links`, 303);
      }
      return handleListLinks(request, env);
    }

    return htmlResponse('后台页面未找到', 404);
}

async function handleGenerateLink(request, env) {
    const formData = await request.formData();
    const targetUrl = formData.get('targetUrl');
    const linkPassword = formData.get('linkPassword') || generateRandomString(8);
    const lifeTime = parseInt(formData.get('lifeTime') || '3600', 10);
    const normalizedUrl = normalizeUrl(targetUrl);

    if (!normalizedUrl) {
        return htmlResponse(getLinkGeneratorPage('无效的目标URL'), 400);
    }

    const customPath = formData.get('customPath')?.trim().replace(/[^a-zA-Z0-9-]/g, '');
    const linkPath = customPath || generateRandomString(6);

    if (linkPath) {
        const existing = await env.LINK_STORAGE.get(`link:${linkPath}`);
        if (existing) {
            return htmlResponse(getLinkGeneratorPage(`自定义路径 "${linkPath}" 已存在，请更换一个。`), 400);
        }
    }

    const workerDomain = new URL(request.url).hostname;
    const link = `https://${workerDomain}/${linkPath}`;
    const now = Date.now();
    const expires = lifeTime > 0 ? now + lifeTime * 1000 : null;

    // 保留新功能：在数据中加入 views: 0
    const data = {
        target: normalizedUrl, password: linkPassword, expires: expires, created: now, views: 0
    };

    await env.LINK_STORAGE.put(`link:${linkPath}`, JSON.stringify(data), {
        expiration: expires ? Math.floor(expires / 1000) : undefined
    });

    return htmlResponse(getLinkGeneratedPage(link, linkPassword, expires));
}

async function handleListLinks(request, env) {
    const list = await env.LINK_STORAGE.list({ prefix: 'link:' });
    let links = await Promise.all(list.keys.map(async (key) => {
        const data = await env.LINK_STORAGE.get(key.name, { type: 'json' });
        if (data) {
            // 返回链接数据时包含访问次数
            return {
                path: key.name.replace('link:', ''),
                target: data.target,
                password: data.password,
                created: new Date(data.created).toLocaleString('zh-CN'),
                expires: data.expires ? new Date(data.expires).toLocaleString('zh-CN') : '永不',
                views: data.views || 0
            };
        }
        return null;
    }));
    links = links.filter(Boolean).sort((a, b) => new Date(b.created) - new Date(a.created));
    return htmlResponse(getLinkListPage(links));
}

async function handleDeleteLink(request, env) {
    const formData = await request.formData();
    const path = formData.get('path');
    if (path) {
        await env.LINK_STORAGE.delete(`link:${path}`);
    }
}

// =================================================================================
// 代理访问模块
// =================================================================================

async function handleProxyRequest(request, env, ctx) {
    const url = new URL(request.url);
    const pathParts = url.pathname.split('/').filter(p => p);
    if (pathParts.length === 0) return new Response('无效的代理路径', { status: 400 });

    const proxyId = pathParts[0];
    const data = await env.LINK_STORAGE.get(`link:${proxyId}`, { type: 'json' });

    if (!data) return htmlResponse('链接已失效或不存在', 404);

    const authCookieName = `link-auth-${proxyId}`;
    const isAuthenticated = getCookie(request, authCookieName) === 'true';

    if (data.password && !isAuthenticated) {
        if (request.method === 'POST') {
            const formData = await request.formData();
            if (formData.get('password') === data.password) {
                const headers = new Headers({ 'Location': request.url });
                headers.set('Set-Cookie', `${authCookieName}=true; Path=/${proxyId}; Max-Age=600; HttpOnly; Secure; SameSite=Strict`);
                return new Response(null, { status: 302, headers: headers });
            } else {
                return htmlResponse(getPasswordPage(url.pathname, '密码错误'), 401);
            }
        }
        return htmlResponse(getPasswordPage(url.pathname));
    }

    // 将 ctx, env 传递给 proxyContent 以实现访问计数
    return proxyContent(request, data, proxyId, env, ctx);
}

/**
 * 【此函数已恢复到原始版本，同时集成了访问计数功能。
 */
async function proxyContent(request, linkData, proxyId, env, ctx) {
    const originalUrl = new URL(request.url);
    const workerDomain = originalUrl.hostname;
    const pathParts = originalUrl.pathname.split('/').filter(p => p);

    // 异步更新访问次数
    ctx.waitUntil((async () => {
        const currentDataStr = await env.LINK_STORAGE.get(`link:${proxyId}`);
        if (!currentDataStr) return;
        const currentData = JSON.parse(currentDataStr);
        currentData.views = (currentData.views || 0) + 1;
        await env.LINK_STORAGE.put(`link:${proxyId}`, JSON.stringify(currentData), {
            expiration: currentData.expires ? Math.floor(currentData.expires / 1000) : undefined
        });
    })());

    // URL 构建逻辑猿人版本 AI
    let targetUrl;
    if (pathParts.length < 2) {
        targetUrl = new URL(linkData.target);
    } else {
        const targetHost = pathParts[1];
        const targetPath = '/' + pathParts.slice(2).join('/');
        targetUrl = new URL(`https://${targetHost}${targetPath}`);
    }
    targetUrl.search = originalUrl.search;
    targetUrl.hash = originalUrl.hash;

    const requestHeaders = new Headers(request.headers);
    requestHeaders.set('Host', targetUrl.hostname);
    requestHeaders.set('Referer', new URL(linkData.target).origin);
    const clientIp = request.headers.get('CF-Connecting-IP');
    if (clientIp) {
        requestHeaders.set('X-Forwarded-For', clientIp);
        requestHeaders.set('X-Real-IP', clientIp);
    }
    requestHeaders.delete('CF-Worker');
    requestHeaders.delete('CF-RAY');
    requestHeaders.delete('CF-Visitor');
    requestHeaders.delete('CF-EW-Via');
    requestHeaders.delete('CDN-Loop');

    try {
        const response = await fetch(targetUrl.toString(), {
            method: request.method, headers: requestHeaders, body: request.body, redirect: 'manual',
        });

        const responseHeaders = new Headers(response.headers);
        responseHeaders.delete('Content-Security-Policy');
        responseHeaders.delete('Content-Security-Policy-Report-Only');
        responseHeaders.delete('X-Frame-Options');

        const rewriter = new UrlRewriter(proxyId, workerDomain, targetUrl.toString());

        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get('Location');
            if (location) {
                const rewrittenLocation = rewriter.rewriteUrl(location);
                if (rewrittenLocation) responseHeaders.set('Location', rewrittenLocation);
                return new Response(null, { status: response.status, headers: responseHeaders });
            }
        }

        const contentType = response.headers.get('content-type') || '';

        if (contentType.includes('text/html')) {
            return rewriter.transform(new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders }));
        }

        if (contentType.includes('application/json')) {
            try {
                const bodyText = await response.text();
                if(bodyText) {
                    const data = JSON.parse(bodyText);
                    rewriteUrlsInObject(data, rewriter);
                    const newBody = JSON.stringify(data);
                    responseHeaders.set('Content-Length', newBody.length.toString());
                    return new Response(newBody, { status: response.status, statusText: response.statusText, headers: responseHeaders });
                }
            } catch(e) {
                console.error("JSON processing error:", e);
            }
        }

        return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });

    } catch (err) {
        console.error(`代理抓取错误: ${targetUrl.toString()}`, err.message, err.stack);
        return new Response(`代理请求失败: ${err.message}`, { status: 502 });
    }
}
// =================================================================================
// 辅助函数和类
// =================================================================================

function htmlResponse(body, status = 200) {
    const response = new Response(body, {
        status: status,
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
    return addSecurityHeaders(response);
}

async function isAdminAuthenticated(request, env) {
    const sessionToken = getCookie(request, 'admin-session-token');
    if (!sessionToken) return false;

    const session = await env.LINK_STORAGE.get(`session:${sessionToken}`, { type: 'json' });
    return session && session.expires >= Date.now();
}

function addSecurityHeaders(response) {
    const headers = new Headers(response.headers);
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'DENY');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    return new Response(response.body, {
        status: response.status, statusText: response.statusText, headers: headers
    });
}

function getCookie(request, name) {
    const cookieString = request.headers.get('Cookie');
    if (cookieString) {
        for (const cookie of cookieString.split(';')) {
            const [cookieName, cookieValue] = cookie.trim().split(/=(.*)/s);
            if (cookieName === name) {
                return cookieValue;
            }
        }
    }
    return null;
}

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
        return null;
    }
}

/**
 * 【AI
 */
function rewriteUrlsInObject(obj, rewriter) {
  for (const key in obj) {
      if (typeof obj[key] === 'string') {
          const originalValue = obj[key];
          const rewrittenValue = rewriter.rewriteUrl(originalValue);
          if (rewrittenValue !== originalValue) {
              obj[key] = rewrittenValue;
          }
      } else if (typeof obj[key] === 'object' && obj[key] !== null) {
          rewriteUrlsInObject(obj[key], rewriter);
      }
  }
}

/**
 * AI
 */
class UrlRewriter {
  constructor(proxyId, workerDomain, baseOrigin) {
      this.proxyId = proxyId;
      this.workerDomain = workerDomain;
      this.baseOrigin = baseOrigin;
      this.attributesToRewrite = [
          'href', 'src', 'action', 'srcset', 'poster',
          'data-src', 'data-href', 'data-url', 'data-mw-src'
      ];
  }

  element(element) {
      this.attributesToRewrite.forEach(attr => {
          const originalUrl = element.getAttribute(attr);
          if (originalUrl) {
              if (attr === 'srcset') {
                  const rewrittenSrcset = originalUrl.split(',').map(part => {
                      const [url, descriptor] = part.trim().split(/\s+/);
                      const rewritten = this.rewriteUrl(url);
                      return rewritten !== url ? (rewritten + (descriptor ? ` ${descriptor}` : '')) : url;
                  }).join(', ');
                  element.setAttribute(attr, rewrittenSrcset);
              } else {
                  const rewritten = this.rewriteUrl(originalUrl);
                  if (rewritten !== originalUrl) {
                      element.setAttribute(attr, rewritten);
                  }
              }
          }
      });
  }

  rewriteUrl(url) {
      if (!url || url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:')) {
          return url;
      }
      try {
          const absoluteUrl = new URL(url, this.baseOrigin);
          const proxiedPath = `/${this.proxyId}/${absoluteUrl.hostname}${absoluteUrl.pathname}${absoluteUrl.search}${absoluteUrl.hash}`;
          return `https://${this.workerDomain}${proxiedPath}`;
      } catch (e) {
          return url;
      }
  }

  transform(response) {
      const selector = this.attributesToRewrite.map(attr => `*[${attr}]`).join(', ');
      const rewriter = new HTMLRewriter().on(selector, this);
      return rewriter.transform(response);
  }
}

// =================================================================================
// HTML 页面模板
// =================================================================================
const inlineCss = `<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background-color:#f4f5f7;margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{background-color:white;padding:2rem 3rem;border-radius:.5rem;box-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -2px rgba(0,0,0,.05);width:100%;max-width:64rem;box-sizing:border-box}h1{font-size:1.5rem;font-weight:600;margin-bottom:1.5rem;text-align:center;color:#111827}.error{color:#ef4444;background-color:#fee2e2;padding:.75rem 1rem;border-radius:.375rem;margin-bottom:1rem;text-align:center}label{display:block;font-size:.875rem;font-weight:500;color:#374151;margin-bottom:.5rem}input[type=text],input[type=password],select{margin-top:.25rem;width:100%;padding:.6rem;border:1px solid #d1d5db;border-radius:.375rem;outline:none;box-sizing:border-box}input:focus,select:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.25)}button{width:100%;background-color:#3b82f6;color:white;padding:.75rem;border-radius:.375rem;border:none;cursor:pointer;font-weight:600;margin-top:1.5rem}button:hover{background-color:#2563eb}a{color:#3b82f6;text-decoration:none;text-align:center;display:block;margin-top:1rem}a:hover{text-decoration:underline}table{width:100%;border-collapse:collapse;margin-top:1.5rem;table-layout:fixed}th,td{padding:.75rem;border:1px solid #e5e7eb;text-align:left;font-size:.875rem;word-break:break-all}th{background-color:#f9fafb;font-weight:600}.font-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace}.text-red{color:#ef4444}.button-delete{background-color:transparent;color:#ef4444;padding:.25rem .5rem;border:1px solid #ef4444;border-radius:.375rem;cursor:pointer;margin-top:0;font-size:.75rem}.button-delete:hover{background-color:#fee2e2}.nav{display:flex;gap:1rem;justify-content:center;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid #e5e7eb}.nav a{margin-top:0;font-weight:500}</style>`;

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

// 增加自定义路径的表单项
function getLinkGeneratorPage(error = '') {
    return renderPage('链接生成器', `${adminNav}<h1>链接生成器</h1>${error ? `<p class="error">${error}</p>` : ''}
<form method="POST" action="/generate">
    <div><label for="targetUrl">目标 URL</label><input type="text" name="targetUrl" id="targetUrl" placeholder="example.com" required></div>
    <div style="margin-top:1rem"><label for="customPath">自定义路径 (可选, 仅字母/数字/连字符)</label><input type="text" name="customPath" id="customPath" pattern="[a-zA-Z0-9-]+" placeholder="my-secret-link"></div>
    <div style="margin-top:1rem"><label for="linkPassword">访问密码 (可选，留空则自动生成)</label><input type="password" name="linkPassword" id="linkPassword"></div>
    <div style="margin-top:1rem"><label for="lifeTime">链接有效期</label><select name="lifeTime" id="lifeTime"><option value="600">10 分钟</option><option value="3600" selected>1 小时</option><option value="86400">1 天</option><option value="604800">7 天</option><option value="0">永不</option></select></div>
    <button type="submit">生成链接</button>
</form>`);
}

function getLinkGeneratedPage(link, password, expires) {
    return renderPage('链接已生成', `${adminNav}<h1>链接已生成</h1><p>您的代理链接: <a href="${link}" target="_blank">${link}</a></p><p>访问密码: <span class="font-mono">${password}</span></p><p>过期时间: ${expires ? new Date(expires).toLocaleString('zh-CN') : '永不'}</p>`);
}

// 在表格中增加“访问次数”列
function getLinkListPage(links) {
    const tableBody = links.map(link => `
<tr>
    <td><a href="/${link.path}" target="_blank">/${link.path}</a></td>
    <td>${link.target}</td>
    <td class="font-mono">${link.password}</td>
    <td>${link.views}</td>
    <td>${link.created}</td>
    <td>${link.expires}</td>
    <td>
        <form method="POST" action="/list-links" onsubmit="return confirm('确定要删除这个链接吗？');">
            <input type="hidden" name="path" value="${link.path}">
            <button type="submit" class="button-delete">删除</button>
        </form>
    </td>
</tr>`).join('');

    return renderPage('链接管理', `${adminNav}<h1>链接管理</h1>${links.length === 0 ? '<p>当前没有有效的链接。</p>' : `
<table>
    <colgroup>
        <col style="width: 15%;"><col style="width: 25%;"><col style="width: 12%;"><col style="width: 8%;"><col style="width: 15%;"><col style="width: 15%;"><col style="width: 10%;">
    </colgroup>
    <thead>
        <tr><th>代理路径</th><th>目标URL</th><th>密码</th><th>访问次数</th><th>创建于</th><th>过期于</th><th>操作</th></tr>
    </thead>
    <tbody>${tableBody}</tbody>
</table>`}`);
}

function getPasswordPage(path, error = '') {
    return renderPage('需要密码', `<h1>需要密码访问</h1><p style="text-align:center;color:#6b7280;">此链接已被加密，请输入密码以继续。</p>${error ? `<p class="error">${error}</p>` : ''}<form method="POST" action="${path}"><div><label for="password">链接密码</label><input type="password" name="password" id="password" required></div><button type="submit">提交</button></form>`);
}
