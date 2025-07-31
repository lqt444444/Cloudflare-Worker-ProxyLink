/**
 * Cloudflare Worker for a High-Security Temporary Proxy Link Service
 *
 * Final Version: Reverted to Core Functionality
 * - REVERTED: All proxy logic, rewriting, and client-side scripts have been reverted to the original, most compatible version as requested.
 * - RETAINED: Only the "Custom Link Path" feature has been kept.
 * - REMOVED: Access counter, client-side interception, SRI handling, and other advanced features have been removed to ensure maximum stability and simplicity.
 */

// =================================================================================
// 主入口 (ESM 模块标准)
// Cloudflare Workers 采用 ES Module 格式。
// 这个 `export default` 对象是 Worker 的入口点。
// =================================================================================

export default {
    /**
     * 每个到达 Worker 的 HTTP 请求都会调用这个 fetch 方法。
     * 这是程序的主函数。
     * @param {Request} request - 传入的HTTP请求对象。
     * @param {object} env - 环境变量和绑定的服务（如KV存储）。
     * @param {object} ctx - 请求的上下文对象（用于执行后台任务等）。
     * @returns {Promise<Response>} - 返回一个Promise，最终解析为Response对象。
     */
    async fetch(request, env, ctx) {
        // 使用 try...catch 块捕获任何未处理的异常，防止 Worker 因意外错误而崩溃。
        try {
            // 将请求传递给核心路由处理器。
            return await handleRequest(request, env);
        } catch (err) {
            // 如果发生严重错误，在Worker日志中记录详细信息。例如KV存储桶写入次数用完了
            console.error('Worker Uncaught Error:', err.message, err.stack);
            // 并向用户返回一个通用的服务器内部错误响应。
            return new Response('有问题了，请workers调试界面重试', { status: 500 });
        }
    }
};

// =================================================================================
// 核心请求路由器
// 这个函数是所有请求的第一个处理站，负责判断请求类型并分发给相应的处理模块。
// url.hostname是我们的主机名称 https://${url.hostname}/list-links用于链接后台可视化便捷管理 admin用于后台与登录验证 ，Generate用于创建新的反代链接，每一个链接都是隔离的，不过他们可以任意代理跳转到的网站，logout会给你设置一个过期的cookie，然后让他删除失效
// =================================================================================

async function handleRequest(request, env) {//这就是前面return await handleRequest(request, env);来到的位置
  // 解析传入请求的URL，以便我们可以检查其路径、主机名等。
  const url = new URL(request.url);
  const path = url.pathname;
  
  // 1. 如果是根路径 ("/")，直接返回项目主页。
  if (path === '/') {
      return htmlResponse(getHomePage());
  }

  // 2. 如果路径以 "/admin" 开头或是其他管理功能路径，则交由后台管理模块处理。
  // 这种方式可以清晰地将管理逻辑和代理逻辑分开。
  if (path.startsWith('/admin') || path === '/generate' || path === '/list-links' || path === '/logout') {
      return handleAdminRoutes(request, env);
  }

  // 3. 如果不是以上任何情况，则默认该请求是一个代理请求，交由代理模块处理。
  return handleProxyRequest(request, env);
}

// =================================================================================
// 后台管理模块
// 这一部分处理所有与管理员面板相关的功能，如登录、生成/管理链接等。
// =================================================================================
async function handleAdminRoutes(request, env) {
    // 解析传入请求的URL，以便我们可以检查其路径、主机名等。和前面一样
    const url = new URL(request.url);//URL
    const path = url.pathname;//路径

    // 登出逻辑
    if (path === '/logout') {
        const sessionToken = getCookie(request, 'admin-session-token');//从请求中获取cookie，验证
        if (sessionToken) {
            // 从KV中删除会话令牌，使其失效
            await env.LINK_STORAGE.delete(`session:${sessionToken}`).catch(e => console.error("Session deletion failed", e));
        }
        const headers = new Headers();
        // 重定向回管理员登录页。
        headers.set('Location', `https://${url.hostname}/admin`);
        // 设置一个立即过期的cookie，以从浏览器中清除它。
        headers.set('Set-Cookie', `admin-session-token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`);
        return new Response(null, { status: 302, headers: headers });
    }

    // 登录逻辑 (处理POST请求)
    if (path === '/admin' && request.method === 'POST') {
        const formData = await request.formData();
        // 将提交的密码与环境变量中设置的管理员密码进行比对。
        if (formData.get('password') === env.ADMIN_PASSWORD) {
            // 密码正确，生成一个唯一的会话令牌。
            const sessionToken = crypto.randomUUID();
            // 设置会话过期时间（1小时后），反向代理本身有风险，这样做是为了保护
            const expires = Date.now() + 3600 * 1000;
            // 将会话令牌存入KV，并设置其在KV中的自动过期时间。
            await env.LINK_STORAGE.put(`session:${sessionToken}`, JSON.stringify({ expires }), { expirationTtl: 3600 });
            
            const headers = new Headers();
            // 登录成功后重定向到链接生成页面。
            headers.set('Location', `https://${url.hostname}/generate`);
            // 在用户的浏览器中设置一个安全的、HttpOnly的cookie
            headers.set('Set-Cookie', `admin-session-token=${sessionToken}; Path=/; Max-Age=3600; HttpOnly; Secure; SameSite=Strict`);
            return new Response(null, { status: 302, headers: headers });
        }
        // 密码错误，返回登录页并显示错误信息。
        return htmlResponse(getAdminLoginPage('密码错误'), 401);
    }

    // 在处理需要登录的页面之前，先进行身份验证。
    const isAdmin = await isAdminAuthenticated(request, env);

    // 如果是访问 /admin 页面 (GET请求)，直接显示登录页。
    if (path === '/admin') {
        return htmlResponse(getAdminLoginPage());
    }

    // 如果访问的是其他管理页面但未通过身份验证，强制重定向到登录页。
    if (!isAdmin) {
      return Response.redirect(`https://${url.hostname}/admin`, 302);
    }

    // 已登录用户访问 /generate 页面
    if (path === '/generate') {
      if (request.method === 'POST') {
        return handleGenerateLink(request, env); // 处理表单提交 
      }
      return htmlResponse(getLinkGeneratorPage()); // 显示生成页面
    }

    // 已登录用户访问 /list-links 页面
    if (path === '/list-links') {
      if (request.method === 'POST') {
        await handleDeleteLink(request, env); // 处理删除链接的请求
        return Response.redirect(`https://${url.hostname}/list-links`, 303); // 重定向回列表页
      }
      return handleListLinks(request, env); // 显示链接列表
    }

    // 如果后台路径未找到，返回404。
    return htmlResponse('后台页面未找到', 404);
}

// 处理生成链接的逻辑
// return handleGenerateLink(request, env); // 处理表单提交 
async function handleGenerateLink(request, env) {
    const formData = await request.formData();//获取表单信息，后面都有他
    const targetUrl = formData.get('targetUrl');//formData获取目标
    const linkPassword = formData.get('linkPassword') || generateRandomString(8); // 如果用户没填（值为空），则自动调用 generateRandomString(8) 生成一个8位的随机密码 还是那句话，咋安全咋来，括号里面就是参数
    const lifeTime = parseInt(formData.get('lifeTime') || '3600', 10);
    const normalizedUrl = normalizeUrl(targetUrl);

    if (!normalizedUrl) {
        return htmlResponse(getLinkGeneratorPage('无效的目标URL'), 400);
    }

    // 【唯一保留的新功能】处理自定义路径
    // 从表单获取自定义路径，并进行简单的安全处理（只允许字母、数字、连字符）。
    const customPath = formData.get('customPath')?.trim().replace(/[^a-zA-Z0-9-]/g, '');
    // 如果自定义路径存在，则使用它；否则，生成一个6位的随机路径，多少都行，自己看咋安全咋来
    const linkPath = customPath || generateRandomString(6);

    // 检查路径是否已存在，防止冲突 
    if (linkPath) {
        const existing = await env.LINK_STORAGE.get(`link:${linkPath}`);
        if (existing) {
            return htmlResponse(getLinkGeneratorPage(`自定义路径 "${linkPath}" 别用了，换个`), 400);
        }
    }

    const workerDomain = new URL(request.url).hostname;//主机名加随机路径
    const link = `https://${workerDomain}/${linkPath}`;
    const now = Date.now();//时间读取
    const expires = lifeTime > 0 ? now + lifeTime * 1000 : null; //修正
    
    // 创建要存储在KV中的数据对象（js存储
    const data = { target: normalizedUrl, password: linkPassword, expires: expires, created: now };

    // 将链接数据写入KV。`expiration`选项可以让Cloudflare在指定时间戳自动删除该键。
    await env.LINK_STORAGE.put(`link:${linkPath}`, JSON.stringify(data), {
        expiration: expires ? Math.floor(expires / 1000) : undefined
    });

    // 返回成功页面，显示生成的链接和密码。HTML写最后了，你鼠标滚下去就你能看到了getLinkGeneratedPage 分成模块写的，方便给Ai处理
    return htmlResponse(getLinkGeneratedPage(link, linkPassword, expires));
}

// 处理显示链接列表的逻辑 link管理
async function handleListLinks(request, env) {
    // 列出KV中所有以 "link:" 为前缀的键。
    const list = await env.LINK_STORAGE.list({ prefix: 'link:' });
    // 使用Promise.all并行获取所有链接的详细数据。
    let links = await Promise.all(list.keys.map(async (key) => {
        const data = await env.LINK_STORAGE.get(key.name, { type: 'json' });
        if (data) {
            // 格式化数据以便在模板中使用。
            return { 
                path: key.name.replace('link:', ''), 
                target: data.target, 
                password: data.password, 
                created: new Date(data.created).toLocaleString('zh-CN'), 
                expires: data.expires ? new Date(data.expires).toLocaleString('zh-CN') : '永不' 
            };
        }
        return null;
    }));
    // 过滤掉可能获取失败的null值，并按创建时间倒序排序。
    links = links.filter(Boolean).sort((a, b) => new Date(b.created) - new Date(a.created));
    // 渲染列表页面。
    return htmlResponse(getLinkListPage(links));//HTML模版 下面
}

// 处理删除链接的逻辑
async function handleDeleteLink(request, env) {
    const formData = await request.formData();
    const path = formData.get('path');
    if (path) {
      // 从KV中删除指定的链接。
      await env.LINK_STORAGE.delete(`link:${path}`);
    }
}

// =================================================================================
// 代理访问模块
// 这是整个服务的核心功能，处理对代理链接的访问。突破美丽而又极品的GfW
// =================================================================================

async function handleProxyRequest(request, env) {
  const url = new URL(request.url);
  // 从路径中解析出代理ID，例如 /abcdef/... 中的 "abcdef"。
  const pathParts = url.pathname.split('/').filter(p => p);
  if (pathParts.length === 0) return new Response('无效的代理路径', { status: 400 });

  const proxyId = pathParts[0];
  // 从KV中获取该代理ID对应的链接数据。
  const data = await env.LINK_STORAGE.get(`link:${proxyId}`, { type: 'json' });

  // 如果找不到数据，说明链接不存在或已过期。
  if (!data) return htmlResponse('链接已失效或不存在', 404);//HTML模版 下面

  // 检查密码保护
  const authCookieName = `link-auth-${proxyId}`;
  const isAuthenticated = getCookie(request, authCookieName) === 'true';

  if (data.password && !isAuthenticated) {//验证密码通过不，不通过就折磨我吧 啊啊啊啊不要啊，主人——
      // 如果链接需要密码，且用户未通过验证（没有有效的cookie）
      if (request.method === 'POST') {
          // 如果是提交密码的POST请求
          const formData = await request.formData();
          if (formData.get('password') === data.password) {
              // 密码正确，设置一个临时cookie并重定向回当前页面
              const headers = new Headers({ 'Location': request.url });
              headers.set('Set-Cookie', `${authCookieName}=true; Path=/${proxyId}; Max-Age=600; HttpOnly; Secure; SameSite=Strict`);
              return new Response(null, { status: 302, headers: headers });
          } else {
              // 密码错误，显示错误信息
              return htmlResponse(getPasswordPage(url.pathname, '密码错误'), 401);
          }
      }
      // 如果是GET请求，显示密码输入页面
      return htmlResponse(getPasswordPage(url.pathname));
  }

  // 验证通过，开始代理内容
  return proxyContent(request, data, proxyId);
}

//这是代理的核心实现，采用“开放代理”模式
async function proxyContent(request, linkData, proxyId) {
  const originalUrl = new URL(request.url);
  const workerDomain = originalUrl.hostname;
  const pathParts = originalUrl.pathname.split('/').filter(p => p);//前面有 不过说了

  let targetUrl;
  // 这个判断是“开放代理”的关键
  if (pathParts.length < 2) {
      // 如果路径只有代理ID (e.g., /abcdef)，则访问链接创建时设定的原始目标
      targetUrl = new URL(linkData.target);
  } else {
      // 如果路径更长 (e.g., /abcdef/another.com/path)，则将第二部分作为新的主机名来代理
      const targetHost = pathParts[1];
      const targetPath = '/' + pathParts.slice(2).join('/');
      targetUrl = new URL(`https://${targetHost}${targetPath}`);
  }
  // 保留原始的查询参数和哈希
  targetUrl.search = originalUrl.search;
  targetUrl.hash = originalUrl.hash;

  // 复制请求头，并进行修改
  const requestHeaders = new Headers(request.headers);
  // 将Host头修改为目标网站的，这对很多网站来说是必须的
  requestHeaders.set('Host', targetUrl.hostname);
  // 将Referer头修改为目标网站的根域，提高兼容性
  requestHeaders.set('Referer', new URL(linkData.target).origin);
  // 传递客户端的真实IP
  const clientIp = request.headers.get('CF-Connecting-IP');
  if (clientIp) {
      requestHeaders.set('X-Forwarded-For', clientIp);
      requestHeaders.set('X-Real-IP', clientIp); 
  }
  // 删除Cloudflare添加的一些特定请求头，避免暴露信息或引起循环 依旧访问不了CF网站
  requestHeaders.delete('CF-Worker');

  try {
      // 向目标服务器发起请求
      const response = await fetch(targetUrl.toString(), {
          method: request.method, headers: requestHeaders, body: request.body, redirect: 'manual',
      });

      // 复制响应头，并进行修改
      const responseHeaders = new Headers(response.headers);
      
      // 【重要】删除目标网站的CSP和X-Frame-Options头，这是代理能正常工作的关键。
      // 否则，目标网站的安全策略会阻止在我们的域名下加载其资源。
      responseHeaders.delete('Content-Security-Policy');
      responseHeaders.delete('Content-Security-Policy-Report-Only');
      responseHeaders.delete('X-Frame-Options');

      // 创建一个URL重写器实例 最他妈烦心的玩意，还有后期加载的资源 YouTube司马的跳转，AI都他妈觉得心烦
      const rewriter = new UrlRewriter(proxyId, workerDomain, targetUrl.toString());

      // 处理3xx重定向
      if (response.status >= 300 && response.status < 400) {
          const location = response.headers.get('Location');
          if (location) {
              // 重写重定向的URL，使其继续通过我们的代理
              const rewrittenLocation = rewriter.rewriteUrl(location);
              if (rewrittenLocation) responseHeaders.set('Location', rewrittenLocation);
              return new Response(null, { status: response.status, headers: responseHeaders });
          }
      }
      
      const contentType = response.headers.get('content-type') || '';

      // 如果响应是HTML，使用HTMLRewriter进行内容重写
      if (contentType.includes('text/html')) {
          return rewriter.transform(new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders }));
      }
      
      // 如果响应是JSON，尝试解析并重写其中的URL
      if (contentType.includes('application/json')) {
          try {
              const bodyText = await response.text();
              if(bodyText) {
                  const data = JSON.parse(bodyText);
                  rewriteUrlsInObject(data, rewriter); // 递归重写
                  const newBody = JSON.stringify(data);
                  responseHeaders.set('Content-Length', newBody.length.toString());
                  return new Response(newBody, { status: response.status, statusText: response.statusText, headers: responseHeaders });
              }
          } catch(e) {
              // 如果JSON处理失败，什么都不做，直接返回原始响应
              console.error("JSON processing error:", e);
          }
      }

      // 对于其他类型的内容（如图片、视频），直接返回原始响应体
      return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });

  } catch (err) {
      console.error(`代理抓取错误: ${targetUrl.toString()}`, err.message, err.stack);
      return new Response(`代理请求失败: ${err.message}`, { status: 502 });
  }
}
// =================================================================================
// 辅助函数和类
// =================================================================================

// 检查管理员是否已通过身份验证
async function isAdminAuthenticated(request, env) {
    const sessionToken = getCookie(request, 'admin-session-token');
    if (!sessionToken) return false;
    const session = await env.LINK_STORAGE.get(`session:${sessionToken}`, { type: 'json' });
    // 验证会话是否存在且未过期
    return session && session.expires >= Date.now();
}

// 统一创建HTML响应的函数，确保总是带有正确的头部
function htmlResponse(body, status = 200) {
    const response = new Response(body, {
        status: status,
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
    });
    return addSecurityHeaders(response);
}

// 为响应添加一些基础的安全头
function addSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set('X-Content-Type-Options', 'nosniff'); // 防止浏览器MIME类型嗅探
  headers.set('X-Frame-Options', 'DENY'); // 防止页面被嵌入到iframe中
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin'); // 控制Referer头的发送策略
  return new Response(response.body, {
      status: response.status, statusText: response.statusText, headers: headers
  });
}

// 从请求头中解析指定名称的cookie值
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

// 生成指定长度的随机字符串
function generateRandomString(length) {
    const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// 规范化URL，确保它以 http(s):// 开头
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

// 【已回滚】递归地重写一个JS对象中所有字符串类型的URL
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

// 【已回滚】核心的URL重写类 噩梦缠绕啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊啊
class UrlRewriter {
  constructor(proxyId, workerDomain, baseOrigin) {
      this.proxyId = proxyId;
      this.workerDomain = workerDomain;
      this.baseOrigin = baseOrigin; // 当前正在处理的页面的URL，用于解析相对路径
      this.attributesToRewrite = [
          'href', 'src', 'action', 'srcset', 'poster',
          'data-src', 'data-href', 'data-url', 'data-mw-src'
      ];
  }

  // HTMLRewriter的元素处理器
  element(element) {
      this.attributesToRewrite.forEach(attr => {
          const originalUrl = element.getAttribute(attr);
          if (originalUrl) {
              if (attr === 'srcset') {
                  // 特殊处理srcset，因为它包含多个URL
                  const rewrittenSrcset = originalUrl.split(',').map(part => {
                      const [url, descriptor] = part.trim().split(/\s+/);
                      const rewritten = this.rewriteUrl(url);
                      return rewritten !== url ? (rewritten + (descriptor ? ` ${descriptor}` : '')) : url;
                  }).join(', ');
                  element.setAttribute(attr, rewrittenSrcset);
              } else {
                  // 对单个URL进行重写
                  const rewritten = this.rewriteUrl(originalUrl);
                  if (rewritten !== originalUrl) {
                      element.setAttribute(attr, rewritten);
                  }
              }
          }
      });
  }

  // URL重写的核心逻辑
  rewriteUrl(url) {
      // 忽略特殊协议的URL
      if (!url || url.startsWith('data:') || url.startsWith('blob:') || url.startsWith('javascript:')) {
          return url;
      }
      try {
          // 使用 new URL(url, base) 可以优雅地将相对路径（如 /path/to/img.png）
          // 解析为基于当前页面的绝对URL（如 https://example.com/path/to/img.png）。
          const absoluteUrl = new URL(url, this.baseOrigin);
          // 构建新的代理路径格式：/{代理ID}/{目标主机名}/{原始路径}
          const proxiedPath = `/${this.proxyId}/${absoluteUrl.hostname}${absoluteUrl.pathname}${absoluteUrl.search}${absoluteUrl.hash}`;
          return `https://${this.workerDomain}${proxiedPath}`;
      } catch (e) {
          // 如果URL无效，返回原始值
          return url;
      }
  }

  // 设置并返回一个配置好的HTMLRewriter实例
  transform(response) {
      const selector = this.attributesToRewrite.map(attr => `*[${attr}]`).join(', ');
      const rewriter = new HTMLRewriter().on(selector, this);
      return rewriter.transform(response);
  }
}

// =================================================================================
// HTML 页面模板
// 这部分代码负责生成所有用户能看到的非代理页面（如主页、登录页、管理页等）。
// =================================================================================

const inlineCss = `<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background-color:#f4f5f7;margin:0;display:flex;justify-content:center;align-items:center;min-height:100vh}.container{background-color:white;padding:2rem 3rem;border-radius:.5rem;box-shadow:0 10px 15px -3px rgba(0,0,0,.1),0 4px 6px -2px rgba(0,0,0,.05);width:100%;max-width:64rem;box-sizing:border-box}h1{font-size:1.5rem;font-weight:600;margin-bottom:1.5rem;text-align:center;color:#111827}.error{color:#ef4444;background-color:#fee2e2;padding:.75rem 1rem;border-radius:.375rem;margin-bottom:1rem;text-align:center}label{display:block;font-size:.875rem;font-weight:500;color:#374151;margin-bottom:.5rem}input[type=text],input[type=password],select{margin-top:.25rem;width:100%;padding:.6rem;border:1px solid #d1d5db;border-radius:.375rem;outline:none;box-sizing:border-box}input:focus,select:focus{border-color:#3b82f6;box-shadow:0 0 0 3px rgba(59,130,246,.25)}button{width:100%;background-color:#3b82f6;color:white;padding:.75rem;border-radius:.375rem;border:none;cursor:pointer;font-weight:600;margin-top:1.5rem}button:hover{background-color:#2563eb}a{color:#3b82f6;text-decoration:none;text-align:center;display:block;margin-top:1rem}a:hover{text-decoration:underline}table{width:100%;border-collapse:collapse;margin-top:1.5rem;table-layout:fixed}th,td{padding:.75rem;border:1px solid #e5e7eb;text-align:left;font-size:.875rem;word-break:break-all}th{background-color:#f9fafb;font-weight:600}.font-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,Liberation Mono,Courier New,monospace}.text-red{color:#ef4444}.button-delete{background-color:transparent;color:#ef4444;padding:.25rem .5rem;border:1px solid #ef4444;border-radius:.375rem;cursor:pointer;margin-top:0;font-size:.75rem}.button-delete:hover{background-color:#fee2e2}.nav{display:flex;gap:1rem;justify-content:center;margin-bottom:2rem;padding-bottom:1rem;border-bottom:1px solid #e5e7eb}.nav a{margin-top:0;font-weight:500}</style>`;

// 基础页面渲染函数
function renderPage(title, bodyContent) {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title} - 临时代理服务</title>${inlineCss}</head><body><div class="container">${bodyContent}</div></body></html>`;
}

// 主页
function getHomePage() {
    return renderPage('欢迎', `<h1>临时链接代理服务</h1><p style="text-align:center;color:#6b7280;">这是一个基于 Cloudflare Worker 的临时链接代理工具。</p><a href="/admin" style="display:inline-block;width:auto;background-color:#3b82f6;color:white;padding:.75rem 2rem;border-radius:.375rem;text-decoration:none;margin-top:2rem;margin-left:50%;transform:translateX(-50%);">前往后台管理</a>`);
}

// 管理员登录页
function getAdminLoginPage(error = '') {
    return renderPage('管理员登录', `<h1>管理员登录</h1>${error ? `<p class="error">${error}</p>` : ''}<form method="POST" action="/admin"><div><label for="password">密码</label><input type="password" name="password" id="password" required></div><button type="submit">登录</button></form>`);
}

// 后台导航栏
const adminNav = `<div class="nav"><a href="/generate">生成新链接</a><a href="/list-links">管理所有链接</a><a href="/logout">退出登录</a></div>`;

// 链接生成页
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

// 链接生成成功页getLinkGeneratedPage
function getLinkGeneratedPage(link, password, expires) {
    return renderPage('链接已生成', `${adminNav}<h1>链接已生成</h1><p>您的代理链接: <a href="${link}" target="_blank">${link}</a></p><p>访问密码: <span class="font-mono">${password}</span></p><p>过期时间: ${expires ? new Date(expires).toLocaleString('zh-CN') : '永不'}</p>`);
}

// 链接管理列表页
function getLinkListPage(links) {
    const tableBody = links.map(link => `
<tr>
    <td><a href="/${link.path}" target="_blank">/${link.path}</a></td>
    <td>${link.target}</td>
    <td class="font-mono">${link.password}</td>
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
    <colgroup><col style="width: 15%;"><col style="width: 30%;"><col style="width: 15%;"><col style="width: 15%;"><col style="width: 15%;"><col style="width: 10%;"></colgroup>
    <thead><tr><th>代理路径</th><th>目标URL</th><th>密码</th><th>创建于</th><th>过期于</th><th>操作</th></tr></thead>
    <tbody>${tableBody}</tbody>
</table>`}`);
}

// 密码输入页
function getPasswordPage(path, error = '') {
    return renderPage('需要密码', `<h1>需要密码访问</h1><p style="text-align:center;color:#6b7280;">此链接已被加密，请输入密码以继续。</p>${error ? `<p class="error">${error}</p>` : ''}<form method="POST" action="${path}"><div><label for="password">链接密码</label><input type="password" name="password" id="password" required></div><button type="submit">提交</button></form>`);
}
