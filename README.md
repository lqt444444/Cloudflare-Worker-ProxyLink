## Cloudflare-Worker-ProxyLink

一个功能强大、自行部署的临时链接反向代理服务，完全基于 Cloudflare Workers 和 KV 存储，无需服务器。

 新增cookie随机生成 提高安全性
---

## 核心功能

-   **管理员后台**: 通过密码保护的后台，统一管理所有代理链接。
-   **安全的会话管理**: 基于 Cookie 的管理员会话，无需重复登录。
-   **链接生成**: 为任意 URL 生成一个安全的、具有随机路径的代理链接。
-   **自定义有效期**: 可为每个链接设置独立的有效期（10分钟、1小时、1天、7天或永不过期）。
-   **链接密码保护**: 可以为每个生成的代理链接设置独立的访问密码。
-   **10分钟免密访问**: 终端用户输入一次链接密码后，10分钟内无需再次验证，提升浏览体验。
-   **强大的反向代理引擎**:
    -   正确处理并重写 HTTP 3xx 重定向，防止“跳转到原网页”。
    -   通过 `HTMLRewriter` 动态重写页面内的所有 URL（包括 `href`, `src`, `action` 等）。
    -   完美支持跨域（CDN）资源的代理和重写。
-   **链接管理面板**: 在后台清晰地查看所有有效链接的目标、密码、创建和过期时间，并可随时删除。
-   **零依赖、易部署**: 单个脚本文件，无需外部服务器或数据库，完全利用 Cloudflare 的全球网络。

## 工作原理

本项目巧妙地利用了 Cloudflare 提供的强大服务：

1.  **Cloudflare Workers**: 作为无服务器运行环境，执行所有的业务逻辑，包括路由、权限验证、密码处理和反向代理。
2.  **Cloudflare KV**: 作为一个高性能的键值存储数据库，用于永久化存储所有代理链接的配置信息（目标地址、密码、有效期等）。
3.  **HTMLRewriter API**: 这是 Worker 的一个强大功能，它能以流式处理的方式解析和重写 HTML 响应，使得动态修改页面内的链接成为可能，且性能极高。

代理流程如下：
`用户请求` -> `Worker` -> `检查权限/密码` -> `Worker 请求原始服务器` -> `获取响应` -> `Worker 重写HTML/重定向` -> `返回给用户`。

## 部署指南

部署本项目非常简单，只需按照以下步骤操作：

### 1. 前提条件
-   一个 Cloudflare 账户。
-   安装了 [Node.js](https://nodejs.org/) 和 `npm`。
-   安装了 Cloudflare 的命令行工具 `wrangler`。如果尚未安装，请运行：
    ```bash
    npm install -g wrangler
    ```

### 2. 克隆并配置项目
1.  克隆本仓库到您的本地：
    ```bash
    git clone https://github.com/lqt444444/Cloudflare-Worker-ProxyLink.git
    cd Cloudflare-Worker-ProxyLink
    ```

2.  登录 `wrangler`：
    ```bash
    wrangler login
    ```
    这将打开浏览器引导您完成 Cloudflare 账户授权。

3.  创建 KV 命名空间：
    ```bash
    wrangler kv:namespace create "LINK_STORAGE"
    ```
    此命令会返回一个 `id` 和一个 `preview_id`。请记下它们。

4.  配置 `wrangler.toml` 文件：
    在项目根目录创建一个名为 `wrangler.toml` 的文件，并将以下内容复制进去。请务必将 `name`, `account_id` 和 `kv_namespaces` 中的占位符替换为您自己的信息。

    ```toml
    name = "my-proxy-link" # 您的 Worker 名称，将成为 URL 的一部分
    main = "index.js"     # 主脚本文件，请确保您的JS代码保存在这个文件中
    compatibility_date = "2023-08-01"

    # 替换成您的 Account ID
    # 您可以在 Cloudflare 仪表板主页的右侧找到它
    account_id = "YOUR_ACCOUNT_ID" 

    # 绑定 KV 命名空间
    [[kv_namespaces]]
    binding = "LINK_STORAGE"
    # 替换为上一步中 `wrangler kv:namespace create` 命令返回的 id
    id = "YOUR_KV_NAMESPACE_ID" 
    # 替换为上一步中 `wrangler kv:namespace create` 命令返回的 preview_id
    preview_id = "YOUR_KV_NAMESPACE_PREVIEW_ID" 
    ```

5.  **（重要）** 修改安全配置：
    打开 `index.js` 文件，找到并修改以下常量：
    ```javascript
    // 替换为您自己的、更安全的管理员密码
    const ADMIN_PASSWORD = 'admin123';

    // 替换为一个独一无二的、随机的字符串，用于增强会话安全
    const ADMIN_SESSION_KEY = 'a-very-secret-key-for-admin-session'; 
    ```

### 3. 部署
一切准备就绪后，运行以下命令即可将您的服务部署到 Cloudflare 全球网络：

```bash
wrangler deploy
```

部署成功后，`wrangler` 会告诉您 Worker 的访问地址，例如 `https://my-proxy-link.your-username.workers.dev`。

## 使用方法

### 1. 访问后台
在浏览器中打开 `https://<您的Worker地址>/admin`。输入您在 `index.js` 中设置的管理员密码即可登录。

### 2. 生成链接
登录后，您会看到链接生成页面：
-   **目标 URL**: 输入您想要代理的完整网址（例如 `www.google.com`）。
-   **访问密码**: (可选) 为此链接设置一个密码。如果留空，系统会自动生成一个8位随机密码。
-   **链接有效期**: 选择链接的存活时间。

点击“生成链接”按钮，即可获得代理链接和对应的访问密码。

### 3. 管理链接
点击后台导航栏的“管理所有链接”，您可以查看所有未过期的链接，并随时删除它们。
