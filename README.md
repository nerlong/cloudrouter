# CloudRouter

> ✅ **稳定版本** - 完全可用，推荐部署使用

CloudRouter 是一个基于 Cloudflare Workers 的智能 API 路由器，为 OpenRouter API 提供 OpenAI 兼容接口，支持多密钥轮询和故障转移。

## 功能特性

- **OpenAI 兼容 API**：支持 `/v1/models` 和 `/v1/chat/completions` 端点
- **智能密钥轮询**：多个 OpenRouter API 密钥自动轮询，提高并发能力
- **故障转移**：密钥失效时自动切换到可用密钥
- **Web 管理界面**：友好的管理界面，支持密钥管理和客户端 Token 管理
- **自定义 Token**：支持自定义客户端访问 Token，完全控制访问权限
- **全球加速**：基于 Cloudflare Workers，全球边缘计算，低延迟

## 一键部署

### 直接部署（推荐）
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cheluen/cloudrouter&autofork=false)

### Fork 后部署
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/cheluen/cloudrouter)

## 手动部署

```bash
# 1. 克隆仓库
git clone https://github.com/cheluen/cloudrouter.git
cd cloudrouter

# 2. 安装依赖
npm install

# 3. 登录 Cloudflare
npx wrangler login

# 4. 创建 KV 命名空间
npx wrangler kv:namespace create "ROUTER_KV"

# 5. 更新 wrangler.toml 中的 KV ID
# 将输出的 ID 替换到 wrangler.toml 文件中

# 6. 部署
npm run deploy
```

## 使用方法

1. **初始设置**：访问 Worker URL，设置管理员密码
2. **添加密钥**：在管理界面添加 OpenRouter API 密钥
3. **创建 Token**：生成客户端访问 Token（支持自定义）
4. **配置客户端**：
   - API Base URL: `https://your-worker-url.workers.dev/v1`
   - API Key: 使用生成的客户端 Token

## 版本说明

- ✅ **当前版本**：完全可用的稳定版本
- 🔧 **功能完整**：包含所有核心功能和改进的健康检查
- 🚀 **推荐使用**：适合生产环境部署

## 许可证

MIT License
