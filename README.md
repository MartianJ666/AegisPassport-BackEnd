# AegisPassport-BackEnd

[![Java](https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white)](https://openjdk.org/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.x-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Spring Security](https://img.shields.io/badge/Spring%20Security-OAuth2%20%2F%20OIDC-6DB33F?logo=springsecurity&logoColor=white)](https://spring.io/projects/spring-security)
[![Flyway](https://img.shields.io/badge/Flyway-DB%20Migration-CC0200?logo=flyway&logoColor=white)](https://flywaydb.org/)
[![License: GPL-3.0-only](https://img.shields.io/badge/License-GPL--3.0--only-blue.svg)](./LICENSE)

**AegisPassport** 统一身份认证与账户管理后端服务，基于 **Java 21**、**Spring Boot** 与 **Spring Security** 构建，完整实现标准 **OAuth 2.0** 与 **OpenID Connect (OIDC)** 身份提供商（IdP）能力。配套前端仓库为 [AegisPassport-FrontEnd](https://github.com/MartianJ666/AegisPassport-FrontEnd)。

---

## 核心特性与安全架构

- **标准 OAuth 2.0 / OIDC 服务**：支持授权码模式（强制/可选 PKCE `S256`）、OIDC Discovery 元数据自动发现、动态 JWKS 非对称签名密钥管理、授权同意（Consent）、多账号切换与令牌撤销。
- **纵深防御安全机制**：
  - **传输层密码加密**：提供临时 RSA 公钥端点（`/api/auth/rsa/public-key`），防止明文密码在非可信链路或代理日志中暴露。
  - **配置信封加密（Envelope Encryption）**：上游第三方 OIDC 客户端密钥使用独立主密钥（`THIRD_PARTY_CONFIG_ENVELOPE_KEY`）加密后落库存储。
  - **独立授权域 CSRF 防护**：内置 `ConsentCsrfOriginFilter`，在拆分授权域名部署模式下严格校验 `Origin` / `Referer` 边界。
  - **凭证版本控制（Credentials Version）**：修改密码或管理员强制重置后递增用户凭证版本，使全平台历史会话与令牌即时失效。
  - **防暴力破解与异常拦截**：内置登录失败频率限制（Login Throttle）与安全违规事件检测拦截。
- **多维度应用访问控制策略**：支持按「组织架构 + RBAC 角色 + 个人特例规则（支持有效期）」统一判定用户对各 OAuth 应用的访问权限。
- **全链路审计与可观测性**：基于 AOP 切面（`@Audit`）记录关键账号变更、OAuth 授权与安全事件，支持 IPv6 记录、页面访问统计及 CSV 导出。

---

## 认证与授权核心流程

```text
第三方业务应用 (Client)                 AegisPassport (FrontEnd + BackEnd)
         │                                              │
         ├── 1. 重定向至 /oauth2/authorize ────────────▶│ (携带 client_id, state, code_challenge)
         │                                              ├── 2. 校验会话与应用访问策略 (Policy)
         │                                              ├── 3. 跳转前端 /auth/login 或 /oauth2/consent
         │                                              ├── 4. 用户完成登录 / 授权同意确认
         │◀── 5. 回调 redirect_uri?code=...&state=... ──┤
         │                                              │
         ├── 6. 后端调用 /oauth2/token ────────────────▶│ (携带 code + code_verifier)
         │◀── 7. 返回 access_token / id_token ──────────┤ (RS256 签名，可通过 /oauth2/jwks 验签)
```

---

## 本地快速启动

### 1. 环境准备
- 安装 **JDK 21**。仓库已内置 Gradle Wrapper（`./gradlew`），无需本地额外安装 Gradle。

### 2. 启动开发实例

```bash
git clone https://github.com/MartianJ666/AegisPassport-BackEnd.git
cd AegisPassport-BackEnd

# Linux / macOS
./gradlew bootRun

# Windows CMD / PowerShell
gradlew.bat bootRun
```

- 默认激活 `local` profile，监听 `8421` 端口，已放行来自 `http://localhost:8420` 的跨域请求。
- 开发模式内置 **H2 内存数据库** 与本地内存缓存，无需启动 MySQL 或 Redis 即可运行（注意：进程停止后内存数据将清空）。

### 3. 初始管理员账号配置

首次启动且数据库无管理员账号时，系统会自动创建初始管理员：
- **默认用户名**：`admin`
- **默认密码**：随机生成的 20 位高强度密码，仅在首次初始化时的控制台日志中打印一次（查找 `username:` 与 `password:` 行）。

如需在启动前指定固定的初始管理员账号和密码：

```bash
# Linux / macOS
BOOTSTRAP_ADMIN_USERNAME=admin \
BOOTSTRAP_ADMIN_PASSWORD='replace-with-your-own-password' \
./gradlew bootRun
```

```powershell
# Windows PowerShell
$env:BOOTSTRAP_ADMIN_USERNAME = 'admin'
$env:BOOTSTRAP_ADMIN_PASSWORD = 'replace-with-your-own-password'
.\gradlew.bat bootRun
```

> **注意**：若未配置 `JWT_SECRET`，开发实例每次重启都会生成临时签名密钥，导致重启前签发的登录 Token 失效。

---

## 业务配置与权限规则

### 1. 自助注册与第三方 OIDC 登录
- **自助注册**：默认开启（`REGISTRATION_SELF_SERVICE_ENABLED=true`）。管理员需先在控制台 **「邮件配置」** 中保存并启用 SMTP，用户才能收到注册邮箱验证码。设为 `false` 后将关闭自助注册及首次第三方登录的自动建号功能（管理员后台建号不受影响）。
- **上游 OIDC 接入**：采用标准 OIDC Discovery 协议，不硬编码特定服务商。配置环境变量 `THIRD_PARTY_CONFIG_ENVELOPE_KEY` 后，在后台填写上游 `Issuer`、`Client ID` 与 `Client Secret`，系统会自动生成并展示需在上游登记的回调地址（Redirect URI）。

### 2. 应用访问控制判定优先级

系统在用户登录或发起 OAuth 授权时，通过 `ClientAccessPolicy` 按以下优先级（自上而下）执行准入校验：

1. **全局状态拦截**：若用户账号被禁用/锁定/封禁，或目标 OAuth 应用处于禁用状态，**直接拒绝**。
2. **个人显式黑名单**：若管理员为该用户配置了针对该应用的「禁止访问」个人规则，**直接拒绝**。
3. **个人特例白名单**：若管理员为该用户配置了有效的「允许访问」个人规则（未过期），**直接放行**（可覆盖组织与角色限制；规则过期后自动回退至常规校验）。
4. **组织与角色双重满足**：其余情况下，用户必须**同时满足**所属组织的准入规则与所拥有角色的访问权限。

> **权限分离原则**：组织成员关系仅用于数据归属与组织级应用访问策略，将用户加入组织**不会**自动赋予其后台管理权限。

---

## 生产环境配置

生产环境需激活 `docker` profile，依赖 **MySQL 8.0+** 与 **Redis**。数据库需提前创建（如 `CREATE DATABASE aegis_passport CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;`），表结构（`V1` ~ `V13`）将在启动时由 **Flyway** 自动初始化。

> `.env.example` 为环境变量模板，Spring Boot 不会自动加载该文件。裸机运行 JAR 时请通过 Systemd / Supervisor 注入环境变量；Docker 部署时请使用 `--env-file .env`。

### 环境变量清单

| 变量名 | 必填 | 说明 |
| :--- | :---: | :--- |
| `SPRING_PROFILES_ACTIVE` | 是 | 生产环境固定设为 `docker` |
| `SPRING_DATASOURCE_URL` | 是 | MySQL JDBC 连接串（如 `jdbc:mysql://mysql:3306/aegis_passport?useUnicode=true&characterEncoding=utf8`） |
| `SPRING_DATASOURCE_USERNAME` | 是 | MySQL 用户名 |
| `SPRING_DATASOURCE_PASSWORD` | 是 | MySQL 密码 |
| `SPRING_REDIS_HOST` | 是 | Redis 主机地址 |
| `SPRING_REDIS_PORT` | 否 | Redis 端口，默认 `6379` |
| `SPRING_DATA_REDIS_PASSWORD` | 否 | Redis 认证密码（若启用） |
| `SPRING_DATA_REDIS_DATABASE` | 否 | Redis 数据库索引，默认 `0` |
| `JWT_SECRET` | 是 | 固定的内部会话 JWT 签名密钥（至少 32 字节） |
| `THIRD_PARTY_CONFIG_ENVELOPE_KEY` | 是 | 独立的 32 字节 Base64 密钥，用于信封加密存储上游 OIDC 客户端密钥 |
| `OAUTH2_ISSUER` | 是 | Passport 认证服务的对外公开 HTTPS Origin（如 `https://passport.example.com`） |
| `FRONTEND_URL` | 是 | 前端登录与管理界面的对外公开 Origin |
| `CORS_ALLOWED_ORIGINS` | 是 | 允许携带凭据跨域访问的前端 Origin，多个值以英文逗号分隔 |
| `CONSENT_BASE_URL` | 否 | 独立授权同意页面的 Origin，留空则默认与 `FRONTEND_URL` 一致 |
| `BOOTSTRAP_ADMIN_USERNAME` | 否 | 空库首次初始化时的管理员用户名，默认 `admin` |
| `BOOTSTRAP_ADMIN_PASSWORD` | 否 | 空库首次初始化时的管理员密码，留空则随机生成并打印至日志 |
| `REGISTRATION_SELF_SERVICE_ENABLED` | 否 | 是否允许自助注册，默认 `true` |
| `UPLOAD_DIR` | 否 | 用户头像、应用图标及登录背景图的持久化存储目录 |
| `SERVER_PORT` | 否 | 服务监听端口，默认 `8421` |

### 生成生产随机密钥

```bash
# 生成 JWT_SECRET
openssl rand -base64 48

# 生成 THIRD_PARTY_CONFIG_ENVELOPE_KEY（32 字节 Base64）
openssl rand -base64 32
```

---

## 构建与容器化部署

### 1. 编译打包与运行回归测试

```bash
# 执行全量单元与集成回归测试，并构建可执行 Fat JAR
./gradlew test bootJar

# 直接运行 JAR
java -jar build/libs/AegisPassport-BackEnd-1.0.0.jar
```

回归测试使用隔离的 H2 数据库实例，覆盖注册权限控制、角色与组织准入策略、多设备会话管理、授权续接、账号切换、PKCE 校验及令牌撤销等核心链路。

### 2. Docker 镜像构建与运行

仓库 `Dockerfile` 基于非 root 用户运行已打包的 JAR 文件：

```bash
# 1. 构建镜像（确保已先执行 ./gradlew bootJar）
docker build -t aegis-passport-backend:local .

# 2. 创建前后端通信桥接网络
docker network create passport

# 3. 启动后端容器
docker run -d --name server \
  --network passport \
  --env-file .env \
  -v passport-uploads:/app/uploads \
  aegis-passport-backend:local
```

> **网络与持久化提示**：
> - 容器内的 `localhost` 指向容器自身，`.env` 中的 MySQL 与 Redis 地址请填写同网络容器名或宿主机内网 IP。
> - 前端 Nginx 容器默认通过 `http://server:8421` 代理请求至本容器。
> - 版本升级前请务必备份 MySQL 数据库与 `/app/uploads` 挂载卷，并核对 Flyway 迁移脚本版本。

---

## 核心端点概览

| 路径 | 协议 / 用途说明 |
| :--- | :--- |
| `/.well-known/openid-configuration` | OIDC 服务发现元数据端点（Discovery） |
| `/oauth2/authorize` | OAuth 2.0 / OIDC 授权请求端点 |
| `/oauth2/token` | 授权码交换与刷新令牌端点（支持 PKCE `code_verifier`） |
| `/oauth2/jwks` | OIDC 公钥集端点（供业务应用验证 `id_token` 签名） |
| `/oauth2/revoke` | 令牌撤销端点 |
| `/userinfo` | OIDC 标准用户身份声明（Claims）端点 |
| `/api/auth/*` | 账号登录、注册、验证码、RSA 公钥及第三方登录流程接口 |
| `/api/admin/*` | 受 RBAC 权限保护的系统与租户管理接口 |
| `/swagger-ui.html` | OpenAPI / Swagger 在线接口文档 |

> **已知部署限制**：当前版本中，OAuth 授权码（Authorization Code）与刷新令牌的授权状态存储于后端进程内存中，重启后端服务会导致未消费的授权码及活跃 OAuth 授权状态失效（用户基础账号、组织、角色及审计数据均持久化于 MySQL）。如需多副本水平扩展部署，需先扩展共享授权存储实现。

---

## 开源许可证

本仓库源码基于 **GNU General Public License v3.0 only**（SPDX：`GPL-3.0-only`）协议开源，完整条款请参阅 [LICENSE](./LICENSE)。第三方开源依赖及 Gradle Wrapper 保留其各自原始许可证，详情见 [THIRD_PARTY_NOTICES.md](./THIRD_PARTY_NOTICES.md)。