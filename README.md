# AegisPassport-BackEnd

AegisPassport 的身份认证与账户管理后端，基于 Java 21、Spring Boot 和 Spring Security，提供 OAuth 2.0 / OpenID Connect 服务。配套界面为 [AegisPassport-FrontEnd](https://github.com/MartianJ666/AegisPassport-FrontEnd)。

## 功能

- 账户登录、邮箱验证码注册、第三方 OIDC 登录、账号绑定与新账号设置。
- 用户、组织、角色权限、个人权限和应用访问规则管理。
- OAuth 应用注册、PKCE、授权同意、账号切换与授权撤销。
- 登录设备管理、密码二次确认、管理员重置密码和全平台注销。
- API 密钥、系统公告、SMTP 邮件配置和登录背景管理。
- 操作审计、安全事件、页面访问记录与 CSV 导出。

## 本地启动

安装 JDK 21。仓库自带 Gradle Wrapper，无需另装 Gradle。

```sh
git clone https://github.com/MartianJ666/AegisPassport-BackEnd.git
cd AegisPassport-BackEnd
./gradlew bootRun
```

Windows 使用 `gradlew.bat bootRun`。

默认启用 `local` profile，监听 `8421`，允许前端从 `http://localhost:8420` 访问。开发环境使用内存 H2 和内存缓存，不要求运行 MySQL 或 Redis；进程停止后，开发数据库中的数据会丢失。

空数据库启动时会创建 `admin` 管理员。若未设置 `BOOTSTRAP_ADMIN_PASSWORD`，程序会生成随机密码并在初始化日志中显示；也可以在启动前通过环境变量指定。初始化配置不会覆盖已有管理员的密码。

未设置 `JWT_SECRET` 的开发实例会生成临时签名密钥，重启后需要重新登录。

## 注册与第三方登录

自助注册默认开启。管理员先在“邮件配置”中保存并启用 SMTP，用户才能接收注册验证码。设置 `REGISTRATION_SELF_SERVICE_ENABLED=false` 可以关闭自助注册和首次第三方登录时的自动建号，管理员创建账号仍可使用。

上游第三方登录采用可配置的 OIDC Discovery，不预置服务商。设置 `THIRD_PARTY_CONFIG_ENVELOPE_KEY` 后，在“第三方登录管理”中填写 issuer、客户端 ID 和客户端密钥。界面会显示需要在上游登记的回调地址。

OAuth 应用由管理员或具备对应权限的用户创建。应用应使用已登记的回调地址，并保留授权请求中的 `state` 和 PKCE 参数。

## 应用访问规则

角色、组织与管理员个人规则在同一处校验，优先级如下：

1. 账号或应用已禁用，或账号处于锁定、封禁状态时拒绝访问。
2. 管理员明确禁止该成员访问时拒绝。
3. 有效的个人允许规则可覆盖角色与组织限制，过期后恢复常规校验。
4. 其余情况需要同时满足组织规则和角色规则。

组织成员关系与角色权限分别管理。分配组织不会自动赋予管理员角色。

## 生产配置

生产使用 `docker` profile，依赖 MySQL 和 Redis。MySQL 数据库需提前创建，表结构由 Flyway 初始化。

`.env.example` 是配置模板，Spring 不会自动读取这个文件。直接运行 jar 时，应由进程管理器注入环境变量；容器运行时可使用 `--env-file`。

| 变量 | 用途 |
| --- | --- |
| `SPRING_PROFILES_ACTIVE` | 生产设为 `docker` |
| `SPRING_DATASOURCE_URL` | MySQL JDBC 地址 |
| `SPRING_DATASOURCE_USERNAME`、`SPRING_DATASOURCE_PASSWORD` | 数据库账号和密码 |
| `SPRING_REDIS_HOST`、`SPRING_REDIS_PORT` | Redis 地址和端口 |
| `SPRING_DATA_REDIS_PASSWORD`、`SPRING_DATA_REDIS_DATABASE` | 可选 Redis 密码及数据库编号 |
| `JWT_SECRET` | 固定的 JWT 签名密钥，至少 32 字节 |
| `THIRD_PARTY_CONFIG_ENVELOPE_KEY` | 独立的 32 字节 Base64 密钥，用于保存上游登录凭据 |
| `OAUTH2_ISSUER` | Passport 认证服务的公开 HTTPS origin |
| `FRONTEND_URL` | 前端登录与管理界面的公开 origin |
| `CORS_ALLOWED_ORIGINS` | 允许携带凭据访问的前端 origin，多个值用逗号分隔 |
| `CONSENT_BASE_URL` | 可选独立授权页面 origin，留空使用前端地址 |
| `BOOTSTRAP_ADMIN_USERNAME`、`BOOTSTRAP_ADMIN_PASSWORD` | 空数据库的管理员初始化配置 |
| `REGISTRATION_SELF_SERVICE_ENABLED` | 是否开放自助注册，默认 `true` |
| `UPLOAD_DIR` | 头像、应用图标及背景图片的持久化目录 |
| `SERVER_PORT` | 监听端口，默认 `8421` |

例如，可在部署环境分别运行以下命令生成两个独立随机值：

```sh
openssl rand -base64 48
openssl rand -base64 32
```

第一个值用于 `JWT_SECRET`，第二个用于 `THIRD_PARTY_CONFIG_ENVELOPE_KEY`。环境变量示例中的空密码和密钥需要在部署前填写。

生产入口使用 HTTPS，并在受信任的反向代理后运行服务。默认同源部署；拆分登录与授权域名时，需同步前端 origin、后端 CORS 与授权页面配置。

## 构建与容器运行

```sh
./gradlew test bootJar
java -jar build/libs/AegisPassport-BackEnd-1.0.0.jar
```

也可以使用仓库中的 Dockerfile。它打包已生成的 jar，以非 root 用户运行：

```sh
docker build -t aegis-passport-backend:local .
docker network create passport
docker run -d --name server \
  --network passport \
  --env-file .env \
  -v passport-uploads:/app/uploads \
  aegis-passport-backend:local
```

该示例假设 MySQL 和 Redis 已能从 `passport` 网络访问。将 `.env` 中的数据库、Redis 地址改为实际地址；容器内的 `localhost` 指向该容器自身。前端镜像默认通过 `server:8421` 连接此容器。

迁移文件面向新数据库安装。已有部署升级前应核对迁移版本，并备份数据库与上传目录。

## 接口与验证

| 路径 | 用途 |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC 服务发现 |
| `/oauth2/authorize`、`/oauth2/token` | 授权请求与令牌交换 |
| `/oauth2/jwks` | 公开签名密钥 |
| `/userinfo` | 用户身份声明 |
| `/api/auth/*` | 账户认证 |
| `/api/admin/*` | 按权限控制的管理接口 |
| `/swagger-ui.html` | 接口说明界面 |

运行 `./gradlew test` 执行回归测试。测试使用隔离 H2 数据库，覆盖注册权限、角色和组织规则、设备会话、授权续接、账号切换、PKCE 与令牌撤销等行为。MySQL 迁移需在目标数据库环境单独验收。

OAuth 授权码和刷新令牌的授权状态目前保存在进程内，后端重启后会丢失；多实例部署前需要实现共享授权存储。账号、角色、组织、审计等数据使用数据库保存。

## 许可证

本仓库源码采用 GNU GPL v3.0 only，SPDX 标识为 `GPL-3.0-only`。完整条款见 [LICENSE](LICENSE)。第三方依赖和 Gradle Wrapper 保留各自的许可证，见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
