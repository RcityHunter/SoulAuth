# SoulAuth 部署指南

本文档说明如何正确部署 SoulAuth 到生产环境。

## 数据库部署

### 1. 创建数据库表结构

在启动应用程序之前，必须先运行以下SQL文件来创建数据库表结构：

```bash
# 连接到 SurrealDB
surreal sql --conn http://localhost:8000 --user root --pass root --ns production --db auth

# 导入表结构
surreal import --conn http://localhost:8000 --user root --pass root --ns production --db auth schema.sql

# 或者手动执行SQL文件内容
```

**重要说明**：
- `schema.sql` 包含所有必需的数据库表定义
- 必须在应用程序启动前执行此文件
- 这样设计符合生产环境最佳实践，避免应用程序具有DDL权限

### 2. 初始化系统数据

创建完表结构后，运行初始数据文件来创建系统角色和权限：

```bash
# 导入初始数据
surreal import --conn http://localhost:8000 --user root --pass root --ns production --db auth initial_data.sql

# 或者手动执行SQL文件内容
```

**`initial_data.sql` 包含的内容**：
- 系统权限（12个基础权限）
- 系统角色（5个预定义角色）
- 系统用户账户（用于权限分配的内部账户）
- 角色权限关联（为系统角色分配适当的权限）

### 3. 安装文档系统权限（可选）

如果需要集成 Rainbow-Docs 文档系统，请运行额外的权限扩展文件：

```bash
# 导入文档系统权限
surreal import --conn http://localhost:8000 --user root --pass root --ns production --db auth docs_permissions.sql

# 或者手动执行SQL文件内容
```

**`docs_permissions.sql` 包含的内容**：
- 文档管理权限（10个文档相关权限）
- 文档系统角色（3个文档专用角色）
- 权限关联（为现有角色分配文档权限）

## 权限系统说明

### 系统角色

| 角色名 | 显示名称 | 描述 | 权限范围 |
|--------|----------|------|----------|
| `admin` | 系统管理员 | 拥有所有权限 | 所有权限 |
| `user_manager` | 用户管理员 | 负责用户管理 | users.read, users.write, users.delete |
| `security_manager` | 安全管理员 | 负责安全管理 | security.read, security.write, users.read |
| `auditor` | 审计员 | 查看审计日志 | audit.read |
| `user` | 普通用户 | 基础用户角色 | 基础权限 |

### 系统权限

| 权限名 | 资源 | 操作 | 描述 |
|--------|------|------|------|
| `users.read` | users | read | 查看用户信息 |
| `users.write` | users | write | 编辑用户信息 |
| `users.delete` | users | delete | 删除用户账户 |
| `roles.read` | roles | read | 查看角色信息 |
| `roles.write` | roles | write | 管理角色 |
| `roles.delete` | roles | delete | 删除角色 |
| `permissions.read` | permissions | read | 查看权限信息 |
| `permissions.write` | permissions | write | 管理权限 |
| `permissions.delete` | permissions | delete | 删除权限 |
| `security.read` | security | read | 查看安全状态 |
| `security.write` | security | write | 管理安全操作 |
| `audit.read` | audit | read | 查看审计日志 |

### 文档系统权限（可选）

如果安装了文档系统权限扩展，还包含以下权限：

| 权限名 | 资源 | 操作 | 描述 |
|--------|------|------|------|
| `docs.read` | documents | read | 查看和阅读文档内容 |
| `docs.write` | documents | write | 创建、编辑和发布文档 |
| `docs.delete` | documents | delete | 删除文档和章节 |
| `docs.admin` | documents | admin | 管理文档空间、权限和设置 |
| `spaces.read` | spaces | read | 查看和访问文档空间 |
| `spaces.write` | spaces | write | 创建、编辑文档空间和设置 |
| `spaces.delete` | spaces | delete | 删除文档空间 |
| `comments.read` | comments | read | 查看文档评论和讨论 |
| `comments.write` | comments | write | 添加、编辑和回复评论 |
| `comments.delete` | comments | delete | 删除评论和讨论 |

### 文档系统角色（可选）

| 角色名 | 显示名称 | 描述 | 权限范围 |
|--------|----------|------|----------|
| `docs_admin` | 文档管理员 | 拥有完整文档管理权限 | 所有文档权限 |
| `docs_editor` | 文档编辑员 | 可以创建和编辑文档 | docs.read, docs.write, comments |
| `docs_reader` | 文档阅读者 | 只能查看文档 | docs.read, spaces.read, comments.read |

## 应用程序部署

### 1. 环境变量配置

确保设置所有必需的环境变量：

```env
# 数据库配置
DATABASE_URL=http://localhost:8000
DATABASE_USER=your-db-user
DATABASE_PASS=your-db-password
DATABASE_CONNECTION_TIMEOUT=30
DATABASE_MAX_CONNECTIONS=10

# JWT配置 (必需)
JWT_SECRET=your-super-secure-jwt-secret-key-here
JWT_EXPIRATION=86400

# OAuth配置 (可选)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
OAUTH_REDIRECT_URL=https://your-domain.com/api/auth/callback

# SMTP配置
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_FROM=noreply@your-domain.com

# 应用配置
APP_URL=https://your-domain.com
```

### 2. 数据库权限

为应用程序创建专用的数据库用户，只授予必要的权限：

```sql
-- 创建应用程序专用用户
CREATE USER app_user ON DATABASE auth PASSWORD 'secure-password';

-- 授予必要的数据权限（不包括DDL权限）
GRANT SELECT, INSERT, UPDATE, DELETE ON auth.* TO app_user;

-- 不要授予CREATE, DROP, ALTER等DDL权限
```

### 3. 部署步骤

1. **准备数据库**：
   ```bash
   # 1. 执行schema.sql创建表结构
   surreal import --conn $DATABASE_URL --user root --pass root --ns $NAMESPACE --db $DATABASE schema.sql
   
   # 2. 执行initial_data.sql创建初始数据
   surreal import --conn $DATABASE_URL --user root --pass root --ns $NAMESPACE --db $DATABASE initial_data.sql
   ```

2. **构建应用程序**：
   ```bash
   cargo build --release
   ```

3. **启动应用程序**：
   ```bash
   ./target/release/soulauth
   ```

4. **验证部署**：
   ```bash
   # 检查健康状态
   curl http://localhost:8080/health
   
   # 创建第一个管理员用户
   curl -X POST http://localhost:8080/api/auth/register \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@your-domain.com","password":"secure-password"}'
   ```

5. **分配管理员权限**：
   ```bash
   # 登录获取JWT token
   curl -X POST http://localhost:8080/api/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"admin@your-domain.com","password":"secure-password"}'
   
   # 手动为第一个用户分配admin角色（通过数据库）
   # 或者使用系统管理界面
   ```

## 安全考虑

### 1. 数据库安全
- ✅ 应用程序只有DML权限，无DDL权限
- ✅ 数据库schema通过专门的迁移管理
- ✅ 避免了运行时表结构变更的风险

### 2. 权限管理
- ✅ 系统角色受保护，不可删除
- ✅ 权限检查在API级别进行
- ✅ 支持细粒度权限控制

### 3. 部署安全
- ✅ 环境变量管理敏感信息
- ✅ 分离的数据库用户权限
- ✅ 明确的初始化流程

## 维护和更新

### Schema变更
如果需要修改数据库结构：

1. 创建新的迁移SQL文件
2. 在维护窗口期间执行迁移
3. 更新应用程序代码
4. 重新部署应用程序

### 添加新权限
如果需要添加新的系统权限：

1. 在 `initial_data.sql` 中添加新权限
2. 更新相应的角色权限分配
3. 执行增量SQL更新

### 监控
建议监控以下指标：
- 数据库连接状态
- API响应时间
- 权限检查失败次数
- 登录失败和账户锁定事件

## 故障排除

### 常见问题

1. **应用启动失败**：
   - 检查数据库连接配置
   - 确认数据库表已创建
   - 检查环境变量设置

2. **权限检查失败**：
   - 确认用户已分配正确角色
   - 检查角色权限配置
   - 验证系统权限是否正确初始化

3. **数据库连接问题**：
   - 检查数据库服务状态
   - 验证连接字符串
   - 确认网络连通性

通过遵循这个部署指南，您可以安全、可靠地部署SoulAuth到生产环境。
