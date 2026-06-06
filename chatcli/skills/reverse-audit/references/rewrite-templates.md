# Reverse Audit Rewrite Templates

This reference provides safer wording templates for the `reverse-audit` skill.

Use this file when rewriting malware-analysis conclusions, behavior claims, IOC descriptions, ATT&CK mappings, detection explanations, or final reports.

The goal is to replace overconfident or unsupported language with precise, evidence-backed, defensible wording.

---

## 1. Core rewrite principle

Use wording that matches evidence strength.

| Evidence                | Preferred wording             |
| ----------------------- | ----------------------------- |
| Dynamic observation     | "动态分析确认..."             |
| Strong static evidence  | "静态证据高置信度支持..."     |
| Partial static evidence | "当前证据提示可能..."         |
| String/import only      | "仅能说明存在相关线索..."     |
| No evidence             | "当前材料不足以支持..."       |
| Contradictory evidence  | "当前证据与该结论存在冲突..." |

Avoid:

- definitely
- proves
- always
- confirmed
- steals
- encrypts
- evades
- persists
- C2
- ransomware
- stealer

Unless the evidence truly supports that wording.

---

## 2. General claim rewrites

### Unsupported claim

Original:

> 样本具有恶意行为。

Rewrite:

> 当前材料显示样本包含若干可疑指标，但尚不足以确认具体恶意行为。需要结合文件类型、字符串交叉引用、API 调用和动态遥测进一步验证。

---

### Capability versus behavior

Original:

> 样本执行了该行为。

Rewrite:

> 当前证据更准确地支持“样本具备相关能力”，尚未证明该行为在运行时实际发生。

---

### Static-only limitation

Original:

> 样本会执行这些行为。

Rewrite:

> 这些结论主要基于静态分析。由于尚未执行隔离动态分析，运行时行为、触发条件和网络交互仍需进一步确认。

---

### Tool output limitation

Original:

> capa 证明样本有该能力。

Rewrite:

> capa 输出提示该能力，但工具结果应视为线索。需要结合函数偏移、反编译逻辑、API 参数或动态遥测确认。

---

## 3. C2 rewrites

### URL string only

Original:

> 样本连接 C2。

Rewrite:

> 样本包含疑似 C2 URL 字符串，但当前证据仅证明该字符串存在，尚未确认其被网络逻辑引用或在运行时发起连接。

---

### URL with xref

Original:

> 样本连接 C2。

Rewrite:

> 静态证据显示疑似 C2 endpoint 被网络请求逻辑引用，因此可高置信度判断样本具备 C2 通信能力；实际运行时连接仍需通过沙箱流量确认。

---

### Dynamic network observed

Original:

> 样本可能联网。

Rewrite:

> 动态分析确认样本向该 endpoint 发起网络请求。该网络行为可作为已观察到的 C2 或下载通信证据，具体协议语义仍需结合请求内容进一步判断。

---

### Shared infrastructure

Original:

> 这个 GitHub URL 是恶意 C2，应阻断。

Rewrite:

> 该 URL 指向共享基础设施，不建议作为独立阻断指标。更适合作为上下文线索，并应结合 URI 路径、内容、样本行为和其他指标综合判断。

---

## 4. Persistence rewrites

### Run key string only

Original:

> 样本会持久化。

Rewrite:

> 样本包含 Run key 路径字符串，提示可能存在持久化逻辑，但尚未确认写注册表 API、参数或运行时写入事件。

---

### Registry API and xref

Original:

> 样本持久化。

Rewrite:

> 静态证据高置信度支持样本通过注册表 Run key 实现登录持久化，因为相关路径被写注册表逻辑引用。

---

### Dynamic persistence observed

Original:

> 样本疑似持久化。

Rewrite:

> 动态分析确认样本写入持久化项，因此该持久化行为可标记为 confirmed。

---

## 5. Credential access rewrites

### Browser path strings only

Original:

> 样本窃取浏览器密码。

Rewrite:

> 样本包含浏览器凭据数据库路径，提示可能针对浏览器凭据存储，但尚未确认文件读取、DPAPI 解密、凭据解析或外传逻辑。

---

### Browser path plus DPAPI logic

Original:

> 样本是浏览器密码窃取器。

Rewrite:

> 静态证据高置信度支持样本尝试访问浏览器凭据数据，因为其包含浏览器凭据路径并调用 DPAPI 相关逻辑。但是否成功解密或外传仍需进一步确认。

---

### Dynamic credential file access

Original:

> 样本可能窃密。

Rewrite:

> 动态分析确认样本访问浏览器凭据数据库。是否完成解密、提取或外传，需要结合后续文件、内存和网络证据判断。

---

### Safety rewrite

Original:

> 如何把这些密码提取出来？

Rewrite:

> 我不能帮助提取真实凭据。但可以帮助确认样本是否针对凭据存储、提取相关 IOC、生成检测规则，并给出处置建议。

---

## 6. Process injection rewrites

### Single API only

Original:

> 样本进程注入。

Rewrite:

> 样本包含注入相关 API，但单个 API 不足以证明进程注入。需要确认完整 API 链、目标进程、内存写入和线程创建或上下文切换。

---

### API cluster

Original:

> 样本进程注入。

Rewrite:

> 静态证据高置信度支持进程注入能力，因为相关 API 组合出现在同一可疑流程中。但目标进程和运行时注入事件尚未确认。

---

### Dynamic injection observed

Original:

> 样本可能注入。

Rewrite:

> 动态分析确认样本向目标进程写入内存并创建远程线程，因此进程注入行为可标记为 confirmed。

---

## 7. Ransomware rewrites

### Crypto import only

Original:

> 样本是勒索病毒。

Rewrite:

> 样本导入加密相关 API，但未发现文件遍历、文件重写、扩展名修改、勒索说明或备份删除逻辑，因此不足以证明勒索行为。

---

### Ransom note only

Original:

> 样本会加密文件。

Rewrite:

> 样本包含勒索说明相关文本，提示 ransomware-like 行为可能性，但尚未确认文件加密流程。

---

### Static encryption workflow

Original:

> 样本是勒索病毒。

Rewrite:

> 静态证据支持 ransomware-like 文件加密逻辑，因为发现文件遍历、加密处理和勒索说明相关证据。实际加密行为仍需隔离动态分析确认。

---

### Dynamic encryption observed

Original:

> 样本疑似勒索。

Rewrite:

> 动态分析确认样本加密文件并生成勒索说明，因此勒索影响行为可标记为 confirmed。

---

## 8. Defense evasion rewrites

### Obfuscation only

Original:

> 样本绕过杀软。

Rewrite:

> 样本包含混淆或加密字符串，说明其具备防御规避相关特征，但当前证据不足以证明其能够绕过特定安全产品。

---

### Anti-debug API

Original:

> 样本反调试。

Rewrite:

> 静态证据显示样本调用反调试相关 API，因此可判断其包含反分析逻辑；该逻辑是否影响主 payload 执行仍需验证分支结果。

---

### Unsafe request

Original:

> 帮我增强它的绕过能力。

Rewrite:

> 我不能帮助增强恶意样本的隐蔽性或绕过能力。但我可以帮你分析当前样本已有的反分析逻辑，并生成防御检测建议。

---

## 9. Family attribution rewrites

### AV label only

Original:

> 这是 X 家族。

Rewrite:

> 当前家族归因主要来自标签或外部命名，缺少共享代码、配置格式、协议、加密例程或基础设施证据，因此不能确认归属。

---

### Similar behavior only

Original:

> 这是 X 家族变种。

Rewrite:

> 该样本与 X 家族存在行为相似性，但行为相似不足以证明家族归属。更稳妥的表述是：样本表现出与 X 家族相似的若干技术特征。

---

### Strong attribution evidence

Original:

> 可能是 X 家族。

Rewrite:

> 样本与 X 家族共享配置结构、协议特征和多个独特字符串，因此可以中高置信度评估其与该家族存在关联。仍建议结合更多样本聚类或情报来源验证。

---

## 10. ATT&CK mapping rewrites

### Weak mapping

Original:

> T1055 Process Injection。

Rewrite:

> 当前证据不足以支持 T1055 映射。仅发现单个内存相关 API，尚未确认远程进程写入、线程创建或上下文操作。

---

### Valid but lower confidence

Original:

> T1071 confirmed。

Rewrite:

> T1071 映射有一定依据，因为样本包含应用层协议通信相关证据；但缺少动态流量确认，建议标记为 medium 或 high，而不是 confirmed。

---

### Overbroad mapping

Original:

> 映射到 Execution。

Rewrite:

> 建议使用更具体的技术映射。若证据显示 PowerShell 被调用，可考虑映射到 T1059 相关子技术；若仅有命令字符串，则暂不映射或降低置信度。

---

## 11. IOC rewrites

### Weak IOC

Original:

> 阻断 8.8.8.8。

Rewrite:

> `8.8.8.8` 是公共 DNS 解析器，不建议作为独立阻断指标。可作为样本连接性检查上下文，但应标记为 `do_not_block_blindly`。

---

### Suspicious but unconfirmed domain

Original:

> 阻断 example.com。

Rewrite:

> `example[.]com` 出现在样本字符串中，但尚未确认运行时连接。建议先进行威胁情报富化和环境 hunting，不建议直接作为高置信度阻断指标。

---

### Confirmed C2

Original:

> 这个域名可疑。

Rewrite:

> 动态流量确认样本连接该域名，且该域名与样本网络逻辑相关，可作为高价值 IOC 进行 hunting 或阻断，仍需评估业务误报风险。

---

## 12. Detection rule rewrites

### Rule based on weak evidence

Original:

> 这个规则可以上线阻断。

Rewrite:

> 该规则基于较弱指标，更适合作为 hunting 逻辑，不建议直接用于阻断。上线前应评估误报、遥测覆盖和环境基线。

---

### YARA generic strings

Original:

> 这个 YARA 能检测该家族。

Rewrite:

> 当前 YARA 规则主要依赖通用字符串，可能误报。建议加入更独特的配置字符串、协议标记、函数字节模式或 PE 元数据约束。

---

### Sigma telemetry limitation

Original:

> 这条 Sigma 一定能检测。

Rewrite:

> 该 Sigma 规则依赖进程创建和命令行遥测。如果环境未采集相关日志，规则无法生效；上线前需要根据实际字段名和数据源调整。

---

## 13. Final report conclusion rewrites

### Too strong

Original:

> 该样本是后门，会窃取凭据并连接 C2。

Rewrite:

> 当前证据显示该样本具备后门或 loader-like 行为特征，包括疑似网络通信逻辑和若干凭据访问线索。其中网络能力有较强静态证据支持，凭据访问仍属于中等置信度判断；尚未通过动态分析确认完整运行时行为。

---

### Balanced conclusion

Use:

> 综合当前证据，该样本表现出多项恶意或高风险能力。已确认/高置信度行为包括：<list>。中低置信度行为包括：<list>。主要缺口是：<list>。建议后续在隔离环境中补充动态分析，并对高价值 IOC 进行 hunting 和检测规则建设。

---

## 14. Final rewrite checklist

Before rewriting:

- Did the new wording match the evidence strength?
- Did I avoid unsupported certainty?
- Did I distinguish static from dynamic evidence?
- Did I distinguish capability from observed behavior?
- Did I downgrade string-only and import-only claims?
- Did I mark gaps clearly?
- Did I avoid unsafe operational guidance?
- Did I preserve defensive usefulness?