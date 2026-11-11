# 开发笔记 & 续作指南（内部文档）

> 状态快照 2026-11-11（v0.2.0 已发布，main 含锁修复 + 10 样本回归）。给下一次继续开发的人（或下一个会话）看的。

## 当前进度

| 模块 | 状态 |
|---|---|
| 纯逻辑层 decode/xor/binfile/constants | ✅ 完成，含全套单元测试 |
| 引擎层 EngineManager（JVM 单线程队列） | ✅ 完成；**失败打开不再泄漏项目锁** |
| stdlib HTTP 服务 + 任务农场 | ✅ 完成（程序级 info 快路径） |
| 前端 IDE（函数/伪代码/汇编/调用图/内存 hex/字符串/导入导出/inspector/解码实验室/搜索/日志） | ✅ 完成并浏览器实测 |
| i18n（中/英）+ 浅色主题默认 | ✅ 完成 |
| 函数重命名/备注、hex 一键送解码、最近打开 | ✅ 完成 |
| PyInstaller 一键解包（inspector 入口） | ✅ 完成，pyre.exe 实测 |
| 加密常量扫描 | ✅ 真实二进制验证（SM4/TEA/AES/Base64/CRC 均命中）；弱签名问题见已知问题 #2 |
| `lvr doctor` + 部署自检（Ghidra/Java 探测、fail-fast） | ✅ 完成，12 个 CLI 单测 |
| 测试 | ✅ 125 个（118 不需要 Ghidra + 7 个引擎集成），全量 72.85s |
| CI workflow | ✅ 写好 |
| README | ✅ 完成（含截图；**截图角标仍是 v0.1.0，待重拍**） |

## v0.2.0 变更摘要

- 解码实验室真正可用：hero 空态被 drawer 遮住的 z-index 修复；hex 一键送解码。
- 函数重命名/备注（持久到 Ghidra program）、最近打开列表、快捷键（`g` `/` `1-4` `n` `m` `?`）。
- PyInstaller 解包路由 + inspector 按钮（pyre.exe：entropy 7.93 / 4 函数 → 解包后 6.25 / 2727 函数）。
- i18n zh/en + 浅色主题为默认。
- `lvr doctor`、`--ghidra` 硬校验、GHIDRA_INSTALL_DIR 无效则警告后继续扫描、Java 探测（JAVA_HOME → `<ghidra>/.jre` → PATH，要求 major ≥ 21）。
- 引擎：shutdownJVM 有界化（10s 宽限）；GhidraProject 锁泄漏修复（见踩坑 #1）。

## 已知问题（按优先级）

1. **v0.2.0 发行版带着项目锁泄漏 bug**（import 失败 → 后续所有 open LockException）。修复已在 main（`manager.py` 的 `_open_job` try/except BaseException → project.close()），并加了回归测试 `test_bad_file_does_not_poison_engine`。**候选 v0.2.1**：可以把锁修复 + 文档单独发一个小版本。
2. **常量扫描弱签名**：4 字节签名（如 `AES Rcon[1..4] (BE)`、`CRC-32 poly (LE)`）在任意样本上可能巧合命中（crackme_easy、flower、NotNormalExe 均有此类误报）。constants.py 目前没有最短长度过滤。
   - **续作方向**：length < 8 的命中标 `weak: true`，前端弱化显示；或要求命中处上下文有附加结构（如 Rcon 后跟 S-box）。
3. **截图角标待重拍**：README 五张截图仍是 v0.1.0 界面（右下角版本角标）。浏览器面板可用时重拍（hero 空态+收起 drawer / workstation 反编译 / 调用图 / 解码链 / 解包）。
4. **IAB（ZCode 内置浏览器）的 Playwright `press("Enter")` 不触发页面 keydown**：合成 `KeyboardEvent` 正常。真实浏览器不受影响（synthetic 与 trusted 事件都会触发 handler）。自动化测试该用 `dispatchEvent`。

## 踩坑记录（v0.2.0 新增）

1. **GhidraProject 锁泄漏（严重，已修）**：`_open_job` 里 GhidraProject 创建之后、`self.project = project` 赋值之前任何异常（如 0 字节文件 import 失败）都会泄漏局部 project 句柄——它持有磁盘项目锁，之后**每一次** open 都报 `LockException: Unable to lock project! ...main\main`，引擎永久中毒，只能删项目目录。修法：整段包 `try/except BaseException`，传播前 `project.close()`。教训：**Ghidra 项目句柄是锁，不是普通资源；失败路径必须显式释放，早于任何状态赋值**。
2. **jpype.shutdownJVM() 会永久阻塞**：Ghidra 起的非守护 Java 线程让 JVM 无法退出，测试收尾挂死 31 分钟（py-spy dump 定位）。修法两层：
   - `manager.shutdown()` 把 shutdownJVM 放到 daemon 线程跑，`done.wait(10.0)` 超时放弃；先 `atexit.unregister(jpype.shutdownJVM)` 防止解释器退出时再卡。
   - `tests/conftest.py`：engine 测试跑过则在 `pytest_unconfigure` 里 flush 后 `os._exit(exitstatus)`，硬切断非守护线程。
3. **drawer/hero 分层**：`#hero` 是 fixed 不透明层（z-40），会盖住 z 序更低的 `#drawer`（空态时解码实验室不可见）。修法：`#drawer { z-index: 50 }`；hero 的 inset 要把「收起 drawer 的 32px + 状态栏 24px」算进去（`46px 0 56px`），并用 `body:has(#drawer.open) #hero { display:none }` 让位。
4. **Git Bash 会吃掉 PowerShell 的 `$_`**（显示成 extglob）。要跑 PS 就写临时 .ps1，或干脆纯 bash（netstat 找 PID + `taskkill //F //PID`）。
5. **TaskStop 杀不掉 server 子进程**：杀掉 wrapper 后 python 还在监听 7331。用 netstat 定位 PID 后 `taskkill //F //PID`。
6. pytest stdout 重定向到文件时是块缓冲，挂住时输出文件为空——用 `py-spy dump --pid` 看栈，别等日志。

## 调用图实现（v0.1.0 重写，机制未变）

- 布局参考 Ghidra `GraphServices`（jungrapht）：**Sugiyama 层次布局**，不是力导向。
  - rank 计算：以中心节点为 0，沿 caller 方向 `-1`、callee 方向 `+1`，BFS 取最短（环自然收敛），钳制到 ±3。
  - 层内顺序：4 轮 barycenter 排序最小化边交叉。
  - 绘制：caller 在上 / 中心 / callee 在下；实线箭头 = 调用方向，虚线 = 回边（cyclic），同层边用二次曲线绕行。
  - 交互：双击节点增量展开（对该节点再请求 `depth=1` 后合并重排）、拖拽节点、拖拽平移、滚轮缩放（0.15–3.5）、`fit` 按钮；最小自动缩放 0.6 保证标签可读，超出视口时以中心节点锚定。
- **踩过的坑**：早期力导向实现里排斥力/引力参数配错，节点坐标发散到 `x≈1.7e7`，现象是画布全白 + 点击坐标全错。教训：图上一切坐标必须有界，布局后用 bbox 校验一次。
- **另一个坑（会再次遇到）**：canvas 的 `width` attribute 与 CSS 自适应尺寸形成反馈环——`ResizeObserver` 观察 canvas + 读写 attribute 尺寸 → 容器变宽 → 再测量 → 无限放大（曾到 207,608px）。修法：CSS 显式 `width/height: 100%`、父级 `min-width/height: 0`、`ResizeObserver` 观察父容器、绘制前对测量值做上限保护（>8000 直接放弃绘制）。

## Ghidra 12.2 API 与旧文档差异踩坑记录（都已绕过）

- `FunctionManager.getFunctionByName` 不存在 → 迭代过滤
- `ExternalManager.getExternalLocations()` 无参重载不存在 → 改用 `SymbolTable.getAllSymbols(True)` + `isExternal()`
- `DefinedDataIterator.definedStrings` 不存在 → `listing.getDefinedData(True)` + `isinstance(value, str)` 过滤
- `Memory.getBytes(Address, int)` 无此重载 → 必须 `getBytes(Address, JArray(JByte)(n))`（见 `_read_bytes` helper）
- `Address` 对象不能 `int()` 直接转 → `addr.getOffset()`

## 部署自检（v0.2.0 新增，写给新人）

- `lvr doctor`：python ≥3.10、java（major ≥21）、Ghidra 目录、端口占用、pyghidra 可导入，ASCII 标记 `[ok]/[warn]/[FAIL]`，全过返回 0。
- Ghidra 发现顺序：`--ghidra`（**硬校验，非法直接退出**并给出原因）→ `GHIDRA_INSTALL_DIR`（无效则 stderr 警告后继续扫描）→ hint 目录扫描（D:/SecurityTools、D:/Tools、C:/ghidra、家目录、Downloads/Desktop 等，取版本号最新的 `ghidra_*`）。
- Java 发现顺序：`JAVA_HOME` → `<ghidra>/.jre/bin/java`（Ghidra 自带 JRE）→ `PATH`。没有 21+ 会 fail-fast 并打印 adoptium.net 链接。
- 端口被占用：serve 会给出「try: lvr serve --port <other>」提示而不是裸 OSError 栈。

## 续作清单（Roadmap 对应的实现提示）

- **v0.2.1**：把已在 main 的锁修复单独发版（外加文档）。顺手可做弱签名标记（见已知问题 #2）。
- **Linux/macOS**：`config.py` 已平台无关（hint 目录按平台分支），主要工作是实际跑一遍 + 文档。
- **pycdc 集成**：pyc 反编译仍是缺口，解包出 .pyc 后目前只能靠 dis。可考虑捆绑/调用 pycdc。
- **Pattern Language**：`.reference/ImHex` 有完整 DSL 实现；第一步可以只做「结构体声明 → 结构化视图」。
- **gdb 桥**：Windows 优先方案是 gdbserver（WSL/远程）+ MI 协议 over stdlib；先做「断点/单步/读寄存器/读内存」四件事。
- **Ghidra 数据库复用**：open() 已实现「项目里有同名 program 就直接 openProgram」（二次打开秒级），可进一步把 `.rep` 项目与样本路径做映射持久化。
- **签名库扩充**：`.reference/yara4ida` 的 SIGS 目录有最全的 crypto/hash/压缩签名集，可写转换脚本导入。

## 开发环境备忘

- 启动开发服务器：`GHIDRA_INSTALL_DIR="D:/SecurityTools/ghidra_12.2_PUBLIC" python -m lovelyreverse serve --no-browser --port 7331`
- 本机 Ghidra：`D:/SecurityTools/ghidra_12.2_PUBLIC`；gcc：`D:\System\mingw64\bin\gcc`（16.2.0）
- 测试样本：`D:\Project\网安训练\学习笔记\逆向\逆向题\challenge1\challenge1.exe`（mingw PE，116 fn / 280 strings）
- 加密夹具：`tests/fixtures/crypto_demo.c`（gcc 编译，含 AES S-box/SHA-256 K/TEA δ/Base64 表）
- 题库回归 harness：`%TEMP%\lvr_dogfood.py`（stdlib 脚本，对 10 个样本跑完整 API 链路；题库二进制**永不入库**）
- 参考项目都在 `.reference/`（584MB，已 gitignore），清单见 `.reference/README.md`

## 已验证的真实链路（回归基准，2026-11-11 全绿）

**10 样本 dogfood**（POST /api/open → 轮询 → program/triage/constants/functions/decompile/callgraph 全链路）：

| 样本 | 打开耗时 | 格式 | 函数 | 常量命中 | 备注 |
|---|---|---|---|---|---|
| c_sm4.exe | 16.0s | PE | 4 | SM4 S-box | 目标算法即身份 |
| crackme_easy.exe | 8.2s | PE | 86 | Rcon/CRC（弱） | 弱签名误报样例 |
| Her.exe | 13.4s | PE | 262 | — | |
| flower.exe（花指令） | 37.4s | PE | 685 | Rcon/Base64/Uuencode | |
| Ferris's Secret Scuttle.exe | 15.2s | PE | 4 | — | entropy 7.93 → 判「加壳」，解包后 6.25 / 2727 fn |
| pyre.exe（PyInstaller） | — | PE | — | — | inspector 一键解包 ✅ |
| MazE / wtf（ELF64） | — | ELF | — | — | e_machine@18:20 解析正常 |
| challenge1.exe | — | PE | 116 | — | 老基准不变 |
| opcode.bin（0 字节） | — | — | — | — | 优雅报错；**暴露并修复锁泄漏** |

**固定链路**：

1. 打开 challenge1.exe → 分析 → 116 函数（列表口径）/280 字符串
2. 点 main → 反编译渲染 → 点击代码里 `xor_encrypt` → 跳转到该函数反编译 ✅
3. 解码实验室：hex 输入 `302F...6F3E`，链 `[xor ATRI][xor 17]` → `flag{y0u_ar3_g0od_@_Debu9}` ✅
4. crypto_demo.exe → 常量扫描 5 命中（TEA δ 归属 tea_encrypt）✅
5. search `b979379e`（TEA δ LE）→ .text 命中且归属 tea_encrypt + .rdata 命中 ✅
6. decompile-all → 100 个 .c 的 zip 下载 ✅
7. opcode.bin 打开失败后紧跟打开正常样本 → 成功（锁修复的活体证明）✅
8. engine 集成测试 7 个全过（含锁回归），全量 125 passed / 72.85s ✅
