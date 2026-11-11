# 开发笔记 & 续作指南（内部文档）

> 状态快照 2026-11-11（v0.2.1 已发布；main =「做题链」+ 右键菜单 v2 + `_lvr/` 工程 + 五张 v0.3.0 截图重拍，v0.3.0 候选就绪）。给下一次继续开发的人（或下一个会话）看的。

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
| README | ✅ 完成（五张截图已用 v0.3.0 界面重拍，browser-use 后台直存 `docs/screenshots/`） |

## v0.2.0 变更摘要

- 解码实验室真正可用：hero 空态被 drawer 遮住的 z-index 修复；hex 一键送解码。
- 函数重命名/备注（持久到 Ghidra program）、最近打开列表、快捷键（`g` `/` `1-4` `n` `m` `?`）。
- PyInstaller 解包路由 + inspector 按钮（pyre.exe：entropy 7.93 / 4 函数 → 解包后 6.25 / 2727 函数）。
- i18n zh/en + 浅色主题为默认。
- `lvr doctor`、`--ghidra` 硬校验、GHIDRA_INSTALL_DIR 无效则警告后继续扫描、Java 探测（JAVA_HOME → `<ghidra>/.jre` → PATH，要求 major ≥ 21）。
- 引擎：shutdownJVM 有界化（10s 宽限）；GhidraProject 锁泄漏修复（见踩坑 #1）。

## 做题链（v0.3.0 候选，2026-11-11）

动机来自作者本人做题流程（查壳 → 跑 → 字符串锚点 → 交叉引用 → 反编译），此前字符串与代码完全断链。本次落地的四件事：

1. **查壳 · 结论面板**（inspector 第一组）：区段名签名（UPX/VMP/Themida/ASPack 等 12 种）→ 区段最高熵 ≥7.5 → 附加数据 → ≥6.5 → 干净，五档结论 + 下一步提示。**熵判定优先于 overlay**（压缩载荷本身就是加壳证据，Ferris 的 Cha1 7.93 该直接红）。
2. **字符串 → xref → 反编译高亮**：单击字符串行 = inspector 显示「谁在用它」并闪现；双击 = 直接跳进引用函数的反编译，**精确高亮引用该字符串的那一行**；右键菜单提供 查引用/送解码/复制。
3. **导入 → 调用者**：imports 行点击即查 xref（thunk 地址），直接看到「main calls fgets」并可跳进反编译。
4. **通用 /api/xrefs/{addr}**：数据地址也能查引用（不再局限于函数）。

引擎侧配套：`decompile()` 现在返回 `addr_lines`（行→最小代码地址）/ `addr_lines_hi`（行→最大代码地址）/ `addr_data`（行→首个数据地址）；xrefs 的 to-refs 带 `function`/`function_addr`。前端高亮规则按序：**target 精确命中 addr_data → 引用指令落在某行代码区间内 → 落在空档则归下一行**（参数装配指令在 call 之前，空档属于后面的语句）→ 兜底取 ≤ref 的最后一行。

### 右键菜单 v2（图标化 + 10 场景）

用户反馈：原菜单「太长、不美观」+「右键情形能否更多」。落地两件事：

1. **紧凑化**：菜单项全部改为「图标 + 短词」（⌖跳转 / ⌕查引用 / ⌗反汇编 / ◈调用图 / ⚗送解码 / ✎重命名 / ✚备注 / ⧉复制），横向排列（`#ctx-menu .menu-item` 覆盖 `.menu-item` 的 column 布局为 row），min-width 118px，完整语义留在 `title` tooltip。文案从「跳转到反编译」这类句子缩成 2-4 字。
2. **10 类右键场景**（contextmenu 监听里按 `e.target.closest(...)` 分派）：① 反编译代码里的符号 ② 代码/hex 里的选中文本 ③ xref 行（跳转按 X1 逻辑优先函数入口）④ 加密常量行 ⑤ 函数列表行（反编译/调用图/重命名/备注/复制）⑥ 字符串行（跳转引用/查引用/送解码/复制）⑦ 导入行（查调用者/复制）⑧ 导出行 ⑨ 搜索结果行 ⑩ 汇编行（有跳转目标时多一个 ⌖跟随跳转）。`Esc` / 点击空白处关闭。

### 工程目录迁移：样本同级 `_lvr/`（C 盘不再增长）

用户反馈：每次打开二进制都在往 C 盘复制项目（`~/.lovelyreverse/projects`）。现改为**每个样本一个独立工程，建在样本文件同级目录**：`<样本目录>/_lvr/<程序名>.gpr|.rep`。

- `_project_for(src)`：可写性探针（mkdir + 写删测试文件）失败 → 回退中央目录（`~/.lovelyreverse/projects/main`）；`LVR_PROJECT_DIR` 或显式 `project_dir_path`（测试用）强制走中央目录。
- 程序名来自 `_safe_project_name(src.stem)`：只留 `[A-Za-z0-9_.-]`，非 ASCII/超长 → `"p_" + sha1(stem)[:10]`（中文样本名也能落盘）。
- `/api/program` 新增 `project_dir` 字段，inspector「程序信息」显示工程目录行（用户能看到工程建在哪）。
- 二次打开同一样本 = 打开已有 `.gpr` 直接 openProgram，秒级——分析结果就地复用，与样本同进退（删样本目录即清理）。

## 已知问题（按优先级）

1. **常量扫描弱签名**：4 字节签名（如 `AES Rcon[1..4] (BE)`、`CRC-32 poly (LE)`）在任意样本上可能巧合命中（crackme_easy、flower、NotNormalExe 均有此类误报）。constants.py 目前没有最短长度过滤。
   - **续作方向**：length < 8 的命中标 `weak: true`，前端弱化显示；或要求命中处上下文有附加结构（如 Rcon 后跟 S-box）。
2. **IAB（ZCode 内置浏览器）的 Playwright `press("Enter")` 不触发页面 keydown**：合成 `KeyboardEvent` 正常。真实浏览器不受影响（synthetic 与 trusted 事件都会触发 handler）。自动化测试该用 `dispatchEvent`。
3. **pyghidra 启动间歇失败（~1/3 概率）**：`_GhidraBundleFinder.find_spec` 递归爆栈（launcher.py:116 无条件 `from ghidra.framework import Application`）。两个诱因：`%TEMP%` 下残留空 `ghidra/` 目录会遮蔽 `import ghidra`（已删）；脚本从 %TEMP% 直接跑也易触发。**从仓库 cwd 用 `python -m lovelyreverse serve` 或 `python -c "exec(...)"` 启动可靠**。另：jpype 的 atexit 钩子是 `_core._JTerminate` 而非 `shutdownJVM`，两者都要 unregister 才不挂死退出（manager.shutdown 已修）。

（原「截图角标待重拍」已解决：2026-11-11 用 browser-use 后台直存重拍五张 v0.3.0 截图，顺带修掉两个 drawer 布局 bug，见踩坑 #12。）

## 踩坑记录（v0.2.0 新增）

1. **GhidraProject 锁泄漏（严重，已修）**：`_open_job` 里 GhidraProject 创建之后、`self.project = project` 赋值之前任何异常（如 0 字节文件 import 失败）都会泄漏局部 project 句柄——它持有磁盘项目锁，之后**每一次** open 都报 `LockException: Unable to lock project! ...main\main`，引擎永久中毒，只能删项目目录。修法：整段包 `try/except BaseException`，传播前 `project.close()`。教训：**Ghidra 项目句柄是锁，不是普通资源；失败路径必须显式释放，早于任何状态赋值**。
2. **jpype.shutdownJVM() 会永久阻塞**：Ghidra 起的非守护 Java 线程让 JVM 无法退出，测试收尾挂死 31 分钟（py-spy dump 定位）。修法两层：
   - `manager.shutdown()` 把 shutdownJVM 放到 daemon 线程跑，`done.wait(10.0)` 超时放弃；先 `atexit.unregister(jpype.shutdownJVM)` 防止解释器退出时再卡。
   - `tests/conftest.py`：engine 测试跑过则在 `pytest_unconfigure` 里 flush 后 `os._exit(exitstatus)`，硬切断非守护线程。
3. **drawer/hero 分层**：`#hero` 是 fixed 不透明层（z-40），会盖住 z 序更低的 `#drawer`（空态时解码实验室不可见）。修法：`#drawer { z-index: 50 }`；hero 的 inset 要把「收起 drawer 的 32px + 状态栏 24px」算进去（`46px 0 56px`），并用 `body:has(#drawer.open) #hero { display:none }` 让位。
4. **Git Bash 会吃掉 PowerShell 的 `$_`**（显示成 extglob）。要跑 PS 就写临时 .ps1，或干脆纯 bash（netstat 找 PID + `taskkill //F //PID`）。
5. **TaskStop 杀不掉 server 子进程**：杀掉 wrapper 后 python 还在监听 7331。用 netstat 定位 PID 后 `taskkill //F //PID`。
6. pytest stdout 重定向到文件时是块缓冲，挂住时输出文件为空——用 `py-spy dump --pid` 看栈，别等日志。
7. **反编译行号推导（v0.3.0 做题链核心坑）**：`getCCodeMarkup()` 返回 ClangFunction，token 的 `getLineParent()` 恒为 None（display 层状态没填）、`getLineNumber()` 根本不存在；`tokenIterator()` 需要 boolean 参数但 **JPype 无法把 Python bool 派发到它**（"No matching overloads"）。最终方案：Python 递归遍历 ClangTokenGroup（子项可能是嵌套 group），用 **数 ClangBreak token** 推导显示行号，`token.getMinAddress()` 取地址。traceback 显示的源码行是 linecache 实时读文件——**改完 manager.py 不重启 server，报错栈看起来像新代码在跑**，别被骗。
8. **MinGW 的 COFF 符号表 = 假 overlay**：`-g` 构建的 PE 尾部是符号表+字符串表，naive 的 `file_len - sections_end` 会把所有 debug 构建的 crackme 判成「附加数据」。修法：解析 COFF header 的 `PointerToSymbolTable`/`NumberOfSymbols`，算出 `sym_ptr + 20*nsym` 处的字符串表长度并入 end_max；前端 overlay 面板顺带显示「含 COFF 符号表（N 个符号）」。**判定顺序也重要：高熵要排在 overlay 前**（压缩载荷本身就是加壳证据）。
9. **导入 thunk 地址别用 external symbol**：external symbol 的地址在独立地址空间（offset 0x29 之类），xref 查不到任何东西。真正的「谁调用了 strcmp」要找 **thunk function**：`FunctionManager.getFunctions(True)` 里 `f.isThunk()` 的那批——函数名即导入名，入口在镜像内，调用方 CALL 的就是它。
10. **`tri.max_entropy` 曾是幽灵字段**：前端读它但后端 triage() 从没提供过 → 熵分支永远不触发。前后端字段约定要有测试钉住。
11. **Ghidra 项目路径元素不许以点开头**：`GhidraProject.createProject(dir, ".lvr", …)` 直接抛 `InvalidProjectNameException: Path element starting with '.' is not permitted`。目录名用 `_lvr`。另外 Git Bash 会把中文路径的 env 变量/参数搞乱码（sample 路径带中文时别用 bash 传），用 Python 的 glob 自己找文件。
12. **drawer 状态类的两个隐藏坑（重拍截图时暴露）**：① `--drawer-h` 从未被任何规则/JS 赋值，grid 高度公式 `calc(100vh - 46px - 24px - var(--drawer-h, 236px))` 永远按 236 扣——`#drawer.closed` 用 `!important` 缩到 32px 后，状态栏下方留 ~204px 死白。修：`body:has(#drawer.closed) { --drawer-h: 32px }`。② HTML 初始 `class="open"`，toggle 只加减 `closed`，两个类并存 → `body:has(#drawer.open) #hero{display:none}` 永远命中，**收起抽屉后空态 hero 回不来**。修：toggle 里让 open/closed 互斥（sendToDecoder 展开时同步补回 open）。教训：同一个状态用两个类表达必然漂移，状态类要么互斥维护、要么只留一个。

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

- **v0.3.0 候选**：做题链 + 右键菜单 v2 + `_lvr/` 工程迁移（均已实现，见上节）。发版前可顺手：弱签名标记（已知问题 #1）、xref 面板过滤 0x2e 之类垃圾地址行。
- **Linux/macOS**：`config.py` 已平台无关（hint 目录按平台分支），主要工作是实际跑一遍 + 文档。
- **pycdc 集成**：pyc 反编译仍是缺口，解包出 .pyc 后目前只能靠 dis。可考虑捆绑/调用 pycdc。
- **Pattern Language**：`.reference/ImHex` 有完整 DSL 实现；第一步可以只做「结构体声明 → 结构化视图」。
- **gdb 桥**：Windows 优先方案是 gdbserver（WSL/远程）+ MI 协议 over stdlib；先做「断点/单步/读寄存器/读内存」四件事。
- **签名库扩充**：`.reference/yara4ida` 的 SIGS 目录有最全的 crypto/hash/压缩签名集，可写转换脚本导入。
- ~~**Ghidra 数据库复用**~~：已实现（v0.3.0 候选）——`.rep` 工程与样本路径一一映射（样本同级 `_lvr/`），二次打开秒级。可再做的：工程清单页（跨样本浏览 `_lvr/`）、打开旧样本时提示「检测到已有分析工程」。
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

**做题链（2026-11-11，UI 实测）**：

1. challenge1 双击字符串 "Please input flag: " → 跳进 main 反编译，**精确高亮第 17 行 `printf("Please input flag: ");`**（PARAM ref 0x1400018df 同行）；base64 常量 `dH5z...` → 高亮第 35 行 strcmp ✅
2. imports 面板点 fgets → xref 显示 `UNCONDITIONAL_CALL 0x14000190a main` ✅
3. 查壳结论：challenge1 → v-ok「未见加壳特征」（COFF 1535 符号正确排除假 overlay）；crackme_easy → v-ok；c_sm4 → v-bad（熵 7.82 + PyInstaller overlay）；Ferris → v-bad「最大熵 7.93」+ overlay 402,059 B ✅
4. 字符串右键菜单：查引用（谁在用它）/ 送解码实验室（文本）/ 复制 ✅
5. 全量 pytest 118 passed / 7 skipped（binfile COFF 修复未破坏任何用例）✅

**右键菜单 v2 + `_lvr/` 工程（2026-11-11，UI 实测）**：

1. 10 类右键场景全数实测：xref 行（跳转/复制地址，点「跳转」正确落到 0x140008294 反汇编）、常量行（查引用/反汇编/复制地址）、汇编行（有目标 → 跟随跳转/查引用/复制，无目标 → 查引用/复制）、搜索结果行（反汇编/查引用/复制地址，"50 55" 3 命中）+ 前一轮已验的反编译符号/选中文本/函数/字符串/导入/导出 ✅
2. challenge1 打开 → `_lvr/challenge1.gpr|.rep|.lock` 出现在样本同级目录（原 `.lvr` 因 Ghidra 拒点开头路径改名）；`/api/program` 返回 `project_dir`，inspector 显示工程目录行 ✅
3. `node --check` + `ast.parse` 全过；改动后全量 pytest 118 passed / 7 skipped ✅

**发版终检（2026-11-11，v0.3.0 候选定稿）**：

1. API 冒烟对照作者笔记工作流：锚点字符串 → xref（DATA+PARAM 双引用，带函数入口）→ decompile 行映射（gap 落「下一行」规则正中 `printf("Please input flag: ");`）；fgets thunk → 调用者 main；常量/熵字段齐全 ✅
2. 五张 README 截图用 v0.3.0 界面重拍（browser-use 后台直存 docs/screenshots/）：hero 空态 / workstation（做题链高亮 + 查壳结论 + `_lvr` 工程目录行）/ 调用图（深度 1 层次布局）/ 解码链（XOR 0x17 → XOR "ATRI" → flag）/ PyInstaller 解包（60 条目 + manifest 预览）✅
3. 过程中抓到并修掉两个 drawer 布局 bug（踩坑 #12：收起后死白 + hero 永不回）✅
4. 全量 pytest 125 passed；`node --check` 过 ✅
