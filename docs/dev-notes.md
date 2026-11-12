# 开发笔记 & 续作指南（内部文档）

> 状态快照 2026-11-11（**v0.3.1 已发布**：v0.3.0 做题链 + 右键菜单 v2 + `_lvr/` 工程之上，再打包发布后 6 项实测 UX 修复；GitHub Release 带 whl+tar.gz）。给下一次继续开发的人（或下一个会话）看的。

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
| UX 批量修复（v0.3.0 发布后 6 项实测反馈） | ✅ 完成，E2E 23 项全绿（打开残留/卡顿、xref 卡片置顶、解码预设+统一搜索、解包链、上传语义） |

## v0.2.0 变更摘要

- 解码实验室真正可用：hero 空态被 drawer 遮住的 z-index 修复；hex 一键送解码。
- 函数重命名/备注（持久到 Ghidra program）、最近打开列表、快捷键（`g` `/` `1-4` `n` `m` `?`）。
- PyInstaller 解包路由 + inspector 按钮（pyre.exe：entropy 7.93 / 4 函数 → 解包后 6.25 / 2727 函数）。
- i18n zh/en + 浅色主题为默认。
- `lvr doctor`、`--ghidra` 硬校验、GHIDRA_INSTALL_DIR 无效则警告后继续扫描、Java 探测（JAVA_HOME → `<ghidra>/.jre` → PATH，要求 major ≥ 21）。
- 引擎：shutdownJVM 有界化（10s 宽限）；GhidraProject 锁泄漏修复（见踩坑 #1）。

## 做题链（v0.3.0，2026-11-11）

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

## UX 批量修复（v0.3.0 发布后，2026-11-11）

六项真实做题反馈，根因与修法（E2E：C:\Users\50812\AppData\Local\Temp\e2e_ux.py，headless Edge 1920×1080，23 项断言全绿）：

1. **打开残留 + 切换卡顿**（反馈①）：`/api/status` 原来调 `engine.program_info()`（引擎线程派发）→ open 期间 status 轮询排队，UI 卡在前一个项目。改为锁外 `getattr(engine, "program", None)` 读内存字段；`openByPath` 先 `resetWorkspace()` 清空全部面板再提交任务；失败走 `recoverAfterOpenFail()` 与服务器实态对齐（服务器还有程序就重建，没有就回到干净空态）。
2. **交叉引用文字互遮 + 要独立区块**（反馈②，用户强调「很重要」）：根因 flex 子项默认 `min-width:auto`，长地址/函数名溢出压到隔壁列。`xref-addr` 不收缩、`xref-name` `min-width:0 + text-overflow:ellipsis`；`insp-xrefs` 整组移到 inspector **首位**并卡片化（做题链的脊梁该最先看到）。
3. **解码实验室没搞懂怎么用**（反馈③）：输入区上方加**一键预设 chips**（Base64 / Hex / ROT13 / 字节反转 / XOR 爆破），28 种操作全部加中文标签，空链提示改成三步用法指引。注意 xorbrute 是**动作不是链**——点击路由到 `xorBrute()`，不进 DEC_PRESETS。
4. **搜索不能搜字符串 + 清空不还原**（反馈③/⑤）：搜索页签原来是 hex-only。改成**三索引统一搜索**：字符串（/api/strings?q=）+ 函数名（/api/functions?q=）+ 偶数位 hex 自动追加内存字节，分组展示，点字符串命中直达 xref、点函数命中直接反编译；**输入为空不再 early-return**，还原空态提示。左列字符串过滤清空还原同理（250ms debounce）。
5. **解包链全断**（反馈④）：一个根因——`_open_job` **先关旧工程再导入新文件**，把 .manifest/.pyc 这类非可执行文件送给 Ghidra 导入失败后引擎裸奔，所有 API 409 →「所有函数看不了反编译、所有二进制看不了、导入失败」全是它的表现。改为**导入成功后再关旧工程**（同工程重开仍先关——项目锁约束）；「送 Ghidra」按钮按 MZ/ELF 魔数门控，manifest 等文本条目保留可读预览，.pyc 等二进制条目给 noexec 提示。
6. **直接打开还在写 C 盘**（反馈⑤补充）：浏览器上传拿不到原始路径，复制到数据目录是唯一可行路径（保留但 toast 讲清楚「要就地分析请粘贴绝对路径」）；真正的回归是**解包输出默认 %TEMP%**——现在跟样本走（`<样本目录>/_lvr/unpacked/<名>_<时间戳>`，不可写再回退 tempdir）。路径直开的工程本就建在样本旁 `_lvr/`（上一批已做），实测确认。

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
13. **resetWorkspace 进 loadProgram = 自我清空（UX 批次 E2E 抓的）**：把「打开残留」修复重构成公共 `resetWorkspace()` 后顺手塞进 `loadProgram`，忘了它会把 `S.program/S.triage` 置 null——下一行 `S.program.name` 直接 TypeError，被 `openByPath` 的 catch 静默吞掉走恢复分支，恢复分支再调 loadProgram 再炸，最终 `#st-program` 卡死在「未加载程序」，**console 一个报错都没有**（catch 只进了 toast + 日志页签）。API 层全绿手动测不出来，UI 路径 E2E 一跑就现形。教训：①清空状态的函数别复用进「重建状态」的流程，要么把数据获取放清理之前、清理后重装；②静默 catch 必须有日志落点，否则查无可查。
14. **不同工程的打开顺序：先导入后关旧**：GhidraProject 持磁盘锁，**同工程**重开必须先 close 再 open；但**不同工程**若也先关旧，导入一旦失败（用户把 .manifest/.pyc 塞给 Ghidra）引擎就裸奔——所有 API 409，前端表现为「解包后所有函数看不了反编译、所有二进制导入失败」，看似三个 bug 实为一个根因。修：不同工程先导入、成功后再关旧（`old_project.close()` 挪到状态赋值之后）。
15. **面板状态机必须有空态**：搜索页签原为 hex-only 且输入为空 early-return → 上一次结果死在面板里「直接用不了」；字符串过滤同病。修法不是只补还原逻辑，而是给每个面板定义「空态该显示什么」（search.hint / 完整列表），输入变化必然落到两个合法态之一。三索引统一搜索（字符串/函数名/偶数位 hex 搜内存）是同一批补的衔接。
16. **上传的物理限制要讲给用户听**：浏览器 file input 只给内容不给路径，「直接打开二进制还在写 C 盘」的真凶是上传必然复制到数据目录 + 解包输出默认 %TEMP%。修法：解包输出跟样本走（`_lvr/unpacked/`，不可写再回退）；toast 讲清楚「要就地分析请粘贴绝对路径」。跟用户解释前先分清「设计如此（但要说明）」和「真回归」。

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

- **v0.3.1+ 候选**：弱签名标记（已知问题 #1）、xref 面板过滤 0x2e 之类垃圾地址行——v0.3.0 发版时留下的两个顺手活。
- **Linux/macOS**：`config.py` 已平台无关（hint 目录按平台分支），主要工作是实际跑一遍 + 文档。
- **pycdc 集成**：pyc 反编译仍是缺口，解包出 .pyc 后目前只能靠 dis。可考虑捆绑/调用 pycdc。
- **Pattern Language**：`.reference/ImHex` 有完整 DSL 实现；第一步可以只做「结构体声明 → 结构化视图」。
- **gdb 桥**：Windows 优先方案是 gdbserver（WSL/远程）+ MI 协议 over stdlib；先做「断点/单步/读寄存器/读内存」四件事。
- **签名库扩充**：`.reference/yara4ida` 的 SIGS 目录有最全的 crypto/hash/压缩签名集，可写转换脚本导入。
- ~~**Ghidra 数据库复用**~~：已实现（v0.3.0）——`.rep` 工程与样本路径一一映射（样本同级 `_lvr/`），二次打开秒级。可再做的：工程清单页（跨样本浏览 `_lvr/`）、打开旧样本时提示「检测到已有分析工程」。

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

**发版终检（2026-11-11，v0.3.0 定稿）**：

1. API 冒烟对照作者笔记工作流：锚点字符串 → xref（DATA+PARAM 双引用，带函数入口）→ decompile 行映射（gap 落「下一行」规则正中 `printf("Please input flag: ");`）；fgets thunk → 调用者 main；常量/熵字段齐全 ✅
2. 五张 README 截图用 v0.3.0 界面重拍（browser-use 后台直存 docs/screenshots/）：hero 空态 / workstation（做题链高亮 + 查壳结论 + `_lvr` 工程目录行）/ 调用图（深度 1 层次布局）/ 解码链（XOR 0x17 → XOR "ATRI" → flag）/ PyInstaller 解包（60 条目 + manifest 预览）✅
3. 过程中抓到并修掉两个 drawer 布局 bug（踩坑 #12：收起后死白 + hero 永不回）✅
4. 全量 pytest 125 passed；`node --check` 过 ✅

**UX 批量修复终检（2026-11-11，v0.3.0 发布后）**：

1. UI 路径 E2E（Playwright headless Edge 1920×1080，脚本 `C:\Users\50812\AppData\Local\Temp\e2e_ux.py`）**23 项断言全绿**：路径打开 → st-program/字符串列表就位；xref 卡片 inspector 首位 + 双击高亮 + 行零溢出；切换 pyre 时面板即刻清空、`/api/status` 引擎忙时 <3s 响应；解包 outdir 落样本旁 `_lvr/unpacked/`；manifest 预览可读文本 + Ghidra 按钮隐藏、pyc → noexec 提示、VCRUNTIME140.dll → 按钮出现；垃圾文件打开失败 → 引擎保住 pyre、UI 继续可用；统一搜索（字符串/函数名/MZ hex）+ 清空还原；字符串过滤清空还原；解码预设 b64→`flag{test}`、hex→`flag{x}`；操作中文标签 ✅
2. E2E 顺带抓出并修掉 **loadProgram 自我清空回归**（踩坑 #13）✅
3. 非引擎 pytest 118 passed；`node --check` 过 ✅
4. 干净态验证：中央 projects/samples/recent.json + 三个样本树 `_lvr` + 7 个 %TEMP% 解包残留全部清空后重跑全链路 ✅


## 通宵真人手操实测（2026-11-12，v0.3.2，10 项修复）

以浏览器手操方式把 10 个样本全链路过了一遍（不写测试脚本，纯点击/输入），发现并修复：

| # | 问题 | 根因 | 修法 |
|---|---|---|---|
| 1 | xref 卡片 UNCONDITIONAL_CALL 盖住地址 | .xref-type 固定 6ch 无 overflow 保护 | shortRefType 短标签映射 + title 全名 + ellipsis |
| 2 | 检查器标题显示 0X1400018C3 | .insp-group h3 的 text-transform:uppercase 波及 | #xrefs-target 豁免 |
| 3 | 空态说「从左侧选函数」但列表为空 | code.empty.dec 双场景复用 | 新增 code/disasm.empty.noprogram |
| 4 | 解码链输出=密文（参数失同步） | op 参数绑 onchange 依赖失焦时序 | 改绑 input 逐键同步 |
| 5 | 重命名后伪代码还是旧名 | renameCurrentFn 不刷新代码体 | 改名后对当前函数重新反编译 |
| 6 | 切样本搜索框残留旧词 | resetWorkspace 不清 search-q | 清空输入框与结果区 |
| 7 | 快速滚动函数列表行重复 | loadFunctions append 无并发守卫 | in-flight flag + append 失败写日志 |
| 8 | 搜 flag 命中 __nh_malloc 像错的 | 命中依据（签名 _NhFlag）不可见 | 命中行下显示签片段落（.row-sub） |
| 9 | pyc 预览无处可拿 | 只显示警告 | 显示 _lvr/unpacked 落盘路径 + 复制按钮 |
| 10 | 送解码后字节数标签不更新 | sendToDecoder 不写 dec-in-size | 立即按模式计算字节数 |

**实测覆盖**：challenge1（做题链+重命名+备注+解码 flag）/ c_sm4（SM4 命中@0x41d4c3，数字节区名为样本自带）/ pyre（解包 68 条目，入口 pyc 路径可复制）/ crackme_easy（双击 good sn → FUN_00401370:23 高亮）/ flower（685 fn 滚动加载 400→685）/ MazE（ELF 反编译+调用图）/ ez_debug（4047 fn；1.6MB 尾巴被正确识别为 COFF 符号表 32,738 符号——误报排除逻辑的活体证明）/ Ferris（熵 7.93 → 疑似加壳）。

**踩坑 #14**：IAB 的 clip 截图高度超过视口剩余空间时会滚动拼接，画面内容重复——看起来像 DOM 渲染了两份。遇到"重复渲染"先用 querySelectorAll 数 DOM 再下结论。

**踩坑 #15**：在隐藏页签里测滚动加载必然"失效"（clientHeight=0，scroll 事件都不会有）——自动化测试前先确认目标面板处于 active 态。

**遗留观察**（未修，不影响使用）：
- 常量命中落在数据段时反汇编标题显示 `? · 0x…`（函数名缺失，可显示所属内存块名替代）
- 解码实验室 op 参数默认值靠 OPS 定义里的 def，UI 上 placeholder 与实际值偶尔不一致（填过一次后 placeholder 就变了）

## KeygenMe 实战走查（2026-11-12，v0.3.2 后，2 项修复）

用工具全程浏览器手操解完 `D:\临时取证\ch10\KeygenMe`（Root-Me 的 GTK2 keygenme，32 位 ELF）。该样本用了**重叠指令混淆**：同一字节流按多个入口解码出不同指令，CALL 实为 JMP（CALL 后跟 `eb rel8` → `ADD ESP,4` 丢掉压栈的返回地址），夹 RDTSC 反调试——Ghidra 函数边界与反编译全被污染，反编译视图只能拿到校验骨架（`strtoull` + 假帧参数 + EDX:EAX 比较），核心算法是切到**内存 HEX 视图、按 vaddr = 0x8048e90 + hex 偏移 对着原始字节逐条手解码**才还原的：

> serial = Σ name[i]^(i+2) (mod 2⁶⁴)，name="Root-Me" → **10844645039911251**

**结论**：HEX 视图 + 手解码是反编译被打断时的可靠兜底，工具无需为此改引擎；做题链（查壳→字符串→xref→反编译）负责 80% 的结构还原。

顺手修的两个交互问题（浏览器实测通过，`node --check` 语法通过）：

| # | 问题 | 根因 | 修法 |
|---|---|---|---|
| 11 | 程序加载后中心空态还写「先打开一个二进制…」 | loadProgram 只调 resetWorkspace（装的是未打开文案），code.empty.dec 只存在于静态 HTML，被首次 wipe 冲掉后再没人恢复 | loadProgram 装完数据后把两个面板空态换成 code.empty.dec / disasm.empty |
| 12 | 顶部跳转框输函数名回车"没反应" | 名字分支只过滤函数列表、不动中心区（实为按地址跳转才直接动） | 精确命中 funcMap 直接 selectFunction；过滤后唯一命中也自动选中进反编译 |

## 裸反汇编功能：把手解码交给工具（2026-11-12，同日）

上一节 KeygenMe 的「结论」当天就被推翻了——HEX 手解码虽然可靠，但要人脑模拟 CPU。既然路径规则是明确的（无条件 JMP 跟目标、CALL-实为-JMP 丢返回、垃圾字节是反调试），就该让工具代劳。新增 **⚡ 裸反汇编** 页签：

**设计**（`src/lovelyreverse/disasm.py` 纯 capstone 模块，引擎只负责读内存字节）：

- 线性扫描 + 显式流策略：无条件直接 JMP → 跟随目标（永不 fall-through）；条件跳转 → 走 fall-through（反调试的 JAE/JA 进垃圾由下面的恢复机制兜底）
- **CALL-实为-JMP 签名**：callee 第一条是**向后**的直接 JMP → 视为混淆（真实 callee = `eb rel8` 回跳到 `ADD ESP,4` 丢返回簇）→ 跟进 callee，把压栈返回地址标记为「死返回」跳过；普通 CALL 走 fall-through
- **垃圾恢复**：撞上 int3/ud2/不可解码 → 回退到最近一个条件跳转的目标继续（最多 16 次），恢复点标注 `↝`；KeygenMe 实测最终策略下 0 次恢复（死返回跳过已把垃圾全绕开），恢复机制是保险带
- 终止：ret / end / trap / invalid / loop（自环）/ indirect / limit，页脚说明原因；visited 集防环

**真样本验证**：从 entry 0x8048f50 一键还原 KeygenMe 全部 142 条真实执行路径（stop=ret）——3 处 RDTSC 反调试 gauntlet、7 处死返回、`imul` 主循环、`add/adc` 64 位累加全数命中，与手解结论（serial = Σ name[i]^(i+2) mod 2⁶⁴ → 10844645039911251）互相印证。Ghidra 反编译器的重叠指令污染被完全绕开，无需改引擎。

**踩坑 #16**：第一版线性扫描把 CALL fall-through 一路解进故意垃圾（`in eax,dx` / `faddp` / `loopne`…），最后停在 (bad) 还错误恢复进 `ja` 的反调试垃圾目标——**识别 CALL-实为-JMP 是这类混淆的关键开关**，没有它线性扫描必然出轨；签名必须验「向后」JMP，普通 thunk（向前跳）不能误伤。

**浏览器 E2E（后台实测全通过）**：页签解码 142 条 → 点击跳转目标重新解码 → HEX 框输完整 vaddr 直达 → HEX ⚡ 一键回裸反汇编 → 从垃圾地址 0x8048f5e 起步也能优雅走到 ret。

顺手修的两个交互问题（E2E 中暴露）：

| # | 问题 | 根因 | 修法 |
|---|---|---|---|
| 13 | HEX 跳转框输完整 vaddr 读越界报错（ram:10090f50） | 只检查当前块包含关系；Ghidra 内存块是碎片化的（segment_2.1 只有 276 字节 ELF 头，0x8048f50 属于 .text） | 在全部块中定位包含地址的块并自动切换，再转块内偏移 |
| 14 | HEX 跳转框不支持回车 | 只绑了按钮 click | 补 Enter keydown，与裸反汇编地址框一致 |
