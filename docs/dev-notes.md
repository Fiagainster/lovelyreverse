# 开发笔记 & 续作指南（内部文档）

> 状态快照 2026-11-11 凌晨。给下一次继续开发的人（或下一个会话）看的。

## 当前进度

| 模块 | 状态 |
|---|---|
| 纯逻辑层 decode/xor/binfile/constants | ✅ 完成，含全套单元测试 |
| 引擎层 EngineManager（JVM 单线程队列） | ✅ 完成 |
| stdlib HTTP 服务 + 任务农场 | ✅ 完成 |
| 前端 IDE（函数/伪代码/汇编/**调用图**/内存 hex/字符串/导入导出/inspector/解码实验室/搜索/日志） | ✅ 完成并浏览器实测 |
| 加密常量扫描 | ✅ 真实二进制验证 5/5 命中 |
| 解码实验室 | ✅ 真实 CTF 题目（ez_debug）解出 flag |
| 测试 | ✅ 97 个（92 不需要 Ghidra + 6 个引擎集成） |
| CI workflow | ✅ 写好（未观察首次运行结果） |
| README | ✅ 完成（含截图） |

## 已知问题（按优先级）

1. **pytest 全量套件偶发在引擎测试的 JVM 启动处挂住**（intermittent，约 1/3 概率）。
   - 单独跑 `pytest -m engine` 从未挂过（多次 27-32s 完成）；独立脚本启动 JVM 也从未挂过。
   - 现象：引擎 fixture 的 `pyghidra.start()` 在 worker 线程里不开 JVM，且无报错（faulthandler 显示 startJVM 处有一次良性 SEH 打印——那行是 JPype on Windows 的已知噪音，JVM 实际能启动成功）。
   - 猜测：与并发 CPU 负载/资源竞争相关（常驻服务器 JVM + 浏览器同开时更容易复现）。
   - 已加缓解：`ensure_started()` 300s 超时会抛 `EngineError("JVM boot timed out")` 而不是无限等待。
   - **续作方向**：把 JVM 启动改到主线程（PyGhidra 支持 `pyghidra.start()` 任意线程，但 Windows + JPype + pytest 组合值得试主线程）；或引擎测试改用 subprocess 隔离。
2. **IAB（ZCode 内置浏览器）的 Playwright `press("Enter")` 不触发页面 keydown**：合成 `KeyboardEvent` 正常。真实浏览器不受影响（synthetic 与 trusted 事件都会触发 handler）。自动化测试该用 `dispatchEvent`。
3. 函数计数：inspector 的 `function_count` 已改为与列表一致（`len(funcs_cache)`，不含 thunk/external）。

## 调用图实现（v0.1.0 重写）

- 布局参考 Ghidra `GraphServices`（jungrapht）：**Sugiyama 层次布局**，不是力导向。
  - rank 计算：以中心节点为 0，沿 caller 方向 `-1`、callee 方向 `+1`，BFS 取最短（环自然收敛），钳制到 ±3。
  - 层内顺序：4 轮 barycenter 排序最小化边交叉。
  - 绘制：caller 在上 / 中心 / callee 在下；实线箭头 = 调用方向，虚线 = 回边（cyclic），同层边用二次曲线绕行。
  - 交互：双击节点增量展开（对该节点再请求 `depth=1` 后合并重排）、拖拽节点、拖拽平移、滚轮缩放（0.15–3.5）、`fit` 按钮；最小自动缩放 0.6 保证标签可读，超出视口时以中心节点锚定。
- **踩过的坑**：早期力导向实现里排斥力/引力参数配错，节点坐标发散到 `x≈1.7e7`，现象是画布全白 + 点击坐标全错。教训：图上一切坐标必须有界，布局后用 bbox 校验一次。
- **另一个坑（会再次遇到）**：canvas 的 `width` attribute 与 CSS 自适应尺寸形成反馈环——`ResizeObserver` 观察 canvas + 读写 attribute 尺寸 → 容器变宽 → 再测量 → 无限放大（曾到 207,608px）。修法：CSS 显式 `width/height: 100%`、父级 `min-width/height: 0`、`ResizeObserver` 观察父容器、绘制前对测量值做上限保护（>8000 直接放弃绘制）。
4. Ghidra 12.2 API 与旧文档差异踩坑记录（都已绕过）：
   - `FunctionManager.getFunctionByName` 不存在 → 迭代过滤
   - `ExternalManager.getExternalLocations()` 无参重载不存在 → 改用 `SymbolTable.getAllSymbols(True)` + `isExternal()`
   - `DefinedDataIterator.definedStrings` 不存在 → `listing.getDefinedData(True)` + `isinstance(value, str)` 过滤
   - `Memory.getBytes(Address, int)` 无此重载 → 必须 `getBytes(Address, JArray(JByte)(n))`（见 `_read_bytes` helper）
   - `Address` 对象不能 `int()` 直接转 → `addr.getOffset()`

## 续作清单（Roadmap 对应的实现提示）

- **Linux/macOS**：`config.py` 的 `data_dir/find_ghidra_install_dir` 和 `binfile.py` 已平台无关；主要工作是 ghidra 目录扫描路径与文档。
- **PyInstaller 解包**：把 `extremecoders-re/pyinstxtractor` 的 CArchive 解析逻辑移植成 `util/pyinstaller.py`，加 `/api/unpack/pyinstaller` 路由和前端按钮（参考资料已 clone 在 `.reference/pyinstxtractor`）。
- **Pattern Language**：`.reference/ImHex` 有完整 DSL 实现；第一步可以只做「结构体声明 → 结构化视图」。
- **gdb 桥**：Windows 优先方案是 gdbserver（WSL/远程）+ MI 协议 over stdlib；先做「断点/单步/读寄存器/读内存」四件事。
- **Ghidra 数据库复用**：open() 已实现「项目里有同名 program 就直接 openProgram」（二次打开秒级），可进一步把 `.rep` 项目与样本路径做映射持久化。
- **签名库扩充**：`.reference/yara4ida` 的 SIGS 目录有最全的 crypto/hash/压缩签名集，可写转换脚本导入。

## 开发环境备忘

- 启动开发服务器：`GHIDRA_INSTALL_DIR="D:/SecurityTools/ghidra_12.2_PUBLIC" python -m lovelyreverse serve --no-browser --port 7331`
- 测试样本：`D:\Project\网安训练\学习笔记\逆向\逆向题\challenge1\challenge1.exe`（mingw PE，172 fn / 280 strings）
- 加密夹具：`tests/fixtures/crypto_demo.c`（gcc 编译，含 AES S-box/SHA-256 K/TEA δ/Base64 表）
- gcc：`D:\System\mingw64\bin\gcc`（16.2.0）
- 参考项目都在 `.reference/`（584MB，已 gitignore），清单见 `.reference/README.md`

## 已验证的真实链路（回归基准）

1. 打开 challenge1.exe → 分析 → 116 函数（列表口径）/280 字符串
2. 点 main → 反编译渲染 → 点击代码里 `xor_encrypt` → 跳转到该函数反编译 ✅
3. 解码实验室：hex 输入 `302F...6F3E`，链 `[xor ATRI][xor 17]` → `flag{y0u_ar3_g0od_@_Debu9}` ✅
4. crypto_demo.exe → 常量扫描 5 命中（TEA δ 归属 tea_encrypt）✅
5. search `b979379e`（TEA δ LE）→ .text 命中且归属 tea_encrypt + .rdata 命中 ✅
6. decompile-all → 100 个 .c 的 zip 下载 ✅
7. engine 集成测试 6 个全过（27-32s）✅
