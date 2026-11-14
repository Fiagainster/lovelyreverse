# ch13 复现手记 — lovelyreverse 纯 UI 解题全流程

> 样本：`D:\临时取证\测试\ch13`（884 B，ELF32 i386，gcc，strip，无 libc——纯手写汇编）。
> 本文是给「明天照着复现」的操作手册：每一步点哪个按钮、输入什么、应该看到什么，
> 以及完整的探索思路——为什么走这条路、在哪拐弯、死过一次的地方为什么死。
> 工具版本要求：含「gdb 命令框」（2026-11-15 新增，见第 7 节）。

---

## 0. 启动与打开

1. `python -m lovelyreverse.cli serve --port 7331` → 浏览器开 `http://127.0.0.1:7331`
2. 点 **⌖ 打开二进制**（或路径框直接输入）`D:\临时取证\测试\ch13` → 回车
3. 等引擎分析完成：右侧「程序」面板显示 881 B / 基址 0x08048000 / **函数数 2**

第一印象三件事：

- 查壳结论：最大熵不高、无附加数据、无密码学常量 → 不是壳题、不是 crypto 签名题
- 函数列表只有 `entry`(2 B) 和 `FUN_08048063`(20 B)，而 .text 有 648 B → **代码量与函数数严重不符**
- 点开 ✎ 伪代码：两个函数都只有 `swi(0x80)`（int 0x80）→ **反编译已经报废，这是裸 syscall 汇编题**

> 经验：伪代码里出现成排 `swi(0x80)` / `swi(3)`，直接切换 ⌗/⚡ 视图，别再试图从反编译榨信息。

## 1. ⚡ 裸反汇编读出全部机关

center 面板点 **⚡ 裸反汇编**，地址框输入 `0x08048060`，点 decode。
它的执行流跟随（JMP 跟随）会自动跳过 `eb 01` + `cc` 这种成对花指令，得到干净的线性视图。
整段代码翻译如下（已把 `jmp +1` 花指令折叠掉）：

```
0x08048060  jmp 0x8048063                ; entry
── block1 ──────────────────────────
0x08048063  mov eax, 0x30                ; syscall 48 = signal()
            mov ebx, 5                   ; sig = SIGTRAP
            mov ecx, 0x80480e2           ; handler = 解密器
            int 0x80
0x08048077  int3                         ; ← 主动触发，跳进解密器
── block2 ──────────────────────────
0x0804807b  signal(SIGTRAP, 0x8048194)   ; handler = 完整性校验
0x0804808f  int3
── block3 ──────────────────────────
0x08048093  signal(SIGTRAP, 0x8048104)   ; handler = 提示+读输入
0x080480a7  int3
── block4 ──────────────────────────
0x080480ab  signal(SIGTRAP, 0x8048138)   ; handler = 输入 ⊕ 0xFC
0x080480bf  int3
── block5 ──────────────────────────
0x080480c3  signal(SIGTRAP, 0x8048149)   ; handler = 逐字节比较+宣判
0x080480d7  int3
── block6（兜底）────────────────────
0x080480db  mov eax, 1 ; int 0x80        ; exit(ebx=5) ← ebx 残留自 block5 的 signal
── 解密器（不在加密区内）────────────
0x080480e2  mov eax, 0x8048104
            loop: cmp eax, 0x80482e8 ; je done
                  xor dword [eax], 0x08048fc1
                  add eax, 4
0x08048103  done: …继续
0x08048104  ←—— 加密区域起点（484 B，全部 dword ⊕ 0x08048fc1）
```

**机关结构（SIGTRAP 手滑流）**：程序给 SIGTRAP 装了五个不同的 handler，
再用 `int3` 主动触发——每次陷阱跳进一段隐藏代码。五个 handler 里四个落在
`0x8048104` 起的加密区域内：**先解密，后执行**。

## 2. 算出解密密钥

解密器指令 `xor dword ptr [eax], 0x08048fc1`：

- 立即数 0x08048fc1，小端字节序 = **`c1 8f 04 08`**（注意不是 C18F0480，最后一个是 08 不是 80！）
- 循环从 0x8048104（4 对齐）到 0x80482e8，逐 dword 异或 → 区域内**每个字节**都按相位 `c1 8f 04 08` 循环异或
- 区域大小 0x80482e8 − 0x8048104 = **484 B**

## 3. 内存 HEX → ⚗ 送解码实验室

1. center 面板点 **⊞ 内存 HEX**，combobox 选 `.text`，offset 框输入 `0x8048104`，点 **读取**
   → hexgrid 第一行应显示 `7a 8e 04 08 c1 36 39 8a …`（首 dword 7a8e0408 ⊕ c18f0408 = bb010000，
   正是下面 handler1 的 `mov ebx,1`——密钥相位自检通过）
2. 点 hexgrid 上方的 **⚗** → 当前页送进解码实验室（抽屉打开，输入 484 bytes）
3. 处理链：下拉框选 **XOR 重复密钥** → **+ 添加** → key 填 `C18F0408` 并勾选 `hex` → **▸ 执行链**
4. 输出区勾选 **HEX 视图**（重要！文本视图会把 ≥0x80 的字节渲染成 U+FFFD，HEX 视图是精确的 hexdump）

**立刻能看到的明文串**（在 hexdump 的 ASCII 列，或用文本视图看尾部）：

| vaddr | 字符串 |
|---|---|
| 0x80481e4 | `Gratz, this is the good password !` |
| 0x8048207 | `Bad password, sorry !` |
| 0x804821d | `QUIT ! Executable is modified !` ← 有自校验！ |
| 0x804823d | `Enter the password: ` |

## 4. 人工解码 484 B：完整注解表

484 B 里的代码全部读完后（结合 HEX 视图逐段读），机关如下。区域基址 0x8048104：

```
handler1 @0x00 (0x8048104) — 提示 + 读输入
  bb 01 00 00 00          mov ebx,1                       ; stdout
  b9 3d 82 04 08          mov ecx,0x804823d               ; "Enter the password: "
  ba 14 00 00 00          mov edx,0x14                    ; 20 字节
  e8 b5 00 00 00          call 0x80481CD                  ; write 助手
  bb 00 00 00 00          mov ebx,0                       ; stdin
  b9 51 82 04 08          mov ecx,0x8048251               ; 输入缓冲区
  ba 80 00 00 00          mov edx,0x80                    ; 读 128 B
  e8 a9 00 00 00          call 0x80481D5                  ; read 助手
  bb 51 82 04 08          mov ebx,0x8048251
  01 c3                   add ebx,eax                     ; buf+n
  4b                      dec ebx                         ; 最后一个字节
  c6 03 00                mov byte [ebx],0                ; ← 抹掉换行！
  c3                      ret                             ; 经 sigreturn 回到 int3 之后

handler2 @0x34 (0x8048138) — 输入逐字节 ⊕ 0xFC（原地！）
  b8 51 82 04 08          mov eax,0x8048251
  loop: cmp byte [eax],0 ; je done
        xor byte [eax],0xfc
        inc eax ; jmp loop
  c3

handler3 @0x45 (0x8048149) — 逐字节比较 + 宣判
  b8 51 82 04 08          mov eax,0x8048251               ; 已 ⊕0xFC 的输入
  bb d1 82 04 08          mov ebx,0x80482d1               ; ★ 存储的基准串
  loop: mov cl,[eax] ; cmp cl,[ebx] ; jne bad
        cmp cl,0 ; je gratz
        inc eax ; inc ebx ; jmp loop
  bad:  write("Bad password, sorry !") ; exit(1)
  gratz: write("Gratz, this is the good password !") ; exit(1)

handler0 @0x90 (0x8048194) — 完整性校验（比 handler1 先跑）
  xor eax,eax
  ebx = 0x8048060 → 0x80482e0 每 dword: eax ^= [ebx]      ; 对整个映像求异或和
  cmp eax, [0x80482e4]                                    ; 与存储值比对
  不等: write("QUIT ! Executable is modified !") ; exit    ; patch 过就自杀

助手区 @0xC9..0xDF:
  0x80481CD  mov eax,4 ; int 0x80 ; ret                   ; write
  0x80481D5  mov eax,3 ; int 0x80 ; ret                   ; read
  0x80481DD  mov eax,1 ; int 0x80                         ; exit（无 ret）

存储区 @0xE0..:
  0x80481e4  "Gratz, this is the good password !\n"
  0x8048207  "Bad password, sorry !\n"
  0x804821d  "QUIT ! Executable is modified !\n"
  0x804823d  "Enter the password: "
  0x8048251  输入缓冲区（128 B）——运行时被 read 覆盖
  0x80482d1  ★ 基准串（密文态）：a5 cf 9d b4 dd 88 b4 95 af 95 af 88 b4 cf 97 b9 85 dd 00
  0x80482e4  完整性校验值（dword）
```

判定逻辑：`input ⊕ 0xFC == stored@0x80482d1` ⟹ **password = stored ⊕ 0xFC**。

## 5. 推导密码

HEX 视图输出里找到偏移 `000001c0` 那一行（vaddr 0x80482c0），取
vaddr 0x80482d1 起的字节（到 00 截止）：

```
a5 cf 9d b4 dd 88 b4 95 af 95 af 88 b4 cf 97 b9 85 dd
⊕ fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
  Y  3  a  H  !  t  H  i  S  i  S  t  H  3  k  E  y  !
```

**答案：`Y3aH!tHiSiStH3kEy!`**（18 字符，"Yeah! this is the key!" 的 leetspeak）

> 也可以直接在实验室追加第二级链：复制 stored 那段 hex → XOR 单字节 `FC` → 同样出答案。

## 6. 动态验证（⚙ 动态调试）

### 必须先说的一次失败

直接 ▶ 运行、逐个 ▏▶ 继续：5 个 SIGTRAP 都停下来了，但最终 **exit 05、控制台零输出**。
原因：gdb 默认 `handle SIGTRAP` 是 **stop + nopass** ——继续时 gdb 把信号吞掉，
程序自己的 handler 一次都没跑，执行流从每个 int3 直接滑过去，最后落到 block6
（ebx 残留 block5 的 5）→ exit(5)。**诊断线索**：控制台只有 5 个 signal-received
和 exit 05，没有任何 write 输出。

### 正确姿势：用 gdb 命令框放行信号

1. ⛭ 动态调试 → transport `WSL · Linux ELF`，发行版 `Ubuntu-22.04`
2. stdin 框填 `Y3aH!tHiSiStH3kEy!Z`
   （末尾多喂一个任意字符：handler1 会 `buf[n-1]=0` 吃掉它，等效于回车换行）
3. ▶ 启动会话（等「已装载」）
4. **gdb 命令框**（控制台上方新输入框）输入：`handle SIGTRAP nostop noprint pass` → 回车
   控制台回显 SIGTRAP 表：Stop=No / Print=No / **Pass=Yes**
5. ▶ 运行 → 程序一口气穿过 5 个 int3，控制台直接给出：

   ```
   Enter the password: Gratz, this is the good password !
   [Inferior 1 (process xxxx) exited with code 01]
   ```

### 想逐陷阱观察的变体（已实测）

gdb 命令框输入 `handle SIGTRAP stop print pass`（停 + 传）再 ▶ 运行：
5 次 signal-received 停止（0x8048078 / 0x8048090 / 0x80480a8 / 0x80480c0 / 0x80480d8），
**每次停止时**可以用寄存器面板、「内存读取」（expr 填 `0x80482d1`、len 24）偷看现场，
然后 ▏▶ 继续——信号照样送达 handler。第 5 个继续后输出 Gratz、exit 01。

## 7. 本次顺手修掉的工具短板（复现时已包含）

| 缺陷 | 修复 |
|---|---|
| 调试面板没有任何途径执行 gdb CLI 命令，自陷型样本（SIGTRAP/SEGF 让程序自接管的套路）全部失灵 | gdb 控制台上方新增 **gdb 命令框**，走 MI `-interpreter-exec console`，任何 CLI 命令可达（`handle`/`x/16xw`/`info proc mappings`…） |
| 目标退出后控制台停留在旧视图，成功输出看不见 | gdbPoll 在 exited 状态下也刷新列表/控制台 |
| 程序 stdout 与 MI 流交错后被归类 `[noise]` 隐藏 | noise 行去掉前缀，按程序输出直接显示 |
| 上一个文件的函数过滤器残留，新文件函数列表显示「无匹配项」 | 打开新文件时清空函数/字符串过滤器 |

## 8. 探索思路复盘（为什么这条路）

1. **看体积与函数数**：884 B / 2 函数 / 无 libc 导入 → 没有反编译价值，是汇编谜题。
2. **伪代码确认死路**（`swi(0x80)` 成排）→ 转向执行流视角。
3. **⚡ 裸反汇编是本题的钥匙**：`jmp+1`/`int3` 花指令让线性反汇编错位，执行流跟随自动避开；
   解出 5×(signal+int3) 的骨架。
4. **认出 syscall 号**：`mov eax,0x30` 不是"写"，是 `signal(48)`——这是理解全题的分水岭。
   手写汇编题里 ebx/ecx 的赋值对象（5、handler 地址）本身就是语义。
5. **先解密器后 handler 地址表**：signal 的 ecx 落点全部在 `xor` 循环的区间内 →
   "先解密再跳进去执行"的结论几乎不用猜。
6. **静态优先**：484 B 的解密用解码实验室一条 XOR 链完成，不需要先跑调试器；
   明文串一出来，题型（密码校验）和基准串位置（比较指令里的立即数 0x80482d1）就全知道了。
7. **比较基准 ≠ 密码**：中间还有一层 ⊕0xFC——基准串本身是密文态，要再翻一次。
8. **动态收尾**：密码正确性的最终裁判是程序自己；SIGTRAP 手滑流必须在 gdb 里放行信号
   （`handle ... pass`），否则得到的是 exit 05 的假象。

> 同型题迁移：凡是「函数极少 + .text 大部分当数据 + 伪代码空洞」的样本，
> 先裸反汇编扫 syscall 骨架（int 0x80 前的 eax），再决定静态解密还是动态跟进。
> ch12 的「自解密存根 + 折叠校验」是另一款机关，但入口判断方式相同。
