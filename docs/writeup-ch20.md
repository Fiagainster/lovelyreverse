# ch20 复现手记 — lovelyreverse 纯 UI 解题全流程

> 样本：`D:\临时取证\测试\ch20.bin`（732 B，ELF32 i386，Root-Me 系 crackme，strip）。
> 本文是给「照着复现」的操作手册：每一步点哪个按钮、输入什么、应该看到什么，
> 以及完整的探索思路——为什么走这条路、在哪拐弯、死过一次的地方为什么死。
> 答案在 §5：**`HardW@re_Br3akPoiNT_r0ckS`**（先自己推，卡住再看）。
> 工具版本要求：v0.4.2+（含 HEX 多页发送、解码实验室编码切换、unmapped 提示）。

---

## 0. 启动与打开

1. `python -m lovelyreverse` → 浏览器自动开 `http://127.0.0.1:7331`
   （裸命令也行——v0.4.2 起默认子命令就是 serve，之前会 AttributeError 崩溃）
2. 点 **⌖ 打开二进制**，路径框输入 `D:\临时取证\测试\ch20.bin` → 回车
3. 等引擎分析完成。右侧「程序」面板：732 B / 基址 0x08048000 / 函数数 1

第一印象三件事（⚙ 情报面板）：

- 查壳结论：ELF32、无附加数据、无密码学常量（AES/SM4 表都没有）→ 不是壳题、不是 crypto 题
- 「字符串」面板直接给出全部剧情：`Welcome to Root-Me Challenges`、`Pass: `、
  `Well done man, use this pass to flag!`、`Try again!` → **比较型 crackme，找比较逻辑即可**
- 函数列表只有 1 个——但 .text 明显不止一个函数的量 → 代码是手写汇编，Ghidra 没识别出辅助函数

## 1. ⚡ 裸反汇编一次读完整个程序

这个样本只有 163 字节代码（0x08048080–0x08048122，无花指令、无混淆），
⚡ 裸反汇编地址框输 `0x08048080` 点 decode，线性扫描一遍到底，翻译如下：

```asm
0x08048080  mov eax,4; mov ebx,1; mov ecx,0x80491a1; mov edx,0x26; int 0x80
            ; write(1, banner, 38)  "Welcome to Root-Me Challenges\r\nPass: "
0x08048096  mov eax,3; xor ebx,ebx; mov ecx,0x8049188; mov edx,0x33; int 0x80
            ; read(0, 0x8049188, 51)   ← 输入缓冲区 B
0x080480a9  xor ecx,ecx
            mov eax,0x8048080          ← 自身代码起点
            mov ebx,0x8048123          ← 自身代码终点
            call 0x8048115             ← 哈希函数，种子出在 ECX
0x080480ba  mov edx,ecx                ; EDX = 种子
            mov ecx,0x19               ; j = 25
            mov eax,0x8049155          ; A 表基址（注意 +1 的写法）
            mov ebx,0x8049188          ; 输入基址
0x080480cb  ror edx,1                  ; 每轮先右旋 1 位
            mov al,[eax+ecx-1]         ; A[j]   (= mem[0x8049154+j])
            mov bl,[ebx+ecx-1]         ; input[j](= mem[0x8049187+j])
            xor al,bl
            xor al,dl                  ; 三方异或必须为 0
            jne 0x80480f6              ; 失败
            dec ecx; jne 0x80480c1
0x080480de  write(1, 0x8049124, 38)    ; "Well done man, use this pass to flag!\n"
0x080480f6  write(1, 0x804914a, 11)    ; "Try again!\n"
0x0804810c  exit(0)
0x08048115  sub ebx,eax                ; 计数 = 163 字节
            xor ecx,ecx
0x08048119  add cl,[eax]               ; 低字节吸收代码字节
            rol ecx,3                  ; ★ 整个 32 位 ECX 左旋 3
            inc eax; dec ebx; jne 0x8048119
            ret
```

两个一眼要点：

- **种子不是常量**：call 前把自身代码首尾 (0x08048080, 0x08048123) 压进参数，
  哈希对象是**二进制自己的 163 字节代码**——自哈希（self-checksum）。
  种子完全由文件内容决定 → 静态可算，不需要逆。
- **校验循环只查 25 字节**：j 从 25 递减到 1，比较 `A[j] ^ input[j] ^ dl`，
  dl 是种子右旋 (26−j) 位后的低 8 位 → **异或消去即可直推密码，无需求逆哈希**。

## 2. 内存数据布局（⚙ HEX 面板）

.data 段 LOAD2 = 0x08049124–0x080491C7。HEX 跳转框输 `0x8049124` 回车
（v0.4.2 起合法绝对地址自动定位所在块；乱填会得到列出可读范围的 toast，不再发注定失败的请求）：

| 地址 | 内容 |
|---|---|
| 0x08049124 | `Well done man, use this pass to flag!\n` |
| 0x0804914A | `Try again!\n` |
| 0x08049154 | `0a` + **A 表 25 字节**（1e cd 2a d5 34 87 fc 78 64 35 9d ec de 15 ac 97 99 af 96 da 79 26 4f 32 e0） |
| 0x08049188 | 输入缓冲区（read 的 51 字节，密码占前 25） |
| 0x080491A1 | banner |

> 死过一次：在 HEX 框直接输 `0x08049120`（以为 .data 从这开始）→ 旧版报
> `ram:10091120` 读失败——基址 0x08048000 被当块内偏移又加了一遍。新版会
> toast「不在任何已映射块内 + 可读范围」，且 0x08049124 这种合法地址自动换算。

## 3. ⚗ 拿全 163 字节代码 → 解码实验室

自哈希种子要 163 字节代码原文，但 HEX 单页只有一块的量（chunk 截断）。

1. HEX 跳转框输 `0x8048080` 回车（LOAD1 = 0x08048000–0x08048123，只有 292 B，读到块尾为止）
2. **按住 Shift 点「⚗ 送入解码实验室」**——一次最多连发 8 页，自动拼接到块尾截断
   （toast 显示实际送入字节数；本样本 163 B 一次拿满）
3. 解码实验室输出格式选 **latin-1**（字节不丢、可逆），点 ⧉ 复制原始 hex

> 没有多页发送前，这里只能把 chunk 首页和页尾手动拼——顺手的修复正是被这题逼出来的。

## 4. 算种子与密码（页内 console，两段 JS）

种子哈希的正确语义（对应 0x08048115 的机器码）：

```
ECX = 0
对每个代码字节 b：cl = (ECX 低 8 位 + b) & 0xFF   ← 只动低 8 位
                 ECX = rol32(ECX, 3)              ← 整个寄存器旋转
```

浏览器 console 粘贴（hexstr 换成 §3 复制的 163 字节 hex）：

```js
function rol32(v,n){return((v<<n)|(v>>>(32-n)))>>>0}
function ror32(v,n){return((v>>>n)|(v<<(32-n)))>>>0}
const bytes = hexstr.match(/.{2}/g).map(h=>parseInt(h,16))
let S = 0
for (const b of bytes) {
  const lo = ((S & 0xFF) + b) & 0xFF
  S = rol32((S & 0xFFFFFF00) | lo, 3)
}
console.log("seed =", S.toString(16))        // → ac77e166
const A = [0x1e,0xcd,0x2a,0xd5,0x34,0x87,0xfc,0x78,0x64,0x35,
           0x9d,0xec,0xde,0x15,0xac,0x97,0x99,0xaf,0x96,0xda,
           0x79,0x26,0x4f,0x32,0xe0]
let pw = ""
for (let j = 1; j <= 25; j++)
  pw += String.fromCharCode(A[j-1] ^ (ror32(S, 26-j) & 0xFF))
console.log(pw)                               // → HardW@re_Br3akPoiNT_r0ckS
```

### 死坑：假种子 0x3C283DD3

第一版模拟把 `cl` 写成独立累加器（`cl = (cl+b) & 0xFF` 带出循环），
算出 seed = 0x3C283DD3，密码全是乱码。错在哪：

- `add cl,[eax]` 只改 ECX 的**低 8 位**，但上一轮 `rol ecx,3` 已经把高位绕回了低位——
  低 8 位里躺着历史高位，**不能脱离 S 单独累加**；
- 正确做法每轮从当前 S 取低 8 位再加字节（上面 JS 的 `lo` 行）。

> 经验：模拟寄存器哈希时，先问「这个 8 位子寄存器是不是全寄存器的投影」——
> rol/ror 之后 `cl/ch/dl` 全都混进了别处的位，独立维护必错。

## 5. 答案与校验公式

- **种子 seed = 0xAC77E166**（163 字节代码自哈希，静态可复算）
- **密码 = `HardW@re_Br3akPoiNT_r0ckS`**（25 字符，无前缀字符）
- 推导式：`input[j] = A[j] ^ low8(ror32(seed, 26−j))`，j = 1..25，对应缓冲区前 25 字节
- 成功回执：`Well done man, use this pass to flag!\n`（38 字节，与 write 长度 0x26 对上）

## 6. 动态验证（⚙ 动态调试，WSL gdb 桥）

1. 切 ⚙ 动态调试页签，选 WSL / Ubuntu-22.04（路径自动转 /mnt/d/...，控制台
   中文路径显示正常——v0.4.2 根修了混编转义 mojibake）
2. stdin 文本框填：`HardW@re_Br3akPoiNT_r0ckS`（**结尾必须带换行**——
   程序用裸 read 系统调用读 stdin，没有 \n 会一直等到 EOF）
3. ▶ 启动会话 → ▶ 运行
4. 控制台依次出现 banner、`Well done man, use this pass to flag!.`、`[Inferior 1 exited normally]`

> 对照组（顺手发现的邻题事实）：ch18.bin 在**任何输入**下都零输出——
> strace 实证 0 次 write()，`Great you Got it !!!` 只是 .rodata 里的摆设。
> 别把「console 里没看到输出」当成工具回归，先 strace 一把再下结论。

## 7. 探索思路复盘（为什么这条路）

1. **字符串先看牌**——四句台词直接锁定「比较型」，跳过壳/crypto 分支判断。
2. **小样本上裸反汇编优先于反编译**：163 字节手写汇编，Ghidra 函数识别只给了 1 个，
   ⚡ 视图线性一遍读完，syscall 骨架 30 秒到手。
3. **看到 call(自身代码首尾) 立刻识别自哈希**：参数是代码范围而不是数据指针，
   说明种子 = 文件内容的函数 → 静态可算 → 不走符号执行/爆破。
4. **校验循环是三方异或 → 直推不反演**：`A[j] ^ input[j] ^ dl == 0`，
   input 就是 A 和 dl 的异或，种子到手后密码是纯计算题。
5. **动态验证收尾**：静态推导的答案喂回 gdb 桥跑真程序，闭环确认。
   静态推导 → 动态实证，和 ch13 的「手解码 → gdb 验证」同一节奏。
