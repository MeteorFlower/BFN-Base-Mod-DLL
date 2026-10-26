# C 正确性审计：AutoOffline.cpp 与四份脚本

- 日期：2026-10-26
- 方向：代码正确性（语义、边界、失败路径、规格对照、时长与节流取值、脚本流程）
- 对象：`src/AutoOffline.cpp`（955 行）、`helper-scripts/1-disable-eaac.bat`、`2-enable-eaac.bat`、`3-clear-save.bat`、`src/build.bat`
- 规格来源：`逆向研究/reports/q9-loadout-capture.md`、`q10-loadout-apply.md`、`q11-loadout-restore-timing.md`
- 取证：IDA 会话 `8a657de6`（`BFN_2026_decrypted.exe.i64`，只读，未 patch、未改名、未建库）；.bat 结论在本机 Windows 11 26200 上实测
- 边界：只报告不改代码。性能与简化归 A，注释文风归 B，竞态与内存归 D，越界项收在末尾"交叉线索"

严重度：高 = 会丢功能或丢数据；中 = 特定条件下错或静默失效；低 = 触发面窄或只影响可维护性。

---

## 0. 结论速览

1. 七个挂点、参数表、"只在某个调用点生效"的两处返回地址判据，**全部与反编译一致**（第 1 节）。模型偏移、哈希表遍历边界、槽位数、charId 判 0 也**全部正确**（第 2 节）。
2. 真正的问题集中在**恢复链的兜底**与**存档落盘的失败路径**：UI 管理器为空时整场不恢复且没有任何补救（C-02）；"把所有配置清空"这个状态永远存不下来（C-03）；落盘失败后直接清脏标记，改动丢失（C-04）；存档只要有一处坏或带 BOM 就整份丢弃，且下一次改动会用空库覆盖（C-05）。
3. 脚本侧有两个**实测可复现**的探测失效：EA 注册表 `Install Dir` 的 `tokens=2,*` 落在了 `REG_SZ` 上（B-01），Steam `libraryfolders.vdf` 用空格当分隔符把带空格的库路径截断成 `C:\Program`（B-02）；自提权重启还会把带空格的路径拆成两个参数（B-03）。
4. 上次修过的"if 块内未转义 `)`"这一类，**没有残留**：只剩两处未转义的 `)`，都在顶层、不在括号块里，实测无害（B-10）。但 `3-clear-save.bat` 的行尾是 LF，与另外三份 CRLF 不一致（B-07）。

---

## 1. 七个钩子逐条核对（问 1）

### 1.1 汇总表

| # | 挂点（RVA） | 入口原字节（实测） | 参数 | detour 顺序 | 调用点判据 | 结论 |
|---|---|---|---|---|---|---|
| 1 | `0x156FA30` | `48 83 EC 28 E8 .. 32 C0 48 83 C4 28 C3` | `rcx` = slot | 不调 orig，直接 `return 1` | 无（全点生效） | 与注释一致：原函数恒返回 0，副作用是 `sub_14156E030(slot)` |
| 2 | `0x447450` | `8B 05 D6 1B DD 03 C3`（RIP 相对读 `dword_14421902C`） | 无参 | 先原函数，再按需补位 | `_ReturnAddress() == base+0x178A8C1` | **判据正确**，见 1.2 |
| 3 | `0x2546450` | `... C7 86 30 01 00 00 05 ...`（`+0x130 = 5`） | `a1`=self，`a2/a3` 原样 | 先原函数，再写 `self+0x130` | 无（全部构造） | **正确**，ctor 返回 `a1` |
| 5 | `0x450180` | `48 89 5C 24 10 48 89 74 24 18 57 48 83 EC 20` | `a1`=临时结构，`a2`=`off_144B0F8E0` | 先原函数，再在该点换假对象 | `_ReturnAddress() == base+0x1727CC0` | **判据与对象形状都正确**，见 1.3 |
| 6 | `0x1D05580` | `48 8B C4 57 48 81 EC 80` | `a1`=peer，`a2`=原因码 | 命中原因码则不调 orig | `reason == 0x961799A3` | **正确**，计数器在调用前已清零 |
| 漏斗 | `0x16B74C0` | `44 89 4C 24 20 53 55 57 48 83 EC 50` | `rcx`=mgr，`edx`=slot，`r8d`=charId，`r9d`=key，`[rsp+28h]`=value | 先原函数，再快照 | 无 | **签名与取值位置正确** |
| 建模 | `0x16AD770` | `4C 89 44 24 18 89 54 24 10 48 89 4C 24 08 55 53` | `rcx`=mgr，`edx`=slot，`r8`=资产，`r9`=flag，`[rsp+28h]`=perkDesc | 先原函数，再恢复 | 无 | **正确**，ctor 末尾 `return v9`（模型） |

补丁表里用于判断解密的五个 `rva/expected` 也逐个核过：`0x156FA30`（`48 83 EC`）、`0x178A8ED`（`0F 92 44 24 21`，即 `setb [rsp+21h]`）、`0x25464F4`（`05`）、`0x1D0F6F6`（`E8 85 5E FF FF`，目标 `0x141D05580`）、模型/漏斗入口字节。全部一致，且代码**不再改写任何字节**，`expected` 只当解密标记用，与实际行为相符。

### 1.2 补丁 2 的调用点判据正确，但补的位宽只覆盖 0..7（C-06，中）

- 行号：`741`-`742`、`750`-`751`
- 原文：`#define SESSMASK_SITE_RVA 0x178A8C1u` / `if ((unsigned long long)_ReturnAddress() == g_base + SESSMASK_SITE_RVA)` / `mask |= 0xFFu;`
- 反证：`sub_14178A650` 里 `0x14178A8BC: call sub_140447450`，下一条 `0x14178A8C1: mov ebx, eax`，之后 `0x14178A8E7: mov eax,[rsi+70h]` / `0x14178A8EA: bt ebx, eax`。返回地址 `0x14178A8C1` 与常量完全一致，判据没问题；`sub_140447450` 只有 6+1 字节，MinHook 能安全重定位那条 RIP 相对读。
- 问题：`[rsi+70h]` 是函数入口 `mov [rcx+70h], edx` 写进去的**第二个参数**，调用点 `sub_141781030` 只做了 `cmp edx, 0FFh`（255 排除），没有任何 0..7 的约束；`bt` 对 32 位操作数按 5 位取模，位号 8..31 都是合法输入。
- 触发条件：该函数被以 8 及以上的位号调用（真实上限受对局人数限制，当前 8 人局是 0..7，所以**当前版本大概率不会触发**）。
- 后果：补丁 2 静默失效。日志仍打印 `hook @ ... OK`，从日志上看不出"补上了但没补对"。
- 建议：该点直接 `return 0xFFFFFFFFu;`。语义完全等价（位号按 32 取模，0..31 全覆盖），且对任何未来位号都成立；或者至少把 `0xFF` 换成 `~0u`。
- 证据：`0x14178A650` 反汇编 `mov [rcx+70h], edx` / `mov eax,[rsi+70h]` / `bt ebx,eax`；调用点 `0x14178121A` 的 `mov edx,[rdi+20h]; cmp edx,0FFh; jz skip`。

### 1.3 补丁 5 的判据与假对象都正确（无缺陷，仅记录取证）

- 行号：`803`-`808`、`818`
- 反证：`0x141727CBB: call sub_140450180`，返回地址 `0x141727CC0`，与 `0x1727CC0ull` 一致。消费侧 `0x141727CC3: mov rcx,[rax]; 0x141727CC6: cmp byte ptr [rcx],0; 0x141727CC9: jz loc_141727D88`，而 `loc_141727D88` 正是"执行交互"的分支（其后 `sub_14172E020` 派发交互事件），非空名字走的是 `LABEL_8` 的"拒否"分支。假对象 `{ptr->"" , nullptr}` 恰好满足 `[rax]` 指向空串。
- 同函数里还有第二处调用 `0x141727F0F`（`*(float*)sub_140450180(...)`），返回地址 `0x141727F14`，返回地址判据正确地把它排除了。
- 备注：`sub_140450180` 的返回对象在某些分支来自 `sub_1404B1920`，可能带引用计数；在该点丢弃 orig 的返回值是否会漏一次释放，属 D 方向（见交叉线索）。

### 1.4 补丁 6 与漏斗/建模钩子的返回值语义

- 补丁 6：`sub_141D05580(a1, 0x961799A3)` 的调用点是 `0x141D0F6F6`，且调用前已经 `*(u32*)(a1+176)=0; *(u8*)(a1+249)=0`，所以吞掉上报不会留下"计数不清零"的副作用，注释属实。`sub_141D0F4B0` 只有数据 xref（vtable/描述符），返回值无人使用，detour 声明 `void` 安全。
- 漏斗：`sub_1416B74C0` 声明返回 `__int64`，detour 声明 `void`。逐个查了全部 6 个代码调用点（`0x1416B75C0 / 0x1416B7DD8 / 0x1416B7EBE / 0x1416B7FBD / 0x1416B89DD / 0x1416B8BAB`），调用后紧跟的指令都不读 RAX（`cmp ebp,ebx` / `test r15b,r15b` / `cmp edi,ebx` 等），**销毁返回值不影响任何调用者**。

---

## 2. 模型偏移、遍历边界、槽位数、charId（问 2）

### 2.1 偏移与遍历边界全部正确

| 代码常量 | 值 | 反编译证据 | 结论 |
|---|---|---|---|
| `kModelCharId` | 216 | `sub_1416AD770` 的 `*(u32*)(v9+216)=v13`；`sub_1416AEB60` 的 `cmp ...[216], a3` | 对 |
| `kModelPresetArray` | 280 | `sub_1416AC290` 的 `v4=*(u64*)(model+280)`；`sub_1416ABF60` 的 `*(u64*)(model+280)+56*idx` | 对 |
| `kPresetSize` | 56 | 同上 `imul r8, r14, 38h` | 对 |
| `kPresetMap` | 8 | 漏斗 `*(u64*)(model+280) + 8` 后 `sub_141009BC0` | 对 |
| `kMapBuckets` | 8（桶数组指针，preset+16） | `sub_1416AC290` 的 `v5 = *(__int64***)(v3+v4+16)` | 对 |
| `kMapBucketCount` | 16（桶数，preset+24） | `sub_1416AC290` 的 `result = *(u32*)(v3+v4+24)` | 对 |
| 节点 `+0` key / `+4` value / `+8` next | 16 字节 | `sub_1416AC290` 的 `v10=*j`（低 32 位 key，高 32 位 value）、`j[1]` 为链 | 对 |

- **桶数组是 count+1 格，最后一格是哨兵**：`sub_1416AC290` 里 `v9 = v5[result]`（`v5` 是桶数组、`result` 是桶数），遍历用 `while (j != v9)`，并且用 `for (i = v5 + 1; !*i; ++i)` 跳过空桶。代码的捕获只走 `b < buckets`（0..count-1），**不会去走哨兵格**，这一点是对的，值得明确记一笔（走哨兵会把哨兵当节点解引用）。
- 槽位数组长度：构造器 `for (m = 0; m < 3; ++m)` 恒分配 3 个，代码用 `kPresetCount = 3` 硬编码读写两边一致。**但代码没有按 `(model+288 - model+280)/56` 复核实际长度**（`sub_1416AC290`、`sub_1416ABF60` 都是这么算的）。当前构造器保证是 3，所以不是缺陷；若将来模型布局变化，这里会越界读。建议加一句长度复核并记日志（低）。

### 2.2 charId 判 0 成立，但恢复侧没有对称检查（C-07 附带，低）

- 行号：`531`（`if (charId == 0 || n == 0) return;`）、`631`（恢复侧直接 `charId = *(u32*)(model+216)`，无 0 检查）
- charId 是 `sub_141E6C170` 的 djb2 结果，真实资产名不为 0，且 `+216` 在构造器返回前必已写入（`0x1416ad8c5`），所以判 0 作为"无效"成立。
- 恢复侧不判 0 的后果只在于手改 JSON 写入 `"id": 0` 时，会匹配到 charId 为 0 的模型（现实中不存在）。属可忽略，但两侧不对称，建议统一。

---

## 3. 存档格式与落盘（问 3）

### 3.1 读路径：坏 JSON 与缺字段会整份丢弃，且下一次改动会覆盖掉原文件（C-05，高）

- 行号：`331`-`368`
- 原文：`nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);`；`const nlohmann::json &chars = doc.at("characters");`；`const nlohmann::json &opts = presets[(size_t)p].at("options");`；`catch (...) { g_chars.clear(); return false; }`
- 触发条件（任一条）：
  1. 文件被记事本保存成"UTF-8 带 BOM"，`nlohmann::parse` 不跳过 BOM，直接 `is_discarded()`；
  2. 手改时漏了任何一个 `"options"`、`"id"`、`"presets"` 字段；
  3. `"version"` 写成字符串 `"1"`（`doc.value("version", 0u)` 抛 `type_error`）。
- 后果：`g_chars` 被清空，整份存档作废。**随后玩家只要改一次外观，`SaveStore` 就用空库加这一个角色覆盖 `autooffline_save.json`**，其余角色的数据不可恢复。日志里只有一行 `!! save:...`，玩家看不到。
- 建议：
  1. parse 前跳过 `EF BB BF`；
  2. 逐角色 try/catch（坏一个丢一个，不要整份丢），并在日志里报"丢弃了第 N 个角色"；
  3. 整份不可读时**不要覆盖原文件**：把 `g_chars` 置空的同时置一个 `g_save_readonly`，`SaveStore` 见到它就写到 `autooffline_save.json.new` 并大声报；
  4. 版本号不认识（`version > kSaveVersion`）时拒绝写入，只读。
- 证据：`nlohmann::json::parse(..., false)` 不做 BOM 跳过；`catch` 里 `g_chars.clear()` 与 `SaveStore` 无条件 `MoveFileExA(... REPLACE_EXISTING)`（`435`）。

### 3.2 "多字段/旧文件"安全，"version 不匹配照读"是隐患（低）

- 行号：`337`-`339`
- 原文：`if (version != kSaveVersion) Log("!! save:version %u, expected %u, reading it anyway", ...)`
- 旧文件带 `active_preset` 之类的多余字段：`nlohmann` 忽略未知键，**安全**；`presets` 多于 3 个时多余的被 `p < kPresetCount` 截掉，**安全**（但静默）。
- 隐患：将来把 `kSaveVersion` 提到 2 并改变语义时，旧代码仍会"照读"，把 v2 文件按 v1 解释。建议改成 `version > kSaveVersion` 时只读、不写。

### 3.3 落盘不会写半个文件，但"改完立刻关游戏不能丢"没有做到（C-04，中高）

- 行号：`940`-`943`
- 原文：`if (g_save_dirty) { g_save_dirty = false; SaveStore(); }`
- 原子性：先写 `.tmp` 再 `MoveFileExA(..., REPLACE_EXISTING)`，短写/`fclose` 失败会删 `.tmp` 并返回 false（`427`-`439`），**不会留下半截文件，注释属实**。
- 问题一：`SaveStore()` 失败（磁盘满、杀软占用、目标被占用）时，脏标记已经被清掉，这次的改动**永久丢失**，只有一行 `!! save:...`。
- 问题二：没有任何进程退出时的 flush。`DllMain` 只处理 `DLL_PROCESS_ATTACH`（`947`-`955`），Worker 线程在最坏情况下有 **100 ms** 的窗口没落盘；玩家点完皮肤立刻 Alt+F4 就丢。注释自己写的是"玩家改完立刻关游戏也不能丢"，与实现不符。
- 问题三：没有 `FlushFileBuffers`，`MoveFileExA` 也没有 `MOVEFILE_WRITE_THROUGH`。断电后文件存在但内容可能还是旧的（不是半截，是旧版本）。注释只承诺"不会留下半个文件"，这一点成立。
- 建议：`SaveStore` 返回 false 时**保留脏标记**并退避重试；退出路径加一次 flush（`DLL_PROCESS_DETACH` 或 Worker 里检测主模块卸载）。

### 3.4 两次启动之间不会漂移，但"清空全部"永远存不下来（C-03，高）

- 行号：`531`
- 原文：`if (charId == 0 || n == 0) return;`
- 触发条件：玩家把某个角色的三个槽位全部清空（五件套全默认、Perk 全卸），此时 `n == 0`。
- 后果：本次改动**不写入存档**，`SavePutCharacter` 不执行，旧的（有内容的）记录原样保留。下次启动恢复时，**被清掉的外观又回来了**。玩家会觉得"清空操作无效"。
- 一致性：单槽清空不受影响（三槽整体快照，`SavePutCharacter` 是整份替换），只有"三槽同时为空"这一种状态存不下来。
- 建议：把"角色存在但三槽全空"当成合法状态写入空数组，只保留 `charId == 0` 这一道闸。
- 证据：`SnapshotModel` 的 `n` 是三槽合计（`presetStart[3]`），只有全空才是 0。

### 3.5 截断与上限是静默的（C-09/C-10，低）

- 捕获侧 `505`：`while (node && n < cap && guard < (int)kMapMaxBuckets)` 到达 `cap`（1024）直接停，**不打日志**；`SnapshotModel` 拿到的 `n` 就是 1024，照常落盘。恢复侧 `644`-`647` 有 `!! restore: too many values ... truncated`，两侧不对等。
- 捕获侧 `501`：`if (arr && buckets && buckets <= kMapMaxBuckets)`，桶数超过 4096 时整个 preset 被跳过，`presetStart` 记 0 条，同样无日志。
- 恢复侧 `644`-`647` 的 `break` 只跳出内层循环，外层 `p` 还在转，最多会打 3 行同样的日志（不是错，只是不干净）。
- 实际触发概率极低（一个角色三槽合计不会到 1024 条），但按项目"不许静默降级"的规矩，捕获侧应当至少打一行 `!! capture: truncated at %d`。

---

## 4. 时长与节流（问 4）

| 取值 | 位置 | 判定 |
|---|---|---|
| 解密轮询 500 ms | `151` | 合理。代价是解密完成后最多 500 ms 才能装钩子，见 C-11 |
| 超时 180 s | `150` | 合理偏宽松。超时后 `LogMissingPatterns()` 逐条打印期望/实际字节，并明确写 `NOTHING was hooked`，达标 |
| 落盘节流 100 ms | `939` | 数量级合理，但缺退出 flush，见 C-04 |
| 脚本等待 | 三份 .bat | 没有 sleep/重试。`assertGameClosed` 是即时快照，玩家关游戏后必须重跑脚本，提示里已经写了，可接受 |

### C-11 装钩子滞后 500 ms 会漏掉窗口内建好的模型（中，未验证概率）

- 行号：`911`-`919`
- 原始行为：解密后游戏立刻恢复执行，模型由每帧回调 `sub_141558320` 建，每个玩家槽只建一次（槽状态 `+1712` 置 1 后不再重建）。
- 触发条件：模型在本 DLL 探测到解密（最多晚 500 ms）并装完钩子之前就建好。
- 后果：这一次会话里这些模型永远不会被恢复，玩家看到默认外观，日志里也没有任何异常（只剩正常的 `hook @ ... OK`）。
- 缓解现状：建模闸门还要求"本地玩家对象有效"，正常要从登录流程拿到，通常远晚于 500 ms，所以概率很低。
- 建议：把 `AllExpectedPresent` 的第一个匹配步骤缩短到一个更小的轮询间隔（例如前 5 s 用 50 ms，之后退回 500 ms）；或用 q11 的备选 2（挂 `0x16AEB60` 首次命中时惰性恢复）作为兜底。

---

## 5. 失败路径是否"大声失败"（问 5）

达标的部分（都有日志，且不假装成功）：`MH_Initialize` 失败（`836`-`840`）、单条 `MH_CreateHook`/`MH_EnableHook` 失败（`855`-`870`）、入口字节不合（`674`）、解密超时（`921`-`927`）、SEH 读到错（`527`、`656`）、`MoveFileEx` 失败（`435`）、存档不可解析（`332`）。

不达标的部分：

### C-02 UI 管理器为空时整场不恢复，且没有任何补救（高）

- 行号：`635`-`639`
- 原文：`void *ui = *(void **)(g_base + kUiManagerRva); if (!ui) { Log("!! restore: UI manager is null, character %u skipped", charId); return; }`
- 触发条件：模型构造时 `qword_144659DB0` 还没建（q11 §6.4 明确列为最大风险，创建点未定位）。
- 后果：`sub_1416AF1D0` 在没有 UI 管理器时**既不灌也不清**，而我们的写回全被跳过；模型每槽只建一次，本会话再无第二次机会。玩家这一局所有皮肤与 Perk 都是默认值，日志里只有一行 `!!`，玩家不会去看。
- 规格对照：q11 §7.1 给的配方是"判空则先只写 map 并置 pending，等 `sub_1416ABF60` 首次命中时补写"，或直接改用备选 2。当前实现**只做了判空，没做兜底**。
- 建议：最低成本是加一道 pending：记录 `(slot, charId)`，在漏斗或 `sub_1416ABF60` 的下一次命中时补一次 `RestoreModel`；或者按 q11 的做法，UI 为空时用 `sub_1416B74C0` 逐键写 map（内部已判空，不会崩），并把 `model+220` 临时切到目标槽。

### C-08 日志文件打不开等于全程静默（中）

- 行号：`895`（`g_log = fopen(logPath.c_str(), "w");`）、`174`（`if (g_log) {`）
- 触发条件：游戏目录不可写（装在 `Program Files` 且未提权运行、或被杀软拦截）。
- 后果：`Log()` 变成空操作，**包括 `!! NOTHING was hooked`**。玩家看到的现象是"mod 没生效、也没有日志"，与"mod 生效了但没触发"在外部完全不可区分，正是项目规矩里点名的静默降级。
- 建议：`fopen` 失败时 `OutputDebugStringA` 输出一行，并把日志改写到 `%LOCALAPPDATA%`；再不行就 `MessageBoxA` 一次。

### C-07 补丁 3 的取值校验与文档不符（中）

- 行号：`243`
- 原文：`if (fscanf(f, "%i", &v) != 1 || v < 0 || v > 255)`
- 文档（`229`-`231`）写的是"写个 0..5 的十进制数"，枚举表也写明 7/8 是越界值。
- 触发条件：玩家手滑写成 `11`、`200`。
- 后果：越界值被原样写进 `UserProfileInfo+0x130`，游戏连不上服务器，日志只写 `patch3 value <- ... = 0xC8 (200)`，看起来像"设置成功了"。属静默降级。
- 建议：`v > 5` 直接拒绝并回落到默认 1，日志写明"超出枚举范围 0..5"。

---

## 6. 脚本流程（问 6）

### 6.1 括号与转义：上次那类 bug 没有残留（B-10，无缺陷）

- 机械扫法：`grep -n "echo" *.bat | grep -E "[()]" | grep -v '\^)'`，只剩两处未转义的 `)`：
  - `1-disable-eaac.bat:138` `echo     Moving it to stale\ first (nothing is deleted).`
  - `2-enable-eaac.bat:177` `echo     (Frosty Mod Manager re-adds it the next time it launches the game.)`
  - 两处都在**顶层**（不在任何 `(` 块里），实测无害。
- 反向实测（本机）：块内 `echo D: (text ... unescaped)` 会被当成 if 块的结束符，输出被截断成 `D: (text in parens unescaped both sides`，块提前闭合。所以这类问题确实只能靠"块内必须 `^)`"来防，当前代码满足。
- 建议：收口时把这条 grep 固化成脚本检查项，避免下次又漂。

### 6.2 B-01 EA 注册表探测实际取不到路径（中，实测格式）

- 行号：`1-disable:237`、`2-enable:263`、`3-clear:195`
- 原文：`for /f "tokens=2,*" %%A in ('reg query %%K /v "Install Dir" 2^>nul') do set "ED=%%B"`
- `reg query` 的输出形态是 `    值名    REG_SZ    数据`，默认分隔符是空格和制表符。值名是 `Install Dir`（**带空格，两个 token**）时：`token1=Install`、`token2=Dir`，`tokens=2,*` 得到的 `%%B` 是 `REG_SZ    C:\...`。
- 实测（复刻 reg 输出格式）：`A=[Dir] B=[REG_SZ C:\Program Files\EA Games\PVZ Battle for Neighborville]`
- 后果：`set "ED=REG_SZ C:\..."`，`:try` 里 `if exist "REG_SZ C:\...\PVZBattleforNeighborville.exe"` 必然为假，**第 3 步（EA app 注册表）等于死代码**。装在默认路径时靠第 4 步的盘符扫描还能兜住；装自定义路径时只能靠拖拽或命令行参数。
- 建议：改成 `tokens=2 delims=` 行不通，正确写法是按类型列定位，例如 `for /f "tokens=2,*" %%A in ('reg query %%K /v "Install Dir" 2^>nul ^| findstr /i "REG_SZ"') do ...` 也只能拿到 `REG_SZ`；更稳的是 `for /f "skip=2 tokens=*" %%A in ('reg query ...') do set "ED=%%A"` 再手工剥掉 `REG_SZ` 前缀，或改用 `reg query` 后按 `    ` 四空格切分。

### 6.3 B-02 Steam 库路径解析按空格切分，带空格的库一律丢失（中，实测复现）

- 行号：`1-disable:216`、`2-enable:242`、`3-clear:174`
- 原文：`for /f "usebackq tokens=2 delims=<TAB><SPACE>" %%P in (` + "`findstr /i /c:\"\\\"path\\\"\" ...`" + `) do (...)`
- 实测（构造 `libraryfolders.vdf`，两条库：`C:\\Program Files (x86)\\Steam` 与 `D:\\SteamLibrary`）：
  ```
  RAW=["C:\Program]          LIB=[C:\Program]
  RAW=["D:\SteamLibrary"]    LIB=[D:\SteamLibrary]
  ```
- 后果：第一个库被截成 `C:\Program`，`:try` 必然失败。默认 Steam 在 `Program Files (x86)` 正好带空格，所以"非默认盘 + 默认安装名"这种情况（如 `E:\Program Files (x86)\Steam`）探测不到。默认盘符扫描会命中 `%%D:\Program Files (x86)\Steam\...`，所以影响被掩盖了一部分。
- 建议：`delims` 只留制表符（`delims=<TAB>`），`%%~P` 会自动剥引号；这样带空格的路径能完整取到。

### 6.4 B-03 自提权重启会丢掉带空格的路径参数（中，实测复现）

- 行号：`1-disable:29`、`2-enable:36`、`3-clear:37`
- 原文：`powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -ArgumentList '%~1' -Verb RunAs"`
- 实测：`Start-Process -ArgumentList 'C:\Program Files\Some Game'` 交给子进程后被拆成两个参数（`ARG1=[C:\Program]`、`ARG2=[Files\Some]`）。`Start-Process` 不做重新加引号。
- 后果：拖拽一个带空格的游戏目录到 .bat 上时，提权后的子进程只拿到 `C:\Program`，`call :detect "%~1"` 失败，退回注册表/盘符扫描（见 B-01/B-02 也都有问题），自定义路径就彻底找不到，只留下"Could not find ..."的提示。不提权时（已在管理员窗口里跑）没有这个问题，所以现象是"有时能找到有时不能"。
- 建议：`-ArgumentList ('\"{0}\"' -f '%~1')`，或对 `%~1` 手工加转义引号；同时给子进程传一个 `--elevated` 标记，见 B-04。

### 6.5 B-04 `net session` 判权失败会导致反复自提权（低，未验证）

- 行号：三份脚本各 3-4 行（如 `1-disable:23`-`39`）
- 机制：`net session` 在 Server 服务被停用、或以 SYSTEM 身份运行时也会返回失败。此时提权后的子进程同样判"不是管理员"，于是再 `Start-Process -Verb RunAs` 一次，已经提权的进程不会再弹 UAC，形成无限开窗。
- 触发条件：`LanmanServer` 服务被禁用（少见但存在）、或脚本被计划任务以 SYSTEM 拉起。
- 建议：判权改用 `fltmc >nul 2>&1`，或者给子进程传一个"已提权"参数，父进程见到参数就不再自提权。
- 后果严重度：一旦命中就是刷屏级故障，但概率低，标未验证。

### 6.6 B-05 2-enable 先开 EAAC 再删 DLL，中途失败会留下危险组合（中）

- 行号：`85`-`176`（步骤 1 恢复 EAAC，步骤 2 才处理 RtWorkQ.dll）
- 触发条件：步骤 2 的 `del` 或 `move` 失败（文件被占用、权限不足）。
- 后果：脚本 `exit /b 1` 退出，但状态是"EAAC 已开 + 我们的 RtWorkQ.dll 还在游戏目录"。下次启动游戏时反作弊是开着的，而目录里躺着一个代理 DLL，这正是这套切换器最该避免的状态。
- 建议：把两步顺序对调（先删/移 DLL，再恢复 EAAC），失败时宁可停在"EAAC 关着、DLL 已删"，也不要停在"EAAC 开着、DLL 还在"。

### 6.7 B-06 2-enable 里的 `[!]` 在延迟展开下会被吃掉（低，实测）

- 行号：`94`、`100`、`107`、`124`、`130`、`142`、`148`、`152`、`172`
- 原因：`setlocal EnableDelayedExpansion`（`22`）下，未配对的 `!` 会被解析器丢弃。实测 `echo A: [!] Could not delete the .bak.` 输出 `A: [] Could not delete the .bak.`。
- 后果：只影响观感，不影响流程（这些行都只有一个 `!`，不会误展开变量）。
- 建议：统一改用 `[X]`/`[i]`（1-disable 和 3-clear 就是这么写的），或者 `^!` 转义。

### 6.8 B-07 3-clear-save.bat 的行尾是 LF，其余三份是 CRLF（低）

- 实测：`src/build.bat` CR=107/LF=107，`1-disable` CR=281/LF=281，`2-enable` CR=307/LF=307，**`3-clear-save.bat` CR=0/LF=224**。
- 本机复现：`call :label`、`goto :label`、`if` 块、`set /p` + `if /i` 比较，LF 版与 CRLF 版行为完全一致，**在当前 Windows 11 26200 上复现不出故障**。
- 但这是 cmd 解析器的历史敏感项，而且这份文件恰好是刚修过括号 bug 的那份，很可能是那次编辑带进来的。建议收口时统一转成 CRLF，并加进机械检查。
- 附加：这份文件的 `assertGameClosed` 里有一行 `echo     (The mod writes the save while the game is running.^)`，只转义了 `)` 没转义 `(`。实测块内未转义的 `(` 不坏事，但风格与 1-disable 的 `a^)` 不一致，建议成对处理。

### 6.9 前置判断"游戏在跑就拒绝"可靠性（结论：可用）

- 实测：`tasklist /fi "imagename eq PVZBattleforNeighborville.exe" /nh | findstr /i /c:"..."`，无进程时 findstr 返回 1（走"已关闭"分支），有进程时返回 0（走"拒绝"分支），**逻辑正确**。
- 用完整路径调 `findstr.exe` 的注释属实，确实能避开 PATH 上同名程序。
- 两处残留风险（低）：
  1. `2>nul` 把 tasklist 的错误吞了；若 `tasklist` 不可用，管道无输入，findstr 返回 1，脚本会**静默当成"游戏没在跑"**继续。建议先判 `where tasklist`。
  2. 检查与操作之间没有重试，玩家在检查通过后手动启动游戏仍会撞上文件占用（各处的 `if exist` 复核能兜住，行为正确）。
- 另外三份脚本都没检查 EA app 本体（`EADesktop.exe`）是否持有游戏目录，属于可接受的设计取舍。

### 6.10 其余脚本问题（低）

- `2-enable:91`-`95`：删除残留 `.bak` 失败只 `echo [!]`，最终仍 `exit /b 0`，与同一脚本其它失败一律 `exit /b 1` 的约定不一致。
- `3-clear:84`-`89`：只在主文件存在时才走到 `117` 的 `.tmp` 清理。若上次落盘在 `MoveFileEx` 之前中断，只剩 `autooffline_save.json.tmp`，脚本会提示"没有存档，无需删除"并留下 `.tmp`。建议 `.tmp` 单独判断。
- `1-disable:93`-`112`：EAAC 改名成功之后，若第 2 步安装 DLL 失败，会停在"EAAC 已关、DLL 未装"的半状态（`exit /b 1`，提示清楚）。影响可控，但如果要更稳，可以在失败时把 `.bak` 改回去。
- 退出码一致性总览：成功 `0`、失败 `1`、用户取消 `0`（3-clear），提权分支的 `exit /b`（无参数）继承上一条命令的 errorlevel，符合预期。

### 6.11 build.bat（结论：逻辑正确，两处小建议）

- `49`-`50` `call "%VCVARS%" >nul` 后立刻 `if errorlevel 1 ( echo [!] vcvars failed & exit /b 1 )`：如果 vcvars 内部最后一条命令留下非零 errorlevel，会误报。未实测，建议改成判定 `if not defined VSCMD_ARG_TGT_ARCH` 之类的副作用变量。
- `64`-`71` 的 `^` 续行没有尾随空格，CRLF 行尾，**安全**。
- `72` `if errorlevel 1 goto :build_failed`：`cl /LD ... /link` 的返回值包含链接阶段，LNK1104（DLL 被占用）能正确捕获，`:build_failed` 的提示与 `exit /b 1` 都对。
- 成功路径只 `dir /b AutoOffline.dll` 展示，不校验产物存在/时间戳（D-01，低）。`cl` 的退出码已经覆盖这种情况，可不改。
- `56`-`57` 的 `cl 2>&1 | findstr` / `link 2>&1 | findstr` 只作诊断，errorlevel 被后续命令覆盖，无害。
- 没有清理 `obj\`：源码改名后旧的 `.obj` 不会被链接（`cl` 显式列出源文件并把自己生成的 obj 传给 link），只是残留，不构成正确性问题。

---

## 7. 交叉线索（越界项，一句话一条，不展开）

1. `g_chars` / `g_save_dirty` 在游戏线程（`SnapshotModel`）与 Worker 线程（`SaveSort`/`SaveStore`）之间无同步，排序与 `push_back` 并发会损坏 vector（D 方向，`301`、`478`、`938`-`944`）。
2. `InstallOneHook` / `InstallLoadoutHooks` 先 `MH_EnableHook` 再发布 `orig` 指针，窗口内 `HookModelCtor` 会返回 `nullptr`、`HookLoadoutEdit` 会跳过原函数；`InstallHooks` 的主循环里顺序是对的（`679`-`692`、`703`-`711` 对照 `859`-`867`），属重入与生命周期问题（D 方向）。
3. 补丁 1 跳过 `sub_14156E030(slot)`，若该函数含加引用/释放引用，跳过会改变引用计数（D 方向，`733`-`736`）。
4. 补丁 5 在该调用点丢弃 `sub_140450180` 的返回值，若该返回值由 `sub_1404B1920` 新建并持有引用，可能漏一次释放（D 方向，`803`-`808`）。
5. `RestoreModel` 在 SEH 之外解引用 `model+216`（`631`），`HookProfileCtor` 在 SEH 之外写 `self+0x130`（`759`），D 方向可评估是否需要包起来。
6. `Log()` 由两个线程并发调用，`fputs`/`fputc`/`fflush` 三步不是一个原子序列，日志行可能交错（D 方向）。
7. `RawOption raw[1024]`（8 KB）与 `RawEntry entries[1024]`（12 KB）是栈上大对象，分别位于漏斗回调与建模回调的调用深度内（A/D 方向）。
8. `SaveStore` 每 100 ms 可能重排整个 `g_chars` 并全量序列化，属性能问题（A 方向，`938`-`944`）。
9. 头注释说补丁表包含 `#1 #2 #3 #5 #6`，实际表里只有 4 条（#5 在 `InstallInteractionHook` 单独装）；`AllExpectedPresent` 的注释宣称"挂钩前先核对原始字节"，但对补丁 2/3/6 核对的是另一个地址（注释方向，`18`-`20`、`670`）。
10. `kMapBuckets`/`kMapBucketCount` 实际是"偏移"不是"数量/桶"，命名与语义相反（注释与可读性方向，`460`-`461`）。

---

## 8. 未验证清单

1. 补丁 2 的位号是否真的可能取到 8 及以上（当前对局人数上限 8，理论上限 31）。只证到调用点没有 0..7 约束。
2. UI 管理器 `qword_144659DB0` 的实际创建时机，以及"模型先建、管理器后建"在实机是否会发生（q11 §6.4 同样未验证）。C-02 的概率因此无法定量。
3. EA 注册表 `Install Dir` 的真实值名与是否带引号。本机没有对应注册表键，B-01 的结论基于 `reg query` 输出格式复刻，以及脚本自己声明的值名（带空格）。
4. `net session` 在 Server 服务停用时失败、进而导致自提权死循环（B-04），只做了机制推演。
5. `call "%VCVARS%"` 的 errorlevel 在目标机器上是否可能非零（6.11 第一条）。
6. 解密完成到装好钩子之间的实际时间差，以及该窗口内会不会建模（C-11）。

---

## 9. 最严重的 3 条

1. **C-05**：存档只要有一处坏（含 UTF-8 BOM）就整份作废，且下一次改动会用空库覆盖原文件，玩家其余角色的皮肤与 Perk 永久丢失。
2. **C-02**：UI 管理器为空时恢复被整体跳过且没有任何补写机制，模型每槽只建一次意味着这一整局都用默认外观；q11 已把这条路点名成最大风险，代码只做了判空没做兜底。
3. **C-03**：三槽全空时 `n == 0` 直接返回，导致"清空全部配置"这个操作永远落不了盘，下次启动被清掉的外观会自己回来。

一句话结论：七个钩子的挂点、参数、"只在某调用点生效"的判据以及模型偏移全部与逆向结论一致，问题不在挂钩正确性，而在恢复链的兜底和存档的失败路径，外加脚本里两个实测失效的探测步骤。
