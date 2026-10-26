# BFN Base Mod 注释与对外文案审计

日期: 2026-10-26
范围: src/AutoOffline.cpp 全部注释, README.md, helper-scripts 三个 bat 的 REM 与屏幕文案, src/build.bat 的注释与提示。
方法: 通读全部文本; 跑 _audit/check_style.py 取机械基线; 用 BFN_2026_decrypted.exe.i64 核对 RVA、入口字节、函数签名、模型偏移和调用点。没有运行游戏, 没有改动任何源文件。

---

## 0. 结论摘要

机械基线共 43 条。逐条判定后:

- 必须改 21 条: 反引号 8 行, 散文箭头 12 行, 第三人称"用户" 1 行。
- 误报 22 条: 半角括号 19 行, 本地文件名 3 行。理由见第 6 节。
- 内容层面的主要问题集中在大更新没有同步的三处: 文件头部注释, README 的钩子与脚本描述, build.bat 的下一步提示。另外存档 JSON 的说明写了程序不会生成的名字字段, 补丁 4 的调用点数量与 IDA 对不上。

RVA 与偏移的核对结果总体很好: 表内四条和表外三个钩子的入口字节、目标地址、模型偏移都能对上。唯一明显不成立的是"每个玩家槽只建一次", 构造器实际上由 sub_1416AE140 按条目循环调用。

---

## 1. RVA、偏移与签名核对结果

以下均已用 IDA 数据库 BFN_2026_decrypted.exe.i64 复核。

- 0x14156FA30: 入口 48 83 EC 28 E8 F7 E5 FF FF 32 C0 48 83 C4 28 C3, 与注释逐字节一致。函数有一个 __int64 参数, 但函数体不使用, 而是原样传给 sub_14156E030。
- 0x14178A8ED: 0F 92 44 24 21, setb [rsp+21h], 与 expected 一致。它前面的 bt ebx, eax 用的是 0x14178A8BC 那条 call 的返回值; 该 call 的目标正是 0x140447450, 返回地址 0x14178A8C1, 与 SESSMASK_SITE_RVA 一致。同一函数在 0x14178A8C3 还调用 0x140447460, 是另一个函数, 不在补丁范围内。
- 0x1425464EE: C7 86 30 01 00 00 05 00 00 00, 立即数 05 位于 0x1425464F4, 与注释和 expected 一致。构造器入口 0x142546450 正确。
- 0x141D0F6F6: E8 85 5E FF FF, call 目标 0x141D05580, 与 expected 和 hookRva 一致。
- 0x141727CBB: E8 C0 84 D2 FE, call 目标 0x140450180, 返回地址 0x141727CC0, 与代码里的 _ReturnAddress 判断一致。0x140450180 入口 48 89 5C 24 10, 与 want 前 4 字节一致。
- 0x1416B74C0: 入口 44 89 4C 24 20, 与 editWant 一致。签名确为 (管理器, 玩家槽, 角色 id, 选项 key, 新值), 内部调用 0x1416AEB60 找模型。
- 0x1416AEB60: 按模型 +216 的 dword 匹配角色 id, 与注释一致。
- 0x1416AD770: 入口 4C 89 44 24 18, 与 ctorWant 一致。签名 (管理器, 玩家槽, 角色资产, 标记, Perk 描述) 与注释一致; 内部写入 +216, 建三个 56 字节槽位, 逐槽调用 0x1416AF1D0, 最后调用 0x1416ABF60。
- 0x141766580: 六个参数, 写 UI 管理器里的权威表; 全局指针 qword_144659DB0 对应 RVA 0x4659DB0。
- 0x1416AF1D0: 确实先清空缓存再从权威表重灌, 与注释一致。
- 模型 +216 角色 id, +220 当前槽位下标, +280 槽位数组, 每槽 56 字节, 槽位 +8 起哈希表, 表 +8 桶数组, +16 桶数, 节点 +0 键 / +4 值 / +8 下一节点, 全部对得上。
- System32 的 RtWorkQ.dll 在本机 Windows 11 26100.3912 上确有 37 个导出, 与头部注释一致; 其它 Windows 版本数量可能不同。
- sub_14156FA30 的代码调用点共 8 处, 不是 7 处: 0x14175FA91, 0x14177317B, 0x141775E4A, 0x141776037, 0x141776281, 0x1417BCE63, 0x1417CE206, 0x1417CE288。其中 0x141775E4A 就是补丁 4 说的那一处。
- sub_1416AD770 只有一个代码调用点, 在 sub_1416AE140 里; 该函数按条目循环调用构造器, 所以"每个玩家槽只建一次"没有依据。

---

## 2. src/AutoOffline.cpp 清单

### C1 头部把程序说成"只做三件事", 且把补丁 5 算进 g_patches

- 行号: 16-20
- 类型: 过时 + 矛盾 + 准确性
- 原文:
    设计上只做三件事: 等解密 -> 挂钩 -> 结束。
    没有开关文件、没有热键、没有探针、没有内存 dump, 也不改写游戏代码里的任何字节。
    g_patches 表里列的条目全部挂在函数入口(当前为 #1 OfflineFix、#2 会话掩码、
    #3 clientType、#5 interaction kill switch、#6 client inactivity kick;
    #4 已注释停用)。增删条目直接改表, 然后重启游戏。
- 改为:
    //  设计上分三段: 等解密, 挂钩, 然后常驻; 挂钩之后按需读写本地存档。
    //  没有启用开关文件、没有热键、没有探针、没有内存 dump, 也不在磁盘上改写游戏文件
    //  里的任何字节。
    //  g_patches 表里当前有四条, 全部挂在函数入口: #1 OfflineFix、#2 会话掩码、
    //  #3 clientType、#6 client inactivity kick; #4 只留说明, 不安装。
    //  表外还有三个钩子: 补丁 5 的交互解锁由 InstallInteractionHook 安装, 存档的
    //  捕获与恢复由 InstallLoadoutHooks 安装。增删表内条目后重启游戏即可。
    //
    //  存档: 改动漏斗 0x1416B74C0 之后抓一份该角色三个槽位的数据, 攒在内存里定时写入
    //  autooffline_save.json; 模型构造器 0x1416AD770 返回后把这份数据写回 UI 管理器的
    //  权威表, 再重灌缓存并重算活动字段, 让离线时皮肤和 Perk 不再每次重置。
- 依据: g_patches 实际只有四条, 补丁 5 由 InstallInteractionHook 单独安装, 两个存档钩子由 InstallLoadoutHooks 安装; autooffline_p3.txt 是配置文件, 所以"没有开关文件"不成立; 大更新加入了存档读写, 三件事的说法已经过时。改完这条, README 第 144-145 行"完整说明在文件头部"才重新成立。

### C2 补丁 2 只说 setb 的位置, 没有说 hook 判断的是另一条 call 的返回地址

- 行号: 58-60
- 类型: 准确性(可读性)
- 原文:
    这里不改指令, 改成挂读掩码的 getter sub_140447450: 只有在
    sub_14178A650 里那一次调用时把返回值补成"所有位都在", 该属性于是恒为真。
    掩码本身不动, 其它读它的地方(网络事件、会话状态机)拿到的仍是原值。
- 改为:
    //  这里不改指令, 改成挂读掩码的 getter sub_140447450。sub_14178A650 里对它的
    //  调用指令在 0x14178A8BC, 返回地址 0x14178A8C1, 返回值随后在 0x14178A8ED 由
    //  bt/setb 取某一位。只在返回地址等于 0x14178A8C1 时把返回值补成"所有位都在",
    //  该属性于是恒为真。掩码本身不动, 其它读取方拿到的仍是原值; 同一函数里紧跟
    //  着对 sub_140447460 的调用是另一个函数, 不受影响。
- 依据: 表内 rva 是 0x178A8ED, 代码判断的 SESSMASK_SITE_RVA 是 0x178A8C1, 两个地址差 0x2C。不写清楚读者会以为其中一个错了。

### C3 补丁 5 的注释没有说明它不在表里, 也没写调用指令与返回地址的关系

- 行号: 100-104
- 类型: 准确性 + 重复
- 原文:
    ---- 补丁 5: 交互解锁 (挂取 KillSwitch 名字的函数) ----
    交互是否被禁, 判定依据是取到的 KillSwitch 名字是否为空(sub_141727C50 里
    cmp byte[名字], 0 / jz -> 允许)。名字由 sub_140450180 取出。
    这里挂取名字的函数, 只在 0x141727CBB 那一处调用时返回空串对象, 判定自然走
    "名字为空 -> 允许"; 其它调用者拿到的仍是原值。细节见下面 InstallInteractionHook。
- 改为:
    // ---- 补丁 5: 交互解锁 ----
    //  本条不在表里, 由下面的 InstallInteractionHook 安装; 原理见该函数上面的说明。
- 依据: 该条没有 hookRva 表项, 由 InstallInteractionHook 单独装。完整说明放在 786-793 行即可, 这里只留索引, 避免同一件事讲两遍。若想保留完整说明, 则应删除 786-793 的重复段, 二选一。

### C4 补丁 6 的 +36 阈值名称对公开读者不够清楚

- 行号: 107
- 类型: 准确性(措辞)
- 原文:
    PVZServerSettings 的阈值(+36 击杀阈值 / +44 预警阈值 / +64 总开关)。
- 改为:
    //  PVZServerSettings 的阈值(+36 触发击杀的阈值 / +44 预警阈值 / +64 总开关)。
- 依据: 内部笔记把 +36 记作"触发击杀的阈值", 这里的"击杀阈值"容易被读成击杀数。加"触发"两字即可。

### C5 补丁 4 的调用点数量与 IDA 不符, 且示例漏了实参

- 行号: 119, 124, 125
- 类型: 准确性
- 原文:
    if ( sub_14156FA30() || *(DWORD*)(v5 + 88) ) { *(DWORD*)(this + 48) = 2; }
    放行的做法是让那一次 sub_14156FA30 调用返回 0(调用点 0x141775E4A),
    其余 6 个调用点照旧抑制。
- 改为:
    //      if ( sub_14156FA30(a2) || *(DWORD*)(v5 + 88) ) { *(DWORD*)(this + 48) = 2; }
    //  放行的做法是让那一次 sub_14156FA30(a2) 调用返回 0(调用点 0x141775E4A),
    //  其余 7 个调用点照旧抑制: 0x14175FA91, 0x14177317B, 0x141776037,
    //  0x141776281, 0x1417BCE63, 0x1417CE206, 0x1417CE288。
- 依据: 反编译 sub_141775E00 显示条件是 sub_14156FA30(a2); IDA 交叉引用显示 8 个代码调用点, 去掉 0x141775E4A 还剩 7 个。原来写 6 个, 少算了一个。
- 追加问题: 当前 HookOfflineFix 无条件返回 1, 没有按返回地址区分调用点, 所以注释里"只让那一次返回 0"的实现在现有代码中并不存在。补丁 4 停用时没有影响, 但以后要启用, 必须先像补丁 2/5 那样加返回地址判断。建议在 L127 后补一句:
    //  当前 detour 对所有调用点一律返回 1, 没有按返回地址区分; 要启用这一条,
    //  先给 HookOfflineFix 加上 _ReturnAddress() == 0x141775E4F 的判断。
- 依据补充: 0x141775E4A 的 call 占 5 字节, 返回地址是 0x141775E4F。

### C6 补丁 1 的语义块有日期、箭头, 且没有说明本 DLL 也返回 1 会带来同样后果

- 行号: 131, 135, 136, 140, 145 后
- 类型: 过时 + 文风 + 准确性
- 原文:
    补丁 1 的语义 (2026-09-17 逆向得到)
    14156FA34  E8 F7 E5 FF FF   call sub_14156E030      <- 副作用(疑似启动拦截)
    14156FA39  32 C0            xor  al,al              <- 本来就恒返回 false
    注意: 它本来就返回 false。社区补丁改成 `mov al,1; ret`, 在跳过 call 的同时
    强制 true 之后这两条合起来 = 无条件 return 0, 整个函数被废掉。
- 改为:
    //  补丁 1 的语义
    //      14156FA34  E8 F7 E5 FF FF   call sub_14156E030      ; 副作用(疑似导致进图失败)
    //      14156FA39  32 C0            xor  al,al              ; 本来就恒返回 false
    //  注意: 它本来就返回 false。社区补丁改成 mov al,1; ret, 在跳过 call 的同时
    //  强制 true 之后这两条合起来 = 无条件 return 0, 整个函数被废掉。
    //  本 DLL 的 detour 同样整函数返回 1, 所以也会把 sub_1417CE1A0 废掉, 交互入口
    //  因此被禁; 补丁 5 在另一条路径上把交互放开。
- 依据: HookOfflineFix 直接 return 1, 与"社区补丁强制 true 会废掉函数"是同一语义。不在注释里点明, 读者会以为代码与警告矛盾。日期属于调试日记, 建议去掉; 若确实需要溯源, 写"以下语义由反编译核对"即可。

### C7 补丁 1 detour 的注释把未验证的"会崩"写成事实, 并引用没有定义的点号

- 行号: 729-732
- 类型: 准确性 + 可读性
- 原文:
    补丁 1: 原函数会在每次调用时按槽取一次玩家对象(取到再加引用释放), 然后恒返回 0。
    离线态下这次探测会让游戏在进图时崩, 所以一律不执行探测, 一律回答"不可用"。
    逐点放开的实验做过一轮, 结论是: 放开第 1 点会破坏进入流程(加载完弹回主菜单),
    放开第 5 点会闪退, 放开第 2/6/7 点没有可观察的差别。所以维持整体抑制。
- 改为:
    // 补丁 1: 原函数会在每次调用时按槽取一次玩家对象(取到再加引用释放), 然后恒返回 0。
    // 离线态下这次探测疑似会让进图流程失败, 所以一律不执行探测, 一律回答"不可用"(返回 1)。
    // 返回 1 同时会废掉 sub_1417CE1A0, 交互入口因此被禁; 补丁 5 另行放开。
    // 逐点放开的测试结果: 有的点会破坏进入流程(加载完弹回主菜单), 有的点会闪退,
    // 其余点没有可观察的差别, 所以维持整体抑制。
- 依据: 第 1/5/2/6/7 点在全文没有定义, 读者无法对应到任何一个地址; 而且 IDA 显示共有 8 个调用点。要么补一张"点号到地址"的表, 要么像上面这样去掉点号。另, 头部写的是"疑似", 这里写的是"会让游戏崩", 两处应统一。

### C8 补丁 2 的 detour 注释与表内说明重复, define 也没有解释

- 行号: 738-742
- 类型: 重复 + 准确性
- 原文:
    补丁 2: "该槽玩家在会话中" 读的是掩码 dword_14421902C 的对应位。掩码只由网络
    事件置位和清位, 离线时恒为 0。这里挂读掩码的 getter, 只在 sub_14178A650 里那一次
    调用时把返回值补满, 于是那个属性恒为真; 掩码本身不动, 其它读取方拿到的仍是原值。
    #define SESSMASK_GET_RVA 0x447450u
    #define SESSMASK_SITE_RVA 0x178A8C1u
- 改为:
    // 补丁 2: 只在 0x14178A8BC 那一次调用时把掩码补满, 其余读取方拿到的仍是原值。
    // SESSMASK_GET_RVA 是 getter 入口; SESSMASK_SITE_RVA 是调用点的返回地址。
    #define SESSMASK_GET_RVA 0x447450u
    #define SESSMASK_SITE_RVA 0x178A8C1u
- 依据: 原理已经在 52-60 行讲全, 这里重复一遍没有新信息。define 的第二个名字尤其需要一句解释, 否则读者不知道为什么是 C1 而不是 ED。

### C9 补丁 3 的可调值说明与代码的取值范围不一致, 并重复了枚举表

- 行号: 223-232
- 类型: 准确性 + 重复 + 文风(反引号)
- 原文:
    补丁 3 写入的那个值做成可调, 不用重编译就能扫值
    补丁 3 改的是 `Blaze::Authentication::UserProfileInfo+0x130` = `clientType`。
    它是 `Blaze::ClientType` 枚举, 合法值只有 0..5 六个 (含义见上面那张表)。
    默认 = 1 (CLIENT_TYPE_HTTP_USER), 实测唯一能进入游戏的取值。
    游戏目录下放个 `autooffline_p3.txt`, 里面写个 0..5 的十进制数即可。
    文件不存在 = 用 0x01。
- 改为:
    // --------------------------------------------------------------------------
    //  补丁 3 写入的那个值做成可调, 不用重编译就能逐个试值
    //
    //  合法值只有 0..5 (含义见上面那张枚举表), 默认 1, 实测唯一能进入游戏的是 1。
    //  游戏目录下放个 autooffline_p3.txt, 里面写一个十进制数。代码接受 0..255,
    //  但只有 0..5 是合法枚举值, 其它值写进去没有意义。文件不存在 = 用 0x01。
    // --------------------------------------------------------------------------
- 依据: LoadP3Value 的判据是 v < 0 || v > 255, 所以 6..255 会被接受并写进 clientType。注释说"写个 0..5"与代码不一致。枚举表已经在 73-79 行, 这里不必重复类名。

### C10 存档 JSON 的说明与示例写了程序永远不会生成的名字字段

- 行号: 259-279
- 类型: 准确性
- 原文:
    内容按角色分。每个角色有三个配置槽位, 每个槽位是一张 选项 key 到值 的表;
    key 和值都是游戏自己的 u32 哈希, 另外存一份名字, 便于人看, 也便于哈希口径
    变化时对照。JSON 可以直接打开改。写入先落 .tmp 再替换, 中途断电不会留下半个
    文件。

    结构:
        {
          "version": 1,
          "characters": [
            {
              "id": 1234567,           角色 id
              "name": "Soldier",       角色名, 仅用于人读
              "presets": [
                { "options": [ { "key": 285258545, "key_name": "Outfit",
                                 "value": 987654321, "value_name": "Skin_A" } ] },
                { "options": [] },
                { "options": [] }
              ]
            }
          ]
        }
- 改为:
    //  内容按角色分。每个角色有三个配置槽位, 每个槽位是一张 选项 key 到值 的表;
    //  key 和值都是游戏自己的 u32 哈希。name、key_name、value_name 三个字段程序
    //  自己不会填, 只在手改文件时有用: 读进来之后写回时会原样保留, 便于人看, 也
    //  便于哈希口径变化时对照。JSON 可以直接打开改。写入先落 .tmp 再替换, 中途
    //  断电不会留下半个文件。
    //
    //  结构(数值仅为示意):
    //      {
    //        "version": 1,
    //        "characters": [
    //          {
    //            "id": 1234567,
    //            "presets": [
    //              { "options": [ { "key": 285258545, "value": 987654321 } ] },
    //              { "options": [] },
    //              { "options": [] }
    //            ]
    //          }
    //        ]
    //      }
    //  手改时可以给角色加 "name", 给选项加 "key_name" / "value_name", 写回时会保留。
- 依据: SnapshotModel 只填 key 和 value, keyName/valueName 始终为空, 所以 SaveStore 不会写 key_name/value_name; c.name 也从不赋值, 所以不会写 name。SaveLoad 会读这些字段, SaveStore 在非空时会写回, 所以手改的内容能保留。原文把"可选的手改字段"说成了程序行为。

### C11 模型布局的哈希表描述有歧义, 且漏了 +220

- 行号: 444-455
- 类型: 准确性(可读性)
- 原文:
    改动漏斗 sub_1416B74C0(管理器, 玩家槽, 角色id, 选项 key, 新值) 是五件套和 Perk
    共同的写入口, 菜单里每点一次都经过它。挂在这里, 每次写完就把该角色的三个槽位
    整份读出来存进库里, 不需要区分改的是哪个部位。

    模型布局(已核对):
        +216 角色 id      +280 三个 56 字节的槽位
    每个槽位的 +8 是哈希表: +8 桶数组, +16 桶数, +20 元素数;
    节点 16 字节: +0 键, +4 值, +8 下一个。
- 改为:
    //  改动漏斗 sub_1416B74C0(管理器, 玩家槽, 角色id, 选项 key, 新值) 是皮肤部位和
    //  Perk 共同的写入口, 菜单里每点一次都经过它。挂在这里, 每次写完就把该角色的
    //  三个槽位整份读出来存进库里, 不需要区分改的是哪个部位。
    //
    //  模型布局(已核对):
    //      +216 角色 id
    //      +220 当前槽位下标
    //      +280 三个 56 字节的槽位
    //  每个槽位 +8 起是哈希表: 表 +8 桶数组, 表 +16 桶数, 表 +20 元素数;
    //  节点 16 字节: +0 键, +4 值, +8 下一个。桶数和单链长度都按 4096 兜底。
- 依据: 原文"每个槽位的 +8 是哈希表: +8 桶数组"读起来像槽位 +8 有两个含义。实际是槽位 +8 是表头, 表头 +8 是桶数组。+220 是当前槽位下标, 漏斗用它定位写入哪个槽位, IDA 已确认。kMapMaxBuckets 同时用作桶数上限和单链长度上限, 注释没有提。

### C12 恢复段的"每个玩家槽只建一次"不成立, "发布路径唯一写入者"也没有依据

- 行号: 563-575
- 类型: 准确性
- 原文:
    挂模型构造器 sub_1416AD770(管理器, 玩家槽, 角色资产, 标记, Perk 描述) 的返回处。
    选择这个点是因为游戏对模型是硬依赖: 发布路径先按角色 id 找模型, 找不到直接返回,
    而发布是角色组件容器的唯一写入者、组件又是进图装配的唯一数据来源。所以在这里
    写进去, 对该模型的任何读取和任何一次装配都必然更早, 不靠时序巧合, 也不等进图。
    建模本身由模块初始化驱动, 与菜单和对局状态无关, 每个玩家槽只建一次。

    写的是 UI 管理器里的权威表(sub_141766580), 不是模型里的 preset 表: 后者只是
    缓存, 每次 sub_1416AF1D0 都会先清空再从权威表重灌。写完再逐槽位重灌一次缓存,
    最后重算一次活字段(sub_1416ABF60), 让模型立刻反映新数据。
- 改为:
    //  在模型构造器 sub_1416AD770(管理器, 玩家槽, 角色资产, 标记, Perk 描述) 返回之后
    //  写入。构造器负责按角色 id 建出模型和三个槽位, 模型是后续读取和装配的数据来源,
    //  所以在这里写进去, 对该模型的读取必然更晚, 不靠时序巧合, 也不等进图。
    //  建模由 sub_1416AE140 驱动, 它按条目逐个调用构造器; 这里不假设每个玩家槽只建
    //  一次, 每次构造都会按角色 id 匹配一次存档。
    //
    //  写的是 UI 管理器(全局指针 0x4659DB0)里的权威表, 写入函数 sub_141766580; 不是
    //  模型里的 preset 表: 后者只是缓存, 每次 sub_1416AF1D0 都会先清空再从权威表重灌。
    //  写完再逐槽位重灌一次缓存, 最后重算一次活动字段(sub_1416ABF60), 让模型立刻反映
    //  新数据。
- 依据: IDA 显示 sub_1416AD770 只有一个代码调用点, 在 sub_1416AE140 里; 该函数遍历条目并逐个调用构造器, 不是"每个玩家槽只建一次"。"发布是角色组件容器的唯一写入者"没有在本次核对中验证, 建议改成已验证的表述。UI 管理器全局指针就是 qword_144659DB0, 写入函数是 sub_141766580, 原文把两者混成一句。

### C13 挂钩实现段说"原始字节仍写在 g_patches", 但表外三个钩子不在表里

- 行号: 714-720
- 类型: 准确性
- 原文:
    每一条都在函数入口接管: 语义写在代码里, 不会把指令切坏, 也不依赖某一条
    指令的编码。原始字节仍写在 g_patches 的 expected 里, 挂钩前先核对, 避免对着
    还没解密的乱码做指令解码。
- 改为:
    //  每一条都在函数入口接管, 由 MinHook 在入口写跳转并生成跳板; 我们只给目标
    //  地址和 detour, 不手工挑指令。表内四条的原始字节写在 g_patches 的 expected 里,
    //  用来等代码解密; 表外三个钩子各自带 want 字节, 安装前核对, 避免对着还没解密的
    //  乱码挂钩。
- 依据: InstallInteractionHook 用 want[4], InstallLoadoutHooks 用 editWant/ctorWant, 都不在 g_patches。另外 MinHook 仍然要解码被覆盖的入口指令来生成跳板, "不依赖某一条指令的编码"容易读成"不需要解码"。

### C14 两个存档钩子的 want 字节没有说明

- 行号: 695 前
- 类型: 准确性(可读性)
- 改为: 在 static void InstallLoadoutHooks() 前加三行:
    // 两个 want 数组是入口前 5 字节, 只用来确认代码已解密、函数没认错:
    // editWant 是 mov [rsp+20h], r9d, ctorWant 是 mov [rsp+18h], r8。
    // 这两个钩子不参与上面的解密等待, 安装时字节不对就记日志并跳过。
- 依据: 44 89 4C 24 20 是 mov [rsp+20h], r9d; 4C 89 44 24 18 是 mov [rsp+18h], r8。这两个钩子在 InstallHooks 末尾安装, 不在 AllExpectedPresent 的等待集合里。

### C15 交互解锁实现段的地址说法要区分调用指令与返回地址

- 行号: 789-793
- 类型: 准确性 + 文风(箭头)
- 原文:
    sub_141727C50 判断交互是否被禁用, 依据是取到的 KillSwitch 名字是否为空:
        mov rcx,[rax] / cmp byte[rcx],0 / jz -> 允许
    名字由 sub_140450180 取出。这里挂取名字的函数, 只在被 0x141727CBB 那一处
    调用时换成一个空串对象, 于是判定自然走"名字为空 -> 允许"。
    不去改写那条 jz 指令, 其它调用者拿到的仍是原值。
- 改为:
    //  sub_141727C50 判断交互是否被禁用, 依据是取到的 KillSwitch 名字是否为空:
    //      mov rcx,[rax] / cmp byte[rcx],0 / jz 跳转即允许
    //  名字由 sub_140450180 取出。这里挂取名字的函数, 只在调用指令 0x141727CBB
    //  (返回地址 0x141727CC0)那一次调用时换成一个空串对象, 于是判定自然走
    //  "名字为空即允许"。不去改写那条 jz 指令, 其它调用者拿到的仍是原值。
- 依据: 0x141727CBB 是 call 指令地址, 返回地址是 0x141727CC0; 代码比较的是后者。原文只写 0x141727CBB, 读者容易把两者混为一谈。

### C16 可选: 两个常量没有一句话说明

- 行号: 465, 580
- 类型: 可读性(低优先级)
- 改为:
    constexpr unsigned int kModelLookupRva = 0x16AEB60u;  // (管理器, 槽, 角色 id) 取模型
    constexpr unsigned int kUiManagerRva = 0x4659DB0u;    // UI 管理器全局指针
- 依据: 这两个 RVA 在正文里出现过, 但定义处没有注释; 加上后查表更快。

### C17 文风: 反引号 8 行

- 行号: 64, 70, 73, 98, 140, 226, 227, 230
- 逐行改为:
    L64:  //  位置: UserProfileInfo 的构造函数 sub_142546450 内
    L70:  //  UserProfileInfo 的第 12 个字段名为 "clientType", 类型 Blaze::ClientType,
    L73:  //  Blaze::ClientType 枚举 (类型描述符 @0x1447AD4F0, 成员表 @0x1447AD420):
    L98:  //  取值由游戏目录下的 autooffline_p3.txt 决定, 默认 1。
    L140: //  注意: 它本来就返回 false。社区补丁改成 mov al,1; ret, 在跳过 call 的同时
    L226: //  补丁 3 改的是 Blaze::Authentication::UserProfileInfo+0x130 = clientType。
    L227: //  它是 Blaze::ClientType 枚举, 合法值只有 0..5 六个 (含义见上面那张表)。
    L230: 见 C9, 整段替换。
- 依据: check_style.py 的 BANNED_CHARS 包含反引号。README 里的反引号是 Markdown 语法, 不在本条范围。

### C18 文风: 散文箭头 12 行

- 行号: 16, 69, 102, 104, 116, 135, 136, 239, 244, 790, 792, 889
- 其中 16/102/104/135/136/790/792 已由 C1/C3/C6/C15 覆盖, 其余逐行改为:
    L69:  //  该字段的身份来自类型描述符 (sub_14254A3A0 指向的 off_1447CD8F0 字段表):
    L116: //      经 sub_1415C92A0 转到 sub_1424A8E50 (Blaze 连接对象, 载荷 112 字节)
    L239:     Log("patch3 value: no %s, using 0x%02X", path.c_str(), g_p3_value);
    L244:     Log("patch3 value: bad content in %s, using 0x%02X", path.c_str(), g_p3_value);
    L889: //  等代码解密, 挂钩, 然后常驻
- 依据: check_style.py 把带空格的 -> 和注释里的 <- 都算散文箭头。239/244 是日志字符串, 改逗号后仍是英文输出, 格式符不变。

### C19 文风: 第三人称"用户"

- 行号: 936
- 类型: 文风
- 原文:
    // 捕获到的改动攒一会儿再落盘, 免得用户每点一次都写文件。间隔要短, 玩家改完
- 改为:
    // 捕获到的改动攒一会儿再落盘, 免得每点一次都写文件。间隔要短, 玩家改完
- 依据: 注释是开发者自己的说明, 不写"用户"; 后半句已经有"玩家", 不会歧义。

### C20 可选: 头部导出数量加版本限定, 以及多余空行

- 行号: 9-10, 877-879
- 类型: 准确性(低优先级) + 文风
- 9-10 改为:
    //        (系统那份 RtWorkQ.dll 位于 System32, Windows 11 26100 上有 37 个导出,
    //         其它 Windows 版本数量可能不同; 本 DLL 一个都不导出。游戏实测不调用
    //         RtWorkQ 的任何函数, 所以没有影响。)
- 877-879 三个空行收成一个。
- 依据: 本机 Windows 11 26100.3912 实测 37 个导出, 但这是版本相关的数字。三条空行是 InstallHooks 与 DirOfSelf 之间的排版残留。

---

## 3. README.md 清单

### R1 "两个 bat" 和"2 号脚本只是撤销"已经过时, 且漏掉 3 号脚本和 CryptBase.dll

- 行号: 32-39
- 类型: 过时 + 准确性
- 原文:
    **2. The two `.bat` files rename and copy files inside the game folder.**

    `1-disable-eaac.bat` renames `EAAntiCheat.GameServiceLauncher.exe` to
    `.exe.bak` and copies `RtWorkQ.dll` into the game folder.
    `2-enable-eaac.bat` undoes exactly that.

    Both are plain text. **Open them in Notepad and read every line.** They contain
    no obfuscation, no downloads, no encoded blobs.
- 改为:
    **2. The three `.bat` files rename, copy and delete files inside the game folder.**

    `1-disable-eaac.bat` renames `EAAntiCheat.GameServiceLauncher.exe` to
    `.exe.bak` and copies `RtWorkQ.dll` into the game folder.
    `2-enable-eaac.bat` renames it back, removes `RtWorkQ.dll` (a foreign copy is
    moved to `stale\` instead), and removes a `CryptBase.dll` left behind by Frosty
    Mod Manager.
    `3-clear-save.bat` deletes `autooffline_save.json` after asking for
    confirmation.

    All three are plain text. **Open them in Notepad and read every line.** They
    contain no obfuscation, no downloads, no encoded blobs.
- 依据: helper-scripts 现在有三个脚本; 2 号脚本除了恢复 EAAC 和删 RtWorkQ.dll, 还删 CryptBase.dll, 并把外来 DLL 移到 stale, 所以"undoes exactly that"不准确。仓库存在的目的就是让审查者看懂每个文件做什么, 这一节尤其不能少写。

### R2 写的文件数量与临时文件、可选配置没写全

- 行号: 46-48
- 类型: 准确性
- 原文:
    - It does **not** modify any file belonging to the game. It writes two files next
      to itself: `autooffline_log.txt`, and `autooffline_save.json` (your saved
      skins and perks).
- 改为:
    - It does **not** modify any file belonging to the game. It writes
      `autooffline_log.txt`, `autooffline_save.json` (your saved skins and perks),
      and a temporary `autooffline_save.json.tmp` during each save, all next to
      itself. It reads `autooffline_p3.txt` if you create one.
- 依据: SaveStore 先写 .tmp 再替换; LoadP3Value 会读 autooffline_p3.txt。写"两个文件"会让审查者以为没有别的落盘动作。

### R3 "不改写任何游戏指令"与同页"入口跳转加跳板"自相矛盾

- 行号: 49-51
- 类型: 矛盾
- 原文:
    - It does **not** rewrite the body of any game function. It installs a small
      number of entry hooks, listed below - each one is a jump at the function's
      first bytes plus a trampoline, and it is gone when the game exits.
- 改为:
    - It does **not** edit the game files on disk. It installs seven entry hooks in
      memory, described below. Each hook is a jump at the function's first bytes
      plus a trampoline built by MinHook, and it is gone when the game exits.
- 依据: 入口跳转本身就是改写函数头几个字节; 说"不改写函数体"可以, 但原文紧接着的"first bytes 跳转"会让读者觉得前后不一致。改成"不改磁盘文件, 只在内存里装钩子"最准确。

### R4 脚本表里 2 号脚本的描述不完整

- 行号: 63-65
- 类型: 准确性
- 原文:
    | `helper-scripts/2-enable-eaac.bat` | Undoes that. |
- 改为:
    | `helper-scripts/2-enable-eaac.bat` | Re-enables EAAC, removes the mod, and removes a Frosty `CryptBase.dll` leftover. |
- 依据: 同 R1。

### R5 钩子一节的数量、是否调用原函数、是否改写指令三处都不准确

- 行号: 157-163
- 类型: 准确性 + 矛盾
- 原文:
    **3. The hooks.** A small table in the source (`g_patches`) lists each entry as
    *verification address + expected original bytes + the function to hook*. The
    expected bytes are what proves the code has decrypted. Every hook calls the
    original first and then changes exactly one behaviour - no game instruction is
    rewritten, so there is nothing to get wrong about instruction encoding. Each
    entry is documented in-line with what the original function does and why it is
    being intercepted.
- 改为:
    **3. The hooks.** Seven hooks are installed in total. Four are listed in the
    `g_patches` table as *verification address + expected original bytes + the
    function to hook*; the other three (the interaction unlock and the two save
    hooks) live in their own install functions and carry their own expected bytes.
    The expected bytes are what proves the code has decrypted. Most hooks call the
    original first and then change one behaviour; the OfflineFix hook deliberately
    does not call the original, because the original probe is what has to be
    skipped. MinHook writes a jump at each function's first bytes and relocates the
    covered instructions into a trampoline; we never edit a game instruction by
    hand. Each hook is documented in-line with what the original function does and
    why it is intercepted.
- 依据: 4 条表内钩子加交互解锁 1 条、存档 2 条, 共 7 条; HookOfflineFix 直接返回 1, 不调用原函数; MinHook 仍要解码被覆盖的指令, "nothing to get wrong about instruction encoding"是过度承诺。这一段是审查者最可能逐条对照的地方。

### R6 存档一节的字段说明与程序实际写出的内容不一致

- 行号: 169-175
- 类型: 准确性
- 原文:
    **5. Your skins and perks are saved locally.** Offline the server never sends
    them back, so they used to reset on every launch. The DLL now records what you
    equip - per character, for each of the three loadout slots - as soon as you
    change it in the menus, and writes it back when the game builds that character's
    config model, which happens before anything can read it. The file is
    `autooffline_save.json` next to `RtWorkQ.dll`: plain JSON, one entry per
    option, editable by hand. `3-clear-save.bat` deletes it.
- 改为:
    **5. Your skins and perks are saved locally.** Offline the server never sends
    them back, so they used to reset on every launch. The DLL now records what you
    equip - per character, for each of the three loadout slots - as soon as you
    change it in the menus, and writes it back when the game builds that character's
    config model, which happens before anything can read it. The file is
    `autooffline_save.json` next to `RtWorkQ.dll`: plain JSON, one entry per
    option, editable by hand. The per-character and per-option fields the program
    writes are `id`, `presets`, `key` and `value`; `name`, `key_name` and
    `value_name` are kept if you add them by hand. `3-clear-save.bat` deletes it.
- 依据: 同 C10。

### R7 "没有东西会被静默删除"一节漏了 CryptBase.dll

- 行号: 187-191
- 类型: 准确性
- 原文:
    - **Nothing is deleted without saying so.** A foreign `RtWorkQ.dll` is moved to a
      `stale\` folder instead of being overwritten; `2-enable-eaac.bat` only removes a
      `RtWorkQ.dll` that is byte-identical to the one shipped here. The one
      exception is `3-clear-save.bat`: it deletes `autooffline_save.json`
      (and asks for a confirmation first), because that is the whole point of it.
- 改为:
    - **Nothing is deleted without saying so.** A foreign `RtWorkQ.dll` is moved to a
      `stale\` folder instead of being overwritten; `2-enable-eaac.bat` only removes a
      `RtWorkQ.dll` that is byte-identical to the one shipped here. It also removes
      `CryptBase.dll`, the file Frosty Mod Manager adds before launching the game,
      and prints a line about it before doing so. `3-clear-save.bat` deletes
      `autooffline_save.json` (and asks for a confirmation first), because that is
      the whole point of it.
- 依据: 2-enable-eaac.bat 的 Step 3 会无条件删 CryptBase.dll, 只在删除前打印说明。README 既然把"没有静默删除"当作卖点, 就应该把这条列出来。

### R8 "完整说明在文件头部"依赖 C1

- 行号: 144-145
- 类型: 准确性(依赖项)
- 原文:
    The full explanation is in the comment block at the top of
    `src/AutoOffline.cpp`. In short:
- 改为: 不用改, 但必须先做 C1。做完 C1 后头部才包含存档和表外钩子的说明; 如果不做 C1, 把这里改成 "in the comment blocks in `src/AutoOffline.cpp`"。
- 依据: 当前头部只讲等解密和挂钩, 没有存档, 也没有表外钩子。

### R9 可选: 记录的工具链版本与本机不一致

- 行号: 129-131
- 类型: 准确性(低优先级)
- 说明: README 写 "Incremental Linker Version 14.51.36248.0", 本机 dumpbin 是 14.51.36257.0。如果发布二进制确实由 36248 构建, 保持原样; 否则更新成实际版本。因为 build.bat 会打印版本, 读者可以自行核对, 这条不影响理解。
- 依据: dumpbin 实测版本 14.51.36257.0。

---

## 4. helper-scripts 清单

### S1 1-disable-eaac.bat 头部的箭头

- 行号: 7
- 类型: 文风
- 原文:
    REM    2. Renames EAAntiCheat.GameServiceLauncher.exe -> .exe.bak  (EAAC off)
- 改为:
    REM    2. Renames EAAntiCheat.GameServiceLauncher.exe to .exe.bak  (EAAC off)
- 依据: 注释里不用箭头。

### S2 1-disable-eaac.bat 说 2 号脚本"撤销一切", 与 2 号脚本的实际行为不符

- 行号: 10
- 类型: 准确性
- 原文:
    REM  Run 2-enable-eaac.bat to undo everything.
- 改为:
    REM  Run 2-enable-eaac.bat to turn EAAC back on and remove RtWorkQ.dll.
    REM  It keeps autooffline_save.json; 3-clear-save.bat deletes that file.
- 依据: 2 号脚本保留存档, 还会删 CryptBase.dll; "撤销一切"既不准确, 也没告诉新玩家存档的存在。

### S3 1-disable-eaac.bat 结尾的"To undo"可以顺手补上存档说明

- 行号: 165-166
- 类型: 准确性
- 原文:
    echo   To undo: run 2-enable-eaac.bat
- 改为:
    echo   To undo: run 2-enable-eaac.bat. Your saved skins and perks stay in
    echo   autooffline_save.json; 3-clear-save.bat deletes that file.
- 依据: 同 S2。新玩家装完 mod 后最常问的就是存档在哪、怎么删。

### S4 1-disable-eaac.bat 的子程序注释箭头

- 行号: 195, 261, 268
- 类型: 文风
- 原文:
    REM ---- :detect [dragAndDropPath] -> sets G --------------------------------
    REM ---- :try <folder> -> sets G when the game EXE is inside -----------------
    REM ---- :cmp <a> <b> -> sets MATCH=1 when byte-identical --------------------
- 改为:
    REM ---- :detect [dragAndDropPath] sets G ------------------------------------
    REM ---- :try <folder> sets G when the game EXE is inside --------------------
    REM ---- :cmp <a> <b> sets MATCH=1 when byte-identical -----------------------
- 依据: 注释里不用箭头。

### S5 1-disable-eaac.bat 说"每个盘符", 实际只扫 C 到 I

- 行号: 243
- 类型: 准确性
- 原文:
    REM 4) common locations on every drive letter
- 改为:
    REM 4) common locations on drives C through I
- 依据: 循环是 for %%D in (C D E F G H I)。三个脚本同一处都要改。

### S6 2-enable-eaac.bat 头部的箭头

- 行号: 7
- 类型: 文风
- 原文:
    REM    2. Renames EAAntiCheat.GameServiceLauncher.exe.bak -> .exe  (EAAC back on)
- 改为:
    REM    2. Renames EAAntiCheat.GameServiceLauncher.exe.bak back to .exe  (EAAC back on)
- 依据: 注释里不用箭头。

### S7 2-enable-eaac.bat 的失败标记与 1/3 号脚本不一致

- 行号: 100, 107, 130, 142, 153, 172
- 类型: 文风(一致性)
- 说明: 1 号和 3 号脚本用 [X] 表示失败并退出, 2 号脚本所有错误都用 [!]。建议统一为: [X] 用于会退出或中止的失败, [!] 只用于警告后继续。
- 逐行改为:
    L100: echo [X] Neither the EAAC launcher nor its .bak exists.
    L107: echo [X] Rename FAILED. Close the game and the EA app, then retry.
    L130: echo [X] Could not move it aside. Close the game and retry.
    L142: echo [X] Could not delete RtWorkQ.dll. Close the game and retry.
    L153: echo [X] Could not move it aside. Close the game and retry.
    L172: echo [X] Could not delete CryptBase.dll. Close the game and retry.
- 保持 [!] 的行: 94, 124, 148。这三处是警告后继续, 不是中止。
- 依据: 三个脚本是同一套工具, 标记语义应该一致; 现在 2 号的 [!] 同时表示"警告"和"中止"。

### S8 2-enable-eaac.bat 的子程序注释箭头和"每个盘符"

- 行号: 221, 269, 287, 294
- 类型: 文风 + 准确性
- 改为:
    L221: REM ---- :detect [dragAndDropPath] sets G ------------------------------------
    L269: REM 4) common locations on drives C through I
    L287: REM ---- :try <folder> sets G when the game EXE is inside --------------------
    L294: REM ---- :cmp <a> <b> sets MATCH=1 when byte-identical -----------------------
- 依据: 同 S4、S5。

### S9 可选: 2-enable-eaac.bat 找不到游戏时没有 EA app 的路径提示

- 行号: 61-70
- 类型: 一致性(低优先级)
- 说明: 1 号和 3 号脚本在同样的错误分支里都有 "In the EA app: click the game ..." 三行, 2 号没有。补上可以省一次求助。不是错误, 只是不一致。
- 建议: 在 L68 的 pause 前加:
    echo     In the EA app: click the game - Manage - View Properties -
    echo     Install Location - Open Folder.

### S10 可选: 2-enable-eaac.bat 对 CryptBase.dll 的描述可以更准确

- 行号: 177
- 类型: 措辞(低优先级)
- 原文:
    echo     (Frosty Mod Manager re-adds it the next time it launches the game.)
- 说明: 这句是对的, 保留即可; 如果想和头部一致, 可以把 "re-adds" 改成 "puts it back"。

### S11 3-clear-save.bat 的"五个皮肤部位"建议加 for example

- 行号: 9-12
- 类型: 准确性(低优先级)
- 原文:
    REM  The mod keeps a local copy of what you have equipped - the five skin
    REM  parts (main set, hat, glasses, shoes, mouth) and the perks - for each of
    REM  the three loadout slots, and puts them back on every launch. That copy
    REM  lives in autooffline_save.json next to RtWorkQ.dll.
- 改为:
    REM  The mod keeps a local copy of what you have equipped - the skin options
    REM  (for example main set, hat, glasses, shoes, mouth) and the perks - for
    REM  each of the three loadout slots, and puts them back on every launch. That
    REM  copy lives in autooffline_save.json next to RtWorkQ.dll.
- 依据: 代码只存任意 key/value, 不强制"五个"这个数量; 对公开文案来说, "for example"既保留可读性, 又不会在游戏新增部位时过时。

### S12 3-clear-save.bat 说"别的都不动", 但成功路径还会删 .tmp

- 行号: 17-18
- 类型: 准确性
- 原文:
    REM  Nothing else is touched: the mod, the game files and the log stay as they
    REM  are. Run 1-disable-eaac.bat to remove the mod itself.
- 改为:
    REM  Nothing else is touched: the mod, the game files and the log stay as they
    REM  are. A leftover autooffline_save.json.tmp is deleted after the save file.
    REM  Run 1-disable-eaac.bat to remove the mod itself.
- 依据: L117 在成功删除 .json 后会删 .tmp。只有 .tmp 存在时脚本会走"没有存档"分支, 这是另一个边界, 但文案至少要把成功路径的 .tmp 说清楚。

### S13 3-clear-save.bat 的子程序注释箭头和"每个盘符"

- 行号: 153, 201, 219
- 类型: 文风 + 准确性
- 改为:
    L153: REM ---- :detect [dragAndDropPath] sets G ------------------------------------
    L201: REM 4) common locations on drives C through I
    L219: REM ---- :try <folder> sets G when the game EXE is inside --------------------
- 依据: 同 S4、S5。

### S14 已确认干净: 旧文件名没有残留

- 说明: 全库 grep 没有发现 autooffline_loadout.json、3-clear-loadout-db.bat、database、db 这些旧名字; 三个脚本和 README 都已经用 autooffline_save.json 和 3-clear-save.bat。这一项不需要改, 只是记录核对结果。

---

## 5. src/build.bat 清单

### B1 构建完成后提示去跑 1 号脚本, 但脚本找不到刚构建的 DLL

- 行号: 82-83
- 类型: 准确性(会直接导致下一步失败)
- 原文:
    echo To use it: rename it to RtWorkQ.dll and put it in the game folder -
    echo or simply run helper-scripts\1-disable-eaac.bat, which does that for you.
- 改为:
    echo To use it: copy AutoOffline.dll into helper-scripts as RtWorkQ.dll and run
    echo helper-scripts\1-disable-eaac.bat, or rename it to RtWorkQ.dll and put it in
    echo the game folder yourself.
- 依据: 1-disable-eaac.bat 的 SRC 是 %~dp0RtWorkQ.dll, 也就是 helper-scripts\RtWorkQ.dll。build.bat 的产物在 src\AutoOffline.dll, 直接运行 1 号脚本会报 "RtWorkQ.dll is missing"。这是目前最容易踩到的一条。

### B2 build.bat 的 REM 里有反引号

- 行号: 88
- 类型: 文风
- 原文:
    REM  The result is read back from a file rather than with a `for /f` backtick
- 改为:
    REM  The result is read back from a file rather than with a for /f command that
- 依据: 注释里不用反引号。下一行 "command: cmd's quote handling..." 正好接得上。

### B3 build.bat 的失败提示还在讲"注入"

- 行号: 103-105
- 类型: 过时
- 原文:
    echo     If it says LNK1104 "cannot open AutoOffline.dll", the DLL is currently LOADED
    echo     in a process -- i.e. you already injected it. Close the game and rebuild.
    echo     NOTE: the game merely RUNNING does NOT lock the file. Only injection does.
- 改为:
    echo     If it says LNK1104 "cannot open AutoOffline.dll", the file is open in
    echo     another process: a debugger, or a game that loaded this copy as RtWorkQ.dll.
    echo     Close it and rebuild.
    echo     NOTE: the game merely RUNNING does not lock src\AutoOffline.dll unless
    echo     that copy is the one deployed as RtWorkQ.dll.
- 依据: 现在的部署方式没有注入器, 游戏是直接按裸名加载 RtWorkQ.dll。继续写"you already injected it"会让读者以为还有一个不存在的注入步骤; "Only injection does"也不对, 游戏加载部署后的副本同样会锁文件。

### B4 可选: /Brepro 的说明略微绝对

- 行号: 60-61
- 类型: 措辞(低优先级)
- 原文:
    REM /Brepro = reproducible build. Without it the linker stamps the build time
    REM into the binary, so no two builds of the same source would ever match.
- 说明: 更准确的说法是 "builds made at different times would differ"; 同一秒内的两次构建仍可能相同。不影响理解, 可不改。

### B5 可选: 一处英文语法

- 行号: 63
- 原文:
    REM Only the four files x64 needs; hde32.c is 32-bit only.
- 改为:
    REM Only the four files x64 needs; hde32.c is 32-bit only.
- 说明: 原句可以读通, 只是 "the four files x64 needs" 少一个 that; 不是错误, 不必动。

---

## 6. 文风与标点机械清单

check_style.py 输出 43 条, FAIL。逐条判定如下。

### 6.1 必须改: 反引号 8 行

行号: 64, 70, 73, 98, 140, 226, 227, 230。

替换文本见 C17; 其中 L230 连同取值范围一起在 C9 整段替换。这些行都在中文注释里, 反引号是纯装饰, 去掉即可; 需要引号的地方用文件里已经在用的 ASCII 双引号。

### 6.2 必须改: 散文箭头 12 行

行号: 16, 69, 102, 104, 116, 135, 136, 239, 244, 790, 792, 889。

替换文本见 C1, C3, C6, C15, C18。其中 L239 和 L244 是日志字符串, 把 " -> " 改成逗号, 英文输出和格式符都不变。L135 和 L136 是注释里的 "<-", 改成 ";".

### 6.3 必须改: 第三人称"用户" 1 行

行号: 936。替换见 C19。

### 6.4 误报: 本地文件名 3 行

行号: 98, 230, 256。

这三行分别是 autooffline_p3.txt 和 autooffline_save.json, 都是本程序自己的输入输出文件, 不是作者机器上的审计草稿。check_style.py 的 local_ref 规则本来就是为了抓 _audit、绝对路径、日志、脚本这类只在开发机上存在的东西; 产品文件名应当像 summonai_log.txt 一样豁免。不要改这三行的文件名。

### 6.5 误报: 半角括号 19 行

行号: 2, 12, 14, 18, 37, 39, 55, 60, 101, 107, 135, 159, 181, 192, 451, 572, 574, 729, 731。

判定理由: 这个文件从第一次提交起就通篇使用 ASCII 标点。实测当前文件全角括号 0 个、全角逗号 0 个、ASCII 括号 511 个、ASCII 逗号 439 个、ASCII 双引号 242 个; 历史提交 91809b0、d820cf3、01e2f86 也都是 0 个全角括号。check_style.py 那条规则的注释说 "Chinese prose in this file always uses full-width brackets", 与事实不符, 应是从另一个工程带过来的规则。只把 19 行改成全角会造成同一文件里两种括号混用, 比不改更糟。

建议二选一:

- 推荐: 在本仓库豁免这条规则, 或把规则改成"同一文件内保持一致"。这样本报告里所有替换文本继续用 ASCII 标点, 与现有风格一致。
- 如果确实要全角: 应做一次全文件转换, 覆盖 511 个括号、439 个逗号、242 个引号, 而不是只改这 19 行。这是一次独立的排版改动, 不属于本次注释审计。

### 6.6 其他检查项

- Markdown 粗体: 0 条。
- 无用前向声明: 0 条。
- 全角冒号: 0 条。
- 重复标点: 0 条。
- README 的 **粗体**、反引号代码段、以及标题里的警告符号: 这些是 Markdown 语法, 不是源码注释, 不应按注释规则删。若确实要求整仓无 emoji, 只需处理 README 第 12 行的警告符号, 属于外观选择, 不是缺陷。

---

## 7. 重复与合并建议

同一件事讲多次的地方集中在补丁说明。建议按下面收口, 表格里是当前重复位置和建议保留的一处。

| 主题 | 现在出现的位置 | 建议 |
|---|---|---|
| 补丁 1 语义 | 18 行, 131-146 行, 729-732 行 | 131-146 保留完整语义和副作用; 729-732 压成"为什么整体抑制"三行; 18 行只留一行索引 |
| 补丁 2 原理 | 18-19 行, 52-60 行, 738-742 行 | 52-60 保留完整原理; 738-742 按 C8 压成两行; 18-19 只留索引 |
| 补丁 3 枚举 | 18-19 行, 62-98 行, 223-232 行, 755 行 | 62-98 保留枚举表和实测; 223-232 按 C9 只讲可调文件和取值范围; 755 已是一行 |
| 补丁 5 原理 | 18-19 行, 100-104 行, 786-793 行 | 786-793 保留完整原理; 100-104 按 C3 压成索引; 18-19 只留索引 |
| 补丁 6 原理 | 18-19 行, 105-111 行, 763 行 | 105-111 保留; 763 已是一行 |
| 存档三阶段 | 252-280 行, 444-455 行, 563-575 行 | 三段分别讲格式、捕获、恢复, 不是重复, 保留; 但要保证 C10、C12 与 README R6 三处说法一致 |
| 三个脚本的子程序 | 每个脚本都有一份 :detect / :try / :cmp / :assertGameClosed 和同样的 REM | 脚本要能单独拷走, 重复是设计代价; 抽公共 bat 属于代码改动, 不在本次范围。若以后抽, 注释只留一份 |

另外, 头部注释与下面各补丁块的关系应是"地图与详情": 头部只列编号、一句话作用和表内/表外归属, 不再重复原函数行为。按 C1 改完即符合这个分工。

---

## 8. 交叉线索

以下不属于本次注释方向, 只留一句, 交给对应方向。

- HookOfflineFix 的 slot 参数声明为 unsigned int, IDA 显示原函数 arg0 是 __int64; 该参数未被使用, 目前无行为影响, 但签名与原函数不一致。
- WriteAuthFn 第 5 个参数声明为 unsigned int, IDA 里该形参是 char 且取了地址; 动这个 typedef 前先核 ABI。
- 补丁 5 与两个存档钩子不在 AllExpectedPresent 的等待集合里, 只靠安装时的 want 核对; 如果解密分阶段, 它们可能比表内四条更早失败。
- RestoreModel 在 631 行直接读 model+216, 不在 __try 里; 模型指针有效性由调用点保证。
- RawReadModel 的桶数上限和单链长度上限共用 kMapMaxBuckets=4096, 超限会静默截断, 注释未提。
- 落盘循环 Sleep(100), 改完 100ms 内崩溃或退出会丢最后一次改动; 注释说"不能丢", 实际有这个窗口。
- build.bat 的 LNK1104 提示与部署方式有关: 若把 src 的 DLL 直接当 RtWorkQ.dll 放进游戏目录, 游戏运行时就会锁住它。
- README 记录的 linker 14.51.36248.0 与本机 dumpbin 14.51.36257.0 不同, 核对发布二进制到底由哪版构建。
- 3-clear-save.bat 只在成功删除 .json 后才删 .tmp; 只有 .tmp 存在时会走"没有存档"分支。
- 旧的 autooffline_loadout.json 和 3-clear-loadout-db.bat 名字已无残留, 全库 grep 干净。

---

## 9. 最该改的 3 条

1. C1, 文件头部 16-20 行。README 明确把这段当作"完整说明", 但它还写着"只做三件事"和"没有开关文件", 并把补丁 5 算进 g_patches, 完全没提存档和表外三个钩子。这是审查者读到的第一段, 必须先改。
2. R1 和 R5, README 32-39 行与 157-163 行。公开页面说"两个 bat"、说 2 号脚本"撤销一切"、说每个钩子都先调原函数、说没有改写任何指令, 这四点都与现状不符。仓库存在的意义就是让审查者对照, 这四句最容易被逐条挑出来。
3. B1, build.bat 82-83 行。构建完成后提示直接运行 1-disable-eaac.bat, 但脚本只找 helper-scripts\RtWorkQ.dll, 刚构建的 DLL 在 src\, 照着做必然报 "RtWorkQ.dll is missing"。这是一条会直接卡住构建者的错误指引。

紧随其后的是 C10 和 R6: 存档格式说明写了程序不会生成的 name、key_name、value_name, 玩家打开 JSON 会发现字段不存在。另外 C5 的调用点数量(6 对 7)和 C12 的"每个玩家槽只建一次"也都是硬伤, 建议同批修掉。

一句话结论: 这份代码的 RVA、偏移和入口字节经得起逐条核对, 注释的整体质量高于一般逆向项目; 真正的问题是刚完成的大更新只在代码里落地, 头部注释、README 和 build.bat 还停在上一版, 按上面 C1、R1/R5、B1、C10 的顺序改一轮即可收敛。

