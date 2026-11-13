# 胜利牌 / 左右拳套（Tombstone）的写入与本地持久化路径

- 日期：2026-11-13
- 对象：BFN 2026 解密镜像 `BFN_2026_decrypted.exe`（imagebase `0x140000000`）
- IDA 会话：`d447ab2e`（只读，未改库、未 patch、未改名）
- 证据分级：【已证】有反编译或字节直证；【推测】有线索未闭环；【未验证】静态推不出来，必须实机
- 文中地址一律给绝对地址与 RVA（RVA = 绝对地址 - 0x140000000）

---

## 0. 结论速览

1. 【已证】**胜利牌 / 左拳套 / 右拳套是三个 16 字节的 Frostbite Guid**，不是配置表里的 key/value。三者顺序固定为
   `head`（胜利牌）、`left`（左拳套）、`right`（右拳套）。

2. 【已证】**它们写在 UI 管理器 `qword_144659DB0` 的 per-slot 记录里**：
   `entry = *(void**)(manager + 32) + 184 * slot`，三个 Guid 在 `entry + 88 / +104 / +120`。
   写入口是 `sub_1417669A0`（RVA `0x17669A0`），不是 `sub_141766580`。
   `sub_141766580` 只负责角色皮肤/Perk 的 (slot, charId, preset, key, value) 哈希表；两者相距 0x300 字节，
   但完全不是一张表。**这就是现有 hook 在改胜利牌时既没有 `write:` 也没有 `edit:` 的直接原因。**

3. 【已证】**提交（事件 id `0x5AFEBB1D`）时走三条路**：
   - 本地 UI 管理器写入（`sub_1417669A0`）；
   - HTTP POST `application/json` 上传到 EA 后端（`sub_141766140`，经 `sub_141EC1AC0`）；
   - 发一条网络消息（`sub_142DA2520`，字段就是三个 Guid）+ 同时压一个本地事件
     （`sub_142D13160` + `sub_140470400`）。

4. 【已证】**本地事件会把三个 Guid 序列化成 JSON 字符串，以属性 key `tombstone` 广播给玩家实体**
   （`sub_1415E8910` 的 `0xC1E5086B` 分支 → `sub_1415ED1F0`）。这条是游戏自己的“本地应用”路径，
   离线也会走完（发送失败不影响本地事件）。

5. 【已证】**客户端本地没有任何落盘缓存**。跨会话恢复靠两条外部数据：HTTP 下载（`sub_14175A510`）
   或服务器把玩家属性发回来。离线时两者都不存在，UI 管理器这一格每次启动都是空的，
   所以自定义界面回落到目录默认项（`sub_14179CC10` / `sub_141797D70` 里对无效 Guid 的默认替换）。
   这与 q1 报告“PROFSAVE 里没有任何 loadout/customization 键”的结论一致。

6. 【推荐】AutoOffline 的做法：**hook `sub_1417669A0` 捕获（每次点选都会调用，不依赖提交）**，
   **hook `sub_14175E5F0`（唯一读入口）在它读之前把存档写回管理器**。
   需要玩法侧同步时再重放本地事件。具体见第 5 节。

---

## 1. 调用链与证据

### 1.1 UI 实体

`ClientUICustomizeTombstoneEntity` 的 C++ 类：

| 项 | 值 |
| --- | --- |
| 类型名串 | `0x14363EED8` = `ClientUICustomizeTombstoneEntity` |
| 类型注册 | `sub_14016CCA0` / `sub_14016DB30`（引用上面的串） |
| 构造函数 | `sub_141792F60`（RVA `0x1792F60`），设置 vtable `off_143641DD0` |
| vtable | `0x143641DD0` |
| 对象大小（构造可见） | 至少 0x110 字节（a1+224 是最后一个字段） |

构造函数按 EBX 字段哈希取字段，其中两个是 `PlayerTombstoneInfo` 类型（`off_144DDA240` 对应的
类型记录，元素类型名 `PlayerTombstoneInfo`，数组类型名 `PlayerTombstoneInfo[]`）。
这两个字段是目录里的默认项引用（shared_ptr），不是玩家当前选择。

对象内部布局（本报告需要的部分）：

| 偏移 | 含义 |
| --- | --- |
| `+64` | `slot`（DWORD），来自实体数据 `+32`，就是玩家槽位 |
| `+120` | Guid `head`（已提交的胜利牌） |
| `+136` | Guid `left`（已提交的左拳套） |
| `+152` | Guid `right`（已提交的右拳套） |
| `+168/184/200` | 预览用的一份副本（`sub_14179E3F0` 从 +120/+136/+152 复制后再按当前目录项覆盖） |
| `+216/224` | 两个 `PlayerTombstoneInfo` 默认项 |

### 1.2 单件选择：`sub_1417950E0`

RVA `0x17950E0`，签名 `void __fastcall(entity, Guid *item, int itemType)`：

```c
v3 = itemType - 1;
if (v3) {                       // itemType != 1
  v4 = v3 - 1;
  if (v4) {
    if (v4 == 1) *(OWORD*)(entity + 152) = *item;   // itemType == 3 -> right
  } else {
    *(OWORD*)(entity + 136) = *item;                // itemType == 2 -> left
  }
} else {
  *(OWORD*)(entity + 120) = *item;                  // itemType == 1 -> head
}
if (qword_144659DB0)
  sub_1417669A0(qword_144659DB0, *(DWORD*)(entity + 64), entity + 120);
```

`itemType` 的取值来自 `UITombstoneItemType` 枚举（字符串 `0x1437AA478/498/4B8`）：
`Headstone = 1`、`LeftPunch = 2`、`RightPunch = 3`。

### 1.3 UI 管理器写入：`sub_1417669A0`

RVA `0x17669A0`，首字节 `41 0F 10 00 8B C2 48 69 D0 B8 00 00 00`：

```c
void *__fastcall sub_1417669A0(void *manager, unsigned int slot, OWORD *guids)
{
  __int64 v3 = 184LL * slot;
  void *base = *(void **)(manager + 32);
  *(OWORD *)(v3 + base + 88)  = guids[0];   // head
  *(OWORD *)(v3 + base + 104) = guids[1];   // left
  *(OWORD *)(v3 + base + 120) = guids[2];   // right
  return base;
}
```

全库只有两个调用点，都在这个实体里：

| 调用点 | 所在函数 | 语义 |
| --- | --- | --- |
| `0x141795127` | `sub_1417950E0` | 每点选一件就打进管理器 |
| `0x141795249` | `sub_141795170` | 提交事件里再刷一次 |

对应地，UI 管理器 per-slot 记录（stride 184）的布局【已证 + 部分推测】：

| 偏移 | 内容 | 证据 |
| --- | --- | --- |
| `+8` | std::list 哨兵（节点 +32 = id、+40/+48 = u32 对数组、+56 = next） | `sub_141765910` |
| `+56 / +64` | `vector<Guid>` begin/end（整表上传用） | `sub_141765D60`、`sub_141797210` |
| `+88` | Guid `head` | `sub_1417669A0` / `sub_14175E5F0` |
| `+104` | Guid `left` | 同上 |
| `+120` | Guid `right` | 同上 |
| `+136 / +144` | 排序 vector（元素 24 字节：Guid + 指针），用于“是否已装备”查询 | `sub_14175F3D0` |
| `+176` | byte 脏标记 | `sub_14175BC10` |
| `+180` | DWORD 版本号 | `sub_1417669D0`、`sub_1417614C0` |

### 1.4 提交事件：`sub_141795170` 的 `0x5AFEBB1D` 分支

RVA `0x1795170`，实体的事件处理函数。三个事件 id：

| 事件 id | 分支行为 |
| --- | --- |
| `0xAF9854EA` | 取实体属性 `v7`（`TombstoneItemType`），调用 `sub_1417950E0(entity, item, (v7==2)+2)`；刷新 UI，发输出事件 `0x93D596AF` |
| `0xE0E88E41` | 同上，`sub_1417950E0(entity, item, v7)` |
| `0x5AFEBB1D` | **提交**，见下 |

`0x5AFEBB1D` 分支伪代码（已简化）：

```c
v11 = qword_144659DB0;
if (v11) {
  sub_1417669A0(v11, *(DWORD*)(a1 + 64), a1 + 120);   // 1) 写 UI 管理器
  sub_141766140(v11, *(DWORD*)(a1 + 64));             // 2) HTTP POST 上传
}
v12 = sub_140F3CC30(*(void**)(qword_1445B6040 + 176), *(DWORD*)(a1 + 64)); // 玩家实体
v15 = sub_1406C01F0(*(void**)(qword_1445B6040 + 184));                     // 消息发送器
if (v12 && v15) {
  sub_142DA2520(msg);                    // 3) 构造网络消息（88 字节头 + 三 Guid + net id）
  sub_141129DC0(&netid, v12 + 136);
  msg[88]  = *(OWORD*)(a1 + 120);
  msg[104] = *(OWORD*)(a1 + 136);
  msg[120] = *(OWORD*)(a1 + 152);
  (*(v15->vtbl + 152))(v15, msg);        //    发送
  sub_141107D70(msg);                    //    析构
}
evt = sub_1404151D0(96, qword_144217E88);
if (evt) evt = sub_142D13160(evt, *(DWORD*)(a1 + 64));   // 4) 本地事件（96 字节）
*(OWORD*)(evt + 48) = *(OWORD*)(a1 + 120);
*(OWORD*)(evt + 64) = *(OWORD*)(a1 + 136);
*(OWORD*)(evt + 80) = *(OWORD*)(a1 + 152);
return sub_140470400(qword_1445B6040 + 32, evt);         //    压进本地事件队列
```

要点：
- HTTP 上传与网络发送都可能因为离线失败，但 **本地事件这一段是无条件的**（只要 `qword_1445B6040` 非空）。
- 网络消息的类型在 `sub_142DD1480` 注册（`sub_141107330(..., 0x5973B9, 0x729DEEF4, 255, 2, 2, ...)`），
  字段布局为三 Guid 在 `+88/+104/+120`、玩家 net id 在 `+136`。
  【推测】它就是 `UITombstoneUpdateMessage`（名字串在 `0x143796FE0`，类型记录在 `0x144DEF960`），
  但没有找到两者之间的直接指针链，故只作推测。

### 1.5 本地应用：`0xC1E5086B` → `sub_1415ED1F0`

本地事件类型由 `sub_142D1A440` 注册，事件 id `0xC1E5086B`（= 注册参数 `-1041954709`）。
分发器 `sub_1415E8910` 的 `0xC1E5086B` 分支：

```c
v7 = <把 a2+48 的三个 Guid 序列化成字符串>;   // 通过 sub_141EBCA00 + 转换器
if (*v7) {
  v8 = "tombstone";                             // off_143FBF930
  v6 = sub_140F3CC30(*(qword_1445B6040 + 176), *(DWORD*)(a1 + 32)); // 玩家实体
  sub_1415ED1F0(a1, v6, v8, v7, v8);
}
```

`sub_1415ED1F0`（RVA `0x15ED1F0`）构造一条 288 字节的属性变更消息（vtable `off_144F2B9D0`，
在注册表 `sub_142273C90` 的 109 个同类消息里），字段：

| 偏移 | 内容 |
| --- | --- |
| `+256` | key 字符串 `tombstone` |
| `+264` | key 字符串 `tombstone`（重复一份，给不同接收方） |
| `+272` | value 字符串（三 Guid 的 JSON） |
| `+280` | 标志位，或上 1 / 2 / 4 |
| `+136` 等 | 玩家身份（由 `sub_1415D1D30` 填入 net id、名字、会话信息） |

然后 `sub_1415D1D30` 把这条消息投给玩家实体（`sub_142278870(playerEntity, slot)`）。
也就是说 **玩家实体上有一个以 `tombstone` 为 key 的属性**，值是三 Guid 的 JSON；
这条路径就是“改完之后立刻生效”的来源，也是【推测】实际墓碑模型读取的数据源。

### 1.6 读回：`sub_14175E5F0`（唯一读取点）

RVA `0x175E5F0`，签名 `void __fastcall(manager, slot, OWORD *out3)`，就是把
`entry + 88/+104/+120` 三个 Guid 拷出来。全库只有一个调用者：
`sub_141797D70`（实体 activate，vtable 槽 16）。

`sub_141797D70` 的逻辑：

```c
sub_14175E5F0(qword_144659DB0, *(DWORD*)(a1 + 64), a1 + 120);   // 读管理器
if (qword_144790778) {                    // 目录已就绪
  v3 = sub_1417F7FA0();                   // 目录
  v5 = <玩家实体>;
  if (<Guid 为零 或 sub_142321650(目录, 玩家实体, Guid) 判定未拥有>)
      a1+120 = v3[6] 的默认项;             // 胜利牌默认
      a1+136 = v3[7] 的默认项;             // 拳套默认
      a1+152 = v3[8] 的默认项;
  sub_14179CC10(a1);                      // 重建列表/选中态
  sub_14179E3F0(a1);                      // 刷新预览
  sub_141090840(a1, ..., 0x93D596AF);     // 发输出事件
}
```

**这就是离线启动时“回到默认”的具体位置**：管理器这一格是空的，读出来是零 Guid，
于是走默认替换分支。同一函数里 `sub_142321650` 还会做一次“是否拥有”的校验，
存档里的 Guid 必须仍然拥有，否则同样被替换成默认。

### 1.7 服务端数据形态（旁证）

镜像里确实存在墓碑的业务类型，但它们是 Blaze TDF / 经济系统那一套：

| 类型 | 注册函数 | 字段（TDF 偏移） |
| --- | --- | --- |
| `Blaze::PvzGw::TombstoneLoadout`（type id `-855502176` = `0xCD0212A0`） | `sub_141CC1800` | `head` @0x10、`left` @0x28、`right` @0x40 |
| `Blaze::PvzGw::TombstoneItem`（type id `674097077` = `0x282DE7B5`） | `sub_141CD6900` | `name` @0x10、`description` @0x28、`guid` @0x40、`new` @0x58、`itemBin` @0x60、`st` @0x78、`alias` @0x90、`category` @0xA8、`rarity` @0xC0 |
| `Blaze::PvzGw::EconomyLoadoutType` | `sub_141CD6B90` | `TOMBSTONESETTINGS = 1`（`CHARACTERLOADOUTS = 0`） |

【已证】这些 TDF 类型在代码里没有任何直接引用（xref 只有注册桩），与 q1 报告的结论一致：
Blaze 经济回包不会被 C++ 侧解释。**真正在跑的是 HTTP + 属性消息这条路。**

另外，玩家档案 JSON 的 key 表里同时有 `customizations` 和 `tombstone`
（`0x1437796C8` / `0x1437796D8`），序列化侧在 `sub_141D19F60`，反序列化侧在
`sub_1415E8910` 的各分支。这说明 `tombstone` 是玩家档案里的一个独立字段，与角色皮肤并列。

---

## 2. 三项选择在客户端本地到底存在哪里

按“从哪读到、能活多久”分成四层：

| 层 | 位置 | 生命周期 | 谁写 | 谁读 |
| --- | --- | --- | --- | --- |
| 实体暂存 | `entity + 120/136/152` | 界面实体销毁即丢 | `sub_1417950E0`、`sub_141797D70`（初始化）、`sub_14179E3F0`（预览副本） | 实体内各处 |
| UI 管理器 | `*(qword_144659DB0 + 32) + 184*slot + {88,104,120}` | 进程内，登录/切换槽位时可能被重置或重填 | 只有 `sub_1417669A0`（实体两处） | 只有 `sub_14175E5F0`（实体 activate） |
| 玩家属性 | 玩家实体上的 `tombstone` 键值（JSON 字符串） | 进程内，随玩家实体 | `sub_1415ED1F0`（本地事件分发后） | 未定位（【推测】墓碑生成方） |
| 服务端 | EA 后端 HTTP（`application/json`）+ 网络消息 | 跨会话 | `sub_141766140` / `sub_142DA2520` | 启动时 HTTP 下载（`sub_14175A510` → `sub_1417566B0` → `sub_14175EF30`） |

结论：
- **本地没有文件缓存**。`PROFSAVE` / `PROFSAVE_profile` 不含任何 customization 键（q1 已实测）。
- 离线时唯一能跨会话保存这三项的只有我们自己的 `autooffline_save.json`。
- 现有存档里没有 id=0 条目，是因为胜利牌根本不走 `sub_1416B74C0` / `sub_141766580`。

---

## 3. 现有 AutoOffline 代码里过时的结论

`src/AutoOffline.cpp` 第 68-69 行的注释

```
// 配置权威表写入: 胜利牌/拳套这类不经漏斗的 UI 也走这里。
{0x1766580u, {0x48, 0x83, 0xEC, 0x28, 0xE8}, 5, "config write auth", 0x1766580u},
```

与实测不符：胜利牌**不走** `sub_141766580`。同一模块里另有一组函数
（`sub_141766140` / `sub_1417669A0` / `sub_1417669D0` / `sub_14175E5F0`）专管墓碑三项。
`sub_141766580` 的 xref 仍然只有 `sub_1416B74C0` 和它的类 vtable 数据引用，这点没有变化。

---

## 4. 函数表（按调用顺序）

| RVA | 绝对地址 | 名字 | 签名 | 作用 |
| --- | --- | --- | --- | --- |
| `0x1792F60` | `0x141792F60` | `ClientUICustomizeTombstoneEntity` ctor | `(this, entityData, instanceId)` | 建实体，取 slot 与默认项 |
| `0x1797D70` | `0x141797D70` | 实体 activate（vtable 槽 16） | `(this)` | 读管理器 + 默认替换 + 刷新 |
| `0x175E5F0` | `0x14175E5F0` | 管理器读取 helper | `(mgr, slot, OWORD out[3])` | 拷出三个 Guid（唯一读者） |
| `0x17669A0` | `0x1417669A0` | 管理器写入 helper | `(mgr, slot, const OWORD in[3])` | 写入三个 Guid（唯一写者之一） |
| `0x17950E0` | `0x1417950E0` | 单件选择 | `(entity, const Guid*, int itemType)` | 按 1/2/3 写实体暂存再刷管理器 |
| `0x1795170` | `0x141795170` | 实体事件处理 | `(entity, msg)` | `0x5AFEBB1D` = 提交 |
| `0x1766140` | `0x141766140` | 墓碑上传 | `(mgr, slot)` | HTTP POST `application/json` |
| `0x175A510` | `0x14175A510` | 墓碑下载请求 | `(this, msg)` | HTTP GET，回调 `sub_1417566B0` |
| `0x17566B0` | `0x1417566B0` | 下载完成回调 | `(this, resp, err)` | `err==0` 才应用 |
| `0x175EF30` | `0x14175EF30` | 下载数据反序列化 | `(mgr, resp)` | 通用 JSON 绑定 |
| `0x2DA2520` | `0x142DA2520` | 网络消息构造 | `(msg)` | 88 字节头 + 三 Guid + net id |
| `0x2DD1480` | `0x142DD1480` | 网络消息类型注册 | `()` | id `0x5973B9` / `0x729DEEF4` |
| `0x2D13160` | `0x142D13160` | 本地事件构造 | `(evt, slot)` | 96 字节，类型 `0xC1E5086B` |
| `0x04151D0` | `0x1404151D0` | 事件分配器 | `(size, pool)` | 池 `qword_144217E88` |
| `0x0470400` | `0x140470400` | 事件入队 | `(queue, evt)` | queue = `*(qword_1445B6040)+32` |
| `0x15E8910` | `0x1415E8910` | 事件分发 | `(this, evt)` | `0xC1E5086B` 分支处理墓碑 |
| `0x15ED1F0` | `0x1415ED1F0` | 属性广播 | `(this, playerEntity, key, value, key2)` | 构造 288 字节属性消息并投递 |
| `0x1766580` | `0x141766580` | 皮肤/Perk 权威表写入 | `(mgr, slot, charId, preset, key, value)` | 与墓碑无关（现有 hook） |
| `0x4659DB0` | `0x144659DB0` | UI 管理器全局指针 | `qword` | entry 数组在 `*(+32)` |
| `0x45B6040` | `0x1445B6040` | 全局运行时（玩家管理器 +176、消息器 +184、事件队列 +32） | `qword` | |
| `0x4217E88` | `0x144217E88` | 事件分配池 | `qword` | |

---

## 5. AutoOffline hook 方案

### 5.1 捕获（必做）

挂 `sub_1417669A0`（RVA `0x17669A0`，expected `41 0F 10 00 8B C2 48 69 D0 B8 00 00 00`）：

```c
typedef void *(__fastcall *UiTombstoneWriteFn)(void *mgr, unsigned int slot, const void *guids);
static void __fastcall HookTombstoneWrite(void *mgr, unsigned int slot, const void *guids) {
  UiTombstoneWriteFn orig = (UiTombstoneWriteFn)g_tombstone_write_orig;
  void *ret = orig ? orig(mgr, slot, guids) : nullptr;
  if (!g_in_restore && mgr && guids && slot < kMaxSlots) {
    // 读 48 字节，按 slot 存进 autooffline_save.json 的新节
    SaveTombstone(slot, (const unsigned char *)guids);
  }
  return ret;
}
```

为什么选这里而不是提交点：
- 每点一件就调用一次，**不依赖 `0x5AFEBB1D` 提交事件**，离线也不会漏；
- 参数就是完整的三个 Guid，天然带 slot；
- 它不参与角色皮肤/Perk 的任何路径，和现有 hook 不冲突；
- 它是“UI 管理器最终值”的唯一写入口，采到的就是 UI 认的值。

可选加挂 `sub_1415ED1F0`（RVA `0x15ED1F0`，expected `48 85 D2 0F 84 0F 02 00 00 48 8B C4 57 41 56 41`）
保存那份 JSON 字符串（`a4`），作为“原样重放”的备份；不存也可以，重放本地事件时游戏会自己生成。

### 5.2 存档格式

现有 `autooffline_save.json` 是 `{version, characters[]}`，每角色三个 preset 的 (key,value) 表。
墓碑是三个 16 字节 Guid，塞不进 key/value。建议新增顶层节，并把 `kSaveVersion` 升到 2：

```json
{
  "version": 2,
  "characters": [ ... 原样 ... ],
  "tombstones": [
    { "slot": 0,
      "head":  "1A2B3C4D5E6F708192A3B4C5D6E7F809",
      "left":  "....",
      "right": "...." }
  ]
}
```

注意：`SaveLoad` 必须显式解析 `tombstones`（不认识的键在 `SaveStore` 重写时会丢），
`g_save_writable` 的保护逻辑照旧。Guid 用 32 个 hex 字符存，写盘前排序、字节序固定为内存原序。

### 5.3 恢复（推荐做法）

**主恢复点：`sub_14175E5F0`（RVA `0x175E5F0`，expected `8B C2 48 69 D0 B8 00 00 00 48 8B 41 20`）**

这是实体 activate 读管理器之前唯一的一道门，时序天然正确，不存在“写早了被重置”的问题：

```c
typedef void (__fastcall *UiTombstoneReadFn)(void *mgr, unsigned int slot, void *out);
static void __fastcall HookTombstoneRead(void *mgr, unsigned int slot, void *out) {
  if (!g_in_restore && mgr && slot < kMaxSlots) {
    void *base = *(void **)((unsigned char *)mgr + 32);
    Tombstone t;
    if (base && LoadTombstone(slot, &t)) {
      unsigned char *e = (unsigned char *)base + 184u * slot;
      memcpy(e + 88,  t.head,  16);
      memcpy(e + 104, t.left,  16);
      memcpy(e + 120, t.right, 16);
    }
  }
  UiTombstoneReadFn orig = (UiTombstoneReadFn)g_tombstone_read_orig;
  if (orig) orig(mgr, slot, out);
}
```

要求与顺序：
1. `mgr` = `*(void**)(g_base + 0x4659DB0)`，和现有 `kUiManagerRva` 是同一个；
2. `*(void**)(mgr + 32)` 必须非空（管理器 ctor 里分配，早于 UI 实体 activate）；
3. `slot` 必须小于槽位数（**建议按 8 校验**，见风险点）；
4. 必须在调用原函数**之前**写，否则这一帧读到的还是旧值；
5. `g_in_restore` 用来挡住恢复期间自己触发的捕获（与本文件现有用法一致）。

如果希望 UI 之外也立刻生效，可在写完之后补一次本地事件重放（可选）：

```c
void *evt = ((AllocFn)(g_base + 0x04151D0))(96, *(void **)(g_base + 0x4217E88));
if (evt) {
  ((EvtCtorFn)(g_base + 0x2D13160))(evt, slot);
  memcpy((char *)evt + 48, t.head,  16);
  memcpy((char *)evt + 64, t.left,  16);
  memcpy((char *)evt + 80, t.right, 16);
  void *rt = *(void **)(g_base + 0x45B6040);
  if (rt) ((EnqueueFn)(g_base + 0x0470400))((char *)rt + 32, evt);
}
```

这条等价于游戏在提交事件里做的第 4 步，会把三个 Guid 序列化成 JSON 并以 `tombstone`
为 key 广播给玩家实体。**离线时游戏自己也会走这一步**（只有 HTTP 和网络发送会失败），
所以重放不会引入服务器依赖。
注意 `sub_140470400` 入口是 `48 8B 09 E9 ...` 的跳板，内部会解引用第一个参数，
必须确认 `qword_1445B6040` 非空再调用；建议只在“玩家实体已经存在、且本槽第一次恢复”时做一次。

### 5.4 需要新增的 RVA / expected bytes / 签名

| 用途 | RVA | expected（前 13 字节） | 签名 |
| --- | --- | --- | --- |
| 捕获 | `0x17669A0` | `41 0F 10 00 8B C2 48 69 D0 B8 00 00 00` | `void *(__fastcall*)(void *mgr, unsigned slot, const void *guids3)` |
| 恢复 | `0x175E5F0` | `8B C2 48 69 D0 B8 00 00 00 48 8B 41 20` | `void (__fastcall*)(void *mgr, unsigned slot, void *out3)` |
| 可选重放 | `0x2D13160` | `48 89 4C 24 08 53 48 83 EC 30` | `void *(__fastcall*)(void *evt, unsigned slot)` |
| 可选重放 | `0x04151D0` | `4C 8B D2 8D 41 F0 85 C0 BA 10 00 00 00` | `void *(__fastcall*)(size_t size, void *pool)` |
| 可选重放 | `0x0470400` | `48 8B 09 E9 38 F7 FF FF`（跳板） | `void (__fastcall*)(void *queue, void *evt)` |

三个全局：`0x4659DB0`（UI 管理器）、`0x45B6040`（运行时）、`0x4217E88`（事件池）。
`expected` 只用于等解密和确认函数身份，和现有 `g_hooks` 表同一套机制。

### 5.5 风险点

1. **槽位数未核实**。entry 数组按 `184 * slot` 寻址，没有边界检查（游戏自己也不查）。
   写之前至少要求 `slot < 8`，最好再加“entry+88 处可读”的 SEH 保护。
2. **拥有校验**。`sub_141797D70` 会用 `sub_142321650(目录, 玩家实体, Guid)` 复核，
   没拥有过的 Guid 会被换成默认项。离线账号如果拿不到目录/拥有列表，恢复可能被判定无效。
   这一点必须在实机验证（见第 6 节）。
3. **管理器重置时机**。未找到“登录时把服务器数据写进 entry”的函数；已确认的写者只有 UI 自己。
   下载回调（`sub_1417566B0`）只在成功时应用，离线不会触发，所以恢复点选在读取之前最稳。
4. **不要在恢复里调用 `sub_1417669A0`**。它本身不校验任何东西，但调用它会触发我们自己的捕获；
   用 `g_in_restore` 挡住虽然可行，但直接写 entry 更简单、副作用更小。
5. **属性重放的时机**。`sub_140470400` 依赖 `qword_1445B6040` 的事件队列；
   在会话/玩家实体建立之前调用可能被丢弃。建议只在读取 hook 里、玩家实体已存在时做一次。
6. **不要 hook `sub_141766140`**（HTTP 上传）。它是提交路径，离线时会被 `sub_1417601E0` 的前置判断短路，
   即使调用也会走网络层，不是可靠捕获点。

---

## 6. 未解决问题

1. 【未验证】UI 管理器 entry 数组的槽位数量（推测 8），以及它在登录、切槽、下载完成时是否被清空或重填。
2. 【未验证】存档中的 Guid 在离线时能否通过 `sub_142321650` 的“拥有”校验；如果不通过，
   UI 会显示默认项（但 entry 里的值是否会被改写也未验证）。
3. 【推测】`UITombstoneUpdateMessage`（名字串 `0x143796FE0`）与 `sub_142DA2520` 构造的消息类
   是同一条消息；没有找到直接指针链，只确认了字段布局与语义吻合。
4. 【未定位】实际生成墓碑模型的一方如何读取 `tombstone` 属性；本次只追到属性广播，
   没有再往下追消费端（任务边界内不做）。
5. 【未验证】三项 Guid 中 `left` 与 `right` 在 UI 语义上是否与玩家左右手一致
   （代码里只是 `LeftPunch=2`、`RightPunch=3` 的顺序，没有看到左右手绑定代码）。

---

## 7. 下一步验证建议（实机，一次就能闭环）

1. 用诊断 DLL 同时 hook `sub_1417669A0` 和 `sub_14175E5F0`，各打一行日志
   （`slot`、三个 Guid 的 hex）。改一次胜利牌/左右拳套，确认：
   - 每次点选都出现 `tombstone write slot=0 head=... left=... right=...`；
   - 打开自定义界面时出现 `tombstone read slot=0 ...`，且值与存的一致。
2. 在同一份日志里打印 `*(void**)(ui + 32)` 与 `slot` 的最大值，确认数组存在且槽位 < 8。
3. 把捕获值写进 `autooffline_save.json`，重启离线，在读取 hook 里写回，
   观察三件事：UI 是否显示上次的选择、进图死亡后的墓碑模型是否变化、`sub_142321650` 是否把值换掉。
4. 如果 UI 显示正确但墓碑模型不变，再启用 5.3 的本地事件重放，重复第 3 步。

以上第 1 步就能把“写入点 + 读取点 + 槽位”三件事钉死；第 3、4 步区分“只影响 UI”还是“也影响玩法”。

---

## 8. 2026-11-13 实机日志验证

实现按第 5 节方案落地（MinHook 两条入口 hook，存档版本 2 增加 `tombstones`）。部署 DLL 的 SHA256 为 `8266832ACFEDEBE9C52FBC0C0ED33A7F24680F0286D7CE3E74F40D9AE7971B4C`，游戏日志记录：

- `18:20:34` 首次启动，旧 v1 存档：`save: version 1 has no tombstones, reading characters only`。
- `18:21:51` 游戏内修改胜利牌/左右拳套，捕获 hook 连续触发；最终 `capture: tombstones slot=0 head=A1C7F94DFF2C184CADD95C02B5D3F976 left=954A55DE146D904D9A1C180374924910 right=8D4F256508498544B84377B1CB899797`，随后 `save: wrote 29 characters, 1 tombstones`。
- `autooffline_save.json` 已是版本 2，含 `tombstones` 段，值与日志一致。
- `18:22:24` 重启游戏：`save: loaded 29 characters, 1 tombstones`。
- `18:23:25` 读取 hook 触发：`restore: tombstones slot=0 head=A1C7... left=954A... right=8D4F...`，写回值与存档一致。

结论：写入点 `0x17669A0`、读取点 `0x175E5F0`、slot 0、三 Guid 偏移 88/104/120、版本 2 存档均按预期工作。`sub_142321650` 的拥有校验是否把值换掉、UI 是否目视显示上次选择、墓碑模型是否跟随，仍需在游戏内确认。
