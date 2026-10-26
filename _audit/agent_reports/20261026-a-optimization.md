# 2026-10-26 第 1 项（代码能不能优化）审计报告

核到 md5 = caba00976290f6a5a264457af2fc459a，实际行数 955，与派单一致。审计期间除本报告外未改动任何文件，未跑游戏，未装 DLL。
方向：只看能不能删、能不能合、能不能算得更省；不判对错、不判注释、不判并发。越界的写在最后"交叉线索"，一句话一条，不展开。

## 速览（按收益排）

| # | 位置 | 一句话 | 省什么 |
|---|------|--------|--------|
| c1 | 50-128 / 695-712 / 771-784 / 834-876 | 挂钩安装有三套并存，每条 hookRva 被写三遍 | 约 55 行、两条 switch、一条 if-else 链；加一条补丁从改 5 处变成改 1 处 |
| c2 | 100-104 / 810-832 / 695-712 | 交互解锁与两条 loadout hook 不参与"等解密" | 一处静默失效窗口；与 c1 同一处改动 |
| d1 | 549 / 552 / 665 / 749 / 757 / 767 / 804 | 7 处不可达的 orig 空指针守卫，其中 2 处在每次调用上 | 7 个分支、7 行；并消掉"守卫生效时给出错答案"的静默降级 |
| e1 | 936-944 | 100ms 轮询一个 bool | 每秒 10 次空唤醒归零；顺手消掉跨线程裸 bool |
| c3 | 331-368 / 388-418 | JSON 字段映射写了两遍 | 约 25 行，字段名只有一个维护点 |
| c4 | 193-221 | 同一趟字节比对循环写了两遍 | 约 8 行 |
| c5 | 161-179 | 日志格式化两趟 + 1.2KB 栈缓冲 | 约 4 行、1.2KB 栈 |
| b1 | 721 / 725 / 860 | g_p1_orig 只写不读 | 2 行 + 1 个分支 |
| b3 | 487-489 | presetStart[1..3] 的清零是死写 | 3 行 |
| d3 | 644-647 | 截断日志会重复打 | 1 行改动 |
| b2 | 741 | SESSMASK_GET_RVA 无人使用 | 1 行 |
| c6 | 463 / 581 | 同一个 1024 起两个名字 | 1 行 |
| d2 | 217-219 | 失败日志固定打 5 字节，实际有 1 字节和 3 字节的条目 | 日志不再显示幽灵字节 |

合计可删约 90 行（955 行的 9% 左右），运行时省掉每条补丁的一次分支判断和一个每秒 10 次的空转唤醒。下面逐条给判据与改法。

## 问题

### (c) 重复实现

#### c1. 挂钩安装有三套实现，同一条 hookRva 在三个地方各写一遍

原文摘录：

```
 51      {0x156FA30u, {0x48, 0x83, 0xEC}, 3, "OfflineFix #1", 0x156FA30u},
 61      {0x178A8EDu, {0x0F, 0x92, 0x44, 0x24, 0x21}, 5, "player in session", 0x447450u},
 99      {0x25464F4u, {0x05}, 1, "UserProfileInfo+130h = clientType", 0x2546450u},
112      {0x1D0F6F6u, {0xE8, 0x85, 0x5E, 0xFF, 0xFF}, 5, "client inactivity kick", 0x1D05580u},
...
771  static void *DetourFor(unsigned int hookRva) {
772    switch (hookRva) {
773    case 0x156FA30u:
774      return (void *)&HookOfflineFix;
775    case 0x447450u:
...
859      if (p.hookRva == 0x156FA30u)
860        g_p1_orig = (P1Fn)orig;
861      else if (p.hookRva == 0x447450u)
862        g_maskget_orig = (MaskGetFn)orig;
```

判据：0x447450u 这个值在文件里出现四次（第 61 行表、第 741 行那个根本没用上的宏、第 775 行 case、第 861 行 if），0x156FA30u / 0x2546450u / 0x1D05580u 各三次。也就是说"一条补丁的身份"被三个互不引用的结构分别表述：表里一行、DetourFor 一个 case、InstallHooks 里一条 if-else，另外还有一个专属的 g_pX_orig 全局量和一个专属的 typedef。表头第 20 行写"增删条目直接改表, 然后重启游戏"，按现在的结构改表是不够的：要同时改表、改 switch、改 if-else、加全局量、加 typedef，五处漏一处不会编译失败，只会在等满三分钟之后打一行 `no detour for %llX`，然后这条补丁静默不生效。

第二层重复是三个安装器：`InstallOneHook`（671-693，校验字节 + 创建 + 启用 + 记日志）、`InstallHooks` 里的循环（841-873，创建 + 启用 + 记日志，不校验字节）、`InstallInteractionHook`（810-832，校验 + 创建 + 启用 + 记日志，是 InstallOneHook 的手抄本）。三者对同一件事有三种日志格式，并且"orig 什么时候存"也不一致：InstallOneHook 在 MH_EnableHook 成功之后才存（689 行），InstallHooks 在启用之前存（859-866 行）。后者的顺序才是对的：EnableHook 一返回，别的线程就可能进 detour，此时 orig 必须已经就位。

收益：删掉 DetourFor（14 行）、if-else 链（8 行）、InstallInteractionHook（23 行）、InstallLoadoutHooks 里的两条 InstallOneHook 调用和外挂的 want 数组（18 行缩到约 5 行的"取四个辅助函数地址"），InstallOneHook 本身从 23 行缩到 14 行（校验挪走后就不需要 want 参数了，理由见下）。净减约 55 行，七个挂钩点收敛成一张表的七行，安装只有一条路径、一种日志。

关于"校验挪走"为什么安全：现在真正拦住"对着未解密字节做指令解码"的是 `AllExpectedPresent`（第 193 行，等满三分钟的那道闸），不是 InstallOneHook 里的那次 memcmp，因为 InstallHooks 的循环压根没校验（这也是表头第 40 行"挂钩前确认函数没认错"那句话与代码对不上的原因）。四条表行里有三条（#2、#3、#6）的校验地址与挂载地址本来就不是同一处，逐 hook 的字节校验对它们从来做不到。所以把校验集中到 AllExpectedPresent 一处，是把已有的真实语义写明，不是削弱。

建议做法：把表下移到 InstallHooks 旁边（这样 detour 函数都已定义，不需要任何前向声明，也符合"禁止无用前向声明"的既有约定），表加两个字段，然后只留一个安装器。

```cpp
struct PatchDef {
  unsigned int checkRva;      // 校验原始字节的位置, 用来等代码解密
  unsigned char expected[8];
  int explen;
  const char *desc;
  unsigned int hookRva;       // 挂在哪个函数入口; 0 = 只校验, 不挂
  void *detour;
  void **origOut;
};

static const PatchDef g_patches[] = {
    {0x156FA30u, {0x48, 0x83, 0xEC}, 3, "OfflineFix #1", 0x156FA30u,
     (void *)&HookOfflineFix, nullptr},
    {0x178A8EDu, {0x0F, 0x92, 0x44, 0x24, 0x21}, 5, "player in session", 0x447450u,
     (void *)&HookSessionMask, (void **)&g_maskget_orig},
    // ...
    {0x450180u, {0x48, 0x89, 0x5C, 0x24}, 4, "interaction kill switch", 0x450180u,
     (void *)&HookNameGet, (void **)&g_nameget_orig},
    {0x16B74C0u, {0x44, 0x89, 0x4C, 0x24, 0x20}, 5, "loadout edit hook", 0x16B74C0u,
     (void *)&HookLoadoutEdit, (void **)&g_edit_orig},
    {0x16AD770u, {0x4C, 0x89, 0x44, 0x24, 0x18}, 5, "model constructor hook", 0x16AD770u,
     (void *)&HookModelCtor, (void **)&g_ctor_orig},
};

static bool InstallOneHook(unsigned long long target, void *detour, void **origOut,
                           const char *what) {
  void *orig = nullptr;
  MH_STATUS st = MH_CreateHook((LPVOID)target, detour, &orig);
  if (st != MH_OK) {
    Log("!! %s @ %llX: MH_CreateHook %s", what, target, MH_StatusToString(st));
    return false;
  }
  if (origOut)
    *origOut = orig;              // 先存再启用: 启用一返回别的线程就可能进 detour
  st = MH_EnableHook((LPVOID)target);
  if (st != MH_OK) {
    Log("!! %s @ %llX: MH_EnableHook %s", what, target, MH_StatusToString(st));
    return false;
  }
  Log("%s: hooked %llX", what, target);
  return true;
}

  for (int i = 0; i < NPATCH; ++i) {
    const PatchDef &p = g_patches[i];
    if (!p.hookRva)
      continue;                   // 只校验的条目
    InstallOneHook(g_base + p.hookRva, p.detour, p.origOut, p.desc);
  }
```

顺带消失的还有：第 843 行 `if (p.hookRva == 0u)`（表里没有这种行，且 DetourFor 的 default 已经兜了一次，是一个不可达状态上的双重守卫）、第 848-852 行的 `detour == nullptr` 分支、三份日志格式、以及第 818 行 `g_fakeNameObj[0] = (void *)g_emptyName;` 这行安装期初始化（可以并进静态初始化 `static void *g_fakeNameObj[2] = {(void *)g_emptyName, nullptr};`，少一处"必须先装 hook 才能用"的隐式顺序）。

风险：低。唯一要核的是表里新增三条的校验字节与挂载地址相同（第 450180、16B74C0、16AD770），字节已经写在现在的代码里（813、701、707 行），搬过去即可，不需要重新从 exe 取。patch #2/#3/#6 保持 checkRva 与 hookRva 分开，语义不变。

#### c2. 交互解锁与两条 loadout hook 不参与"等解密"，会静默不挂

原文摘录：

```
100    // ---- 补丁 5: 交互解锁 (挂取 KillSwitch 名字的函数) ----
...
812    unsigned long long target = g_base + NAMEGET_RVA;
814    if (!SafeReadBytes(target, head, 4) || memcmp(head, want, 4) != 0) {
815      Log("!! interaction hook: unexpected bytes at %llX, NOT hooked", target);
816      return;
818    }
```

判据：补丁 5 在表里只有注释（100-104 行），没有数据行，所以它不进入 `AllExpectedPresent` 的等待集；`InstallInteractionHook` 只在 InstallHooks 里被调一次，字节不符就直接返回，永不重试。两条 loadout hook 同理（`InstallOneHook` 的 `unexpected bytes ... NOT hooked` 分支）。结果是四条表行享有"最多等 3 分钟"的保护，另外三条只有"那一刻正好解密了才挂上"。日志上这两种结局都表现为"byte patterns matched"之后的一行 NOT hooked，分不出"这个 exe 版本对不上"和"解密晚了一步"。

未验证：这三处是否与四条表行在同一时刻解密（本次不跑游戏）。所以给两条路：

- 推荐：按 c1 把三条并进表，它们自然进入等待集。理由是 RVA 本来就是单一 exe 版本硬编码，任何一条 RVA 错了这个 mod 也已经不适用于该版本，"部分挂上"不是需要保留的工作状态。
- 保守：给 PatchDef 加一个 `bool required`，AllExpectedPresent 只对 required 行返回 false，其余行在同一个 500ms 循环里反复重试到超时。多 5 行，但保留今天的部分可用性。

收益：消掉一处"离线放行成功、交互却还是封着"的失败模式。这正是本项目"不许静默降级"那条定案针对的形态。

#### c3. autooffline_save.json 的字段映射在读写两侧各写一遍

原文摘录：

```
337      unsigned int version = doc.value("version", 0u);
347        c.id = cj.at("id").get<unsigned int>();
348        c.name = cj.value("name", std::string());
349        const nlohmann::json &presets = cj.at("presets");
352          const nlohmann::json &opts = presets[(size_t)p].at("options");
355          o.key = oj.at("key").get<unsigned int>();
356          o.value = oj.at("value").get<unsigned int>();
357          o.keyName = oj.value("key_name", std::string());
358          o.valueName = oj.value("value_name", std::string());
...
393      cj["id"] = c.id;
394      if (!c.name.empty())
395        cj["name"] = c.name;
401        oj["key"] = o.key;
402        oj["value"] = o.value;
403        if (!o.keyName.empty())
404          oj["key_name"] = o.keyName;
```

判据：八个字段名（version / characters / id / name / presets / options / key / value / key_name / value_name）在两侧各出现一次，"缺省时省略 name、key_name、value_name"这条规则也各写一次。nlohmann 的现成设施就是 ADL 的 `to_json` / `from_json`，写一遍就够，而且这是"有现成库就别自己搓"那条定案的典型场景。

收益：约减 25 行（两侧各约 35 行降到各约 12 行，另加 25 行 to/from），字段名只有一个维护点。改 schema（比如加了"哪个槽位被选中"）时不会出现只改了一侧、下次启动读不回来的情况。

风险：低，但有三处必须原样保留，否则改变语义：一是 `for (int p = 0; p < kPresetCount && p < count; ++p)` 的 `p < count`（短数组不能抛异常）；二是整份失败时 `g_chars.clear()` 并返回 false（现在的"一个角色坏了就整份不读"已经是这样，from_json 抛异常的行为一致）；三是 `dump(2)` 与末尾补的换行。给个片段：

```cpp
static void to_json(nlohmann::json &j, const LoadoutOption &o) {
  j = nlohmann::json{{"key", o.key}, {"value", o.value}};
  if (!o.keyName.empty())  j["key_name"] = o.keyName;
  if (!o.valueName.empty()) j["value_name"] = o.valueName;
}
static void from_json(const nlohmann::json &j, LoadoutOption &o) {
  o.key = j.at("key").get<unsigned int>();
  o.value = j.at("value").get<unsigned int>();
  o.keyName = j.value("key_name", std::string());
  o.valueName = j.value("value_name", std::string());
}
```

（LoadoutPreset 因为固定三槽，from_json 里仍要保留那个上界判断。）

#### c4. 字节比对那趟循环在 AllExpectedPresent 与 LogMissingPatterns 里各写一遍

原文摘录：

```
193  static bool AllExpectedPresent() {
194    for (int i = 0; i < NPATCH; ++i) {
195      const PatchDef &p = g_patches[i];
196      unsigned char cur[8] = {0};
197      if (!SafeReadBytes(g_base + p.rva, cur, p.explen))
198        return false;
199      if (memcmp(cur, p.expected, p.explen) != 0)
200        return false;
206  static void LogMissingPatterns() {
207    for (int i = 0; i < NPATCH; ++i) {
208      const PatchDef &p = g_patches[i];
209      unsigned char cur[8] = {0};
210      unsigned long long addr = g_base + p.rva;
211      if (!SafeReadBytes(addr, cur, p.explen)) {
212        Log("  %-28s @ %llX: unreadable", p.desc, addr);
```

判据：同一趟"读 + memcmp + 报告"，一份返回总布尔、一份打印逐条明细，两处都自己拼地址、自己声明 cur[8]。合成 `static bool CheckPatterns(bool verbose)` 即可，verbose 为假时第一条不符就返回。

收益：约 8 行；一个循环上限。注意它只在启动和超时各跑一次，不是热路径，所以我把优先级排在收益之后面。

风险：无。LogMissingPatterns 现在只在超时时调用，保留这个调用条件即可。

#### c5. Log 一次格式化拆成两趟，还多占 1.2KB 栈

原文摘录：

```
161  static void Log(const char *fmt, ...) {
162    char body[1024];
...
170    char line[1200];
171    _snprintf_s(line, sizeof(line), _TRUNCATE, "[%02d:%02d:%02d] %s", st.wHour, st.wMinute,
172                st.wSecond, body);
173
174    if (g_log) {
175      fputs(line, g_log);
176      fputc('\n', g_log);
177      fflush(g_log);
```

判据：先把正文 vsnprintf 进 body，再整体拷进 line 加时间戳前缀，然后 fputs + fputc。前缀完全可以在一次 fprintf 里带出来，body 保留（vsnprintf 需要它），line 与第二趟拷贝都可以去掉。另外 body 是 1024、line 是 1200，超长时 _TRUNCATE 会截断两次，第一次截断在 1024，第二次没机会发生，多出来的 176 字节是白留的。

收益：约 4 行、每次调用少 1.2KB 栈、少一次 memcpy。Log 会被 RestoreModel / SnapshotModel 从游戏线程调用，栈占用不是零成本。顺带把 `_snprintf_s`（MSVC 专有）去掉，文件里就不再有非标准 CRT 调用。

```cpp
  if (g_log) {
    fprintf(g_log, "[%02d:%02d:%02d] %s\n", st.wHour, st.wMinute, st.wSecond, body);
    fflush(g_log);
  }
```

风险：无。fflush 保留（那是刻意的，见"刻意如此"）。

#### c6. 同一个 1024 起了两个名字

原文摘录：

```
463  constexpr int kRawMaxOptions = 1024;
581  constexpr int kRawMaxRestore = 1024;
```

判据：一个限制"从模型最多读多少条选项"，一个限制"往权威表最多写多少条选项"，是同一个上限的两个方向，值也一致。现在两处各自可调，调一处就会造成"存得下但读不回来"或反之。

收益：1 行，一个旋钮。合成 `kMaxOptions`。

风险：无。

### (d) 冗余状态 / 过度防御

#### d1. 7 处不可达的 orig 空指针守卫，其中两处在每次调用上

原文摘录：

```
549    if (g_edit_orig)
550      g_edit_orig(mgr, slot, charId, key, value);
552    if (g_model_lookup) {
...
665    void *model = g_ctor_orig ? g_ctor_orig(mgr, slot, asset, flag, perkDesc) : nullptr;
749    unsigned int mask = g_maskget_orig ? g_maskget_orig() : 0u;
757    void *ret = g_p3_orig ? g_p3_orig(self, a2, a3) : nullptr;
767    if (g_p6_orig)
768      g_p6_orig(peer, reason);
804    void *ret = g_nameget_orig ? g_nameget_orig(a1, a2) : nullptr;
```

判据：这些函数指针只在"创建且启用都成功"之后才被赋值，而 detour 只有在启用成功后才可能被调用，所以守卫为假的分支在任何执行顺序下都到不了。第 696-699 行更直接：g_model_lookup 等四个函数指针在装 hook 之前就无条件赋值了，第 552 行的守卫恒真。

而且守卫生效时的行为不是"报错退出"而是给出错答案：HookSessionMask 返回 0（等于宣布"没人在会话"）、HookNameGet 返回 nullptr（下游会当空名字处理，意外变成"允许"）、HookModelCtor 返回 nullptr（皮肤恢复整段跳过）。这正是"不许可选钩子/静默降级"那条定案要避免的形态：真出问题时会伪装成"本来就不该生效"。

同一份文件里还有相反的写法作对照：`RawApplyRestore`（606、611、613 行）直接裸调 g_write_auth / g_sync_preset / g_recalc，一个守卫都没有。两套策略并存说明这些守卫是样板而不是设计。

收益：7 个分支、7 行。HookSessionMask 与 HookNameGet 是每次调用都过一遍的（掩码读取与 KillSwitch 名字读取都是高频入口），另外五个在菜单点击与建模时各一次。更重要的是策略统一：要么正常工作，要么在安装阶段就记一行失败日志。

建议：删掉守卫，直接调用。安装失败本来就有 `MH_CreateHook / MH_EnableHook` 的日志，不需要在热路径上再兜一次。若要保留一层保险，放在安装完之后一次性检查（`if (!g_maskget_orig) Log(...)`），而不是每次调用。

风险：低。前提是"detour 只在启用成功后可达"这条不变量成立，而它由 MinHook 的 EnableHook 语义保证。

#### d2. 超时日志固定打 5 字节，实际有 1 字节和 3 字节的条目

原文摘录：

```
217      Log("  %-28s @ %llX: want %02X %02X %02X %02X %02X, have %02X %02X %02X %02X %02X",
218          p.desc, addr, p.expected[0], p.expected[1], p.expected[2], p.expected[3],
219          p.expected[4], cur[0], cur[1], cur[2], cur[3], cur[4]);
```

判据：表里的 explen 分别是 3、5、1、5。补丁 3 只比 1 个字节，日志却打出 5 个，后 4 个是 expected 初始化时补的 0 与 cur 的 0；补丁 1 只比 3 个字节，同样多打 2 个。看日志的人会把幽灵字节当成"要匹配的内容"。

收益：0 行（改成循环后行数持平），但失败日志不再误导。这两行本来就是 0 字节和 3 字节条目唯一的排查入口。

```cpp
    char want[32] = {0}, have[32] = {0};
    for (int k = 0; k < p.explen; ++k) {
      _snprintf_s(want + k * 3, sizeof(want) - k * 3, _TRUNCATE, "%02X ", p.expected[k]);
      _snprintf_s(have + k * 3, sizeof(have) - k * 3, _TRUNCATE, "%02X ", cur[k]);
    }
    Log("  %-28s @ %llX: want %s have %s", p.desc, addr, want, have);
```

（这段在两个带 __try 的函数之外，可以用带析构的对象；但为省事仍用 POD 缓冲。）

#### d3. 截断日志只跳出一层循环，会重复打

原文摘录：

```
642    for (int p = 0; p < kPresetCount; ++p) {
643      for (const LoadoutOption &o : c->presets[p].options) {
644        if (count == kRawMaxRestore) {
645          Log("!! restore: too many values for character %u, truncated", charId);
646          break;
647        }
```

判据：break 只出内层，外层接着进下一个槽位，进去第一条又撞上 count == cap，再打一行一模一样的日志。一个角色最多打三遍。日志重复本身无害，但它让"截断了多少"看起来像三个槽位都截断了。

收益：1 行改动（`break` 换成跳到统一出口，或加一个 `bool full` 在外层判）。属低收益，列出来是因为它同时是 c1/d1 那种"小样板没写干净"的证据。

### (b) 死代码

#### b1. g_p1_orig 只写不读

原文摘录：

```
721  typedef char(__fastcall *P1Fn)(unsigned int);
725  static P1Fn g_p1_orig = nullptr;
733  static char __fastcall HookOfflineFix(unsigned int slot) {
734    (void)slot;
735    return 1;
736  }
860        g_p1_orig = (P1Fn)orig;
```

判据：全文件三处出现，一次定义、一次赋值，没有一处读取。HookOfflineFix 恒返回 1，从不调原函数（第 729-732 行的注释也解释了原函数恒返回 false、只执行一次探测，所以确实不需要跳板）。typedef P1Fn 也只服务这一个变量。

收益：2 行 + 一个不可达赋值分支。改法：按 c1 的表结构，该行的 origOut 直接填 nullptr。已核对 MinHook 允许这样传：`third_party/minhook/include/MinHook.h` 第 110 行写明 `ppOriginal ... This parameter can be NULL`，`hook.c` 第 633 行也有 `if (ppOriginal != NULL)` 的保护。

风险：无。注意不要顺手把 MH_CreateHook 的跳板省掉，那是 hook 本身需要的，只是不返回给调用者。

#### b2. 常量区：一个死宏 + 5 个 #define 与文件其余部分不一致

原文摘录：

```
150  #define WAIT_TOTAL_MS (180 * 1000)
151  #define WAIT_STEP_MS 500
741  #define SESSMASK_GET_RVA 0x447450u
742  #define SESSMASK_SITE_RVA 0x178A8C1u
795  #define NAMEGET_RVA 0x450180u
```

判据：SESSMASK_GET_RVA 无人使用；这个 RVA 在表行、DetourFor、InstallHooks 三处都是直接写的字面量 0x447450u，所以这个宏恰恰证明了 c1 那三重表述。另外四个宏与文件里 20 多个 constexpr（281 行起）并存，与"C++ 书写规范：编译期常量用 constexpr"那条既有约定不一致；NPATCH（147 行）也是 `static const int` 而非 constexpr。WIN32_LEAN_AND_MEAN 属规则里明列的例外，不算。

收益：1 行（死宏），其余是规范对齐，运行时零收益。这一条本身不值得单独开工，跟 c1 一起做时顺手收掉即可。

#### b3. RawReadModel 里 presetStart[1..3] 的清零是死写

原文摘录：

```
485    *charId = 0;
486    presetStart[0] = 0;
487    presetStart[1] = 0;
488    presetStart[2] = 0;
489    presetStart[3] = 0;
...
514      presetStart[p + 1] = n;
```

判据：只要返回 n > 0，第 514 行就把 [1]、[2]、[3] 全部覆盖；返回 0 的两条路径（第 482-490 行 model 为空、497-498 行 presets 为空）调用方 SnapshotModel 都在第 527、531 行提前 return，从不读 presetStart。所以第 487-489 行三行写在任何执行路径上都读不到。[0] 要留（它就是 0 号槽的起点）。

收益：3 行死写。顺带说明调用方第 525 行 `int presetStart[4] = {0, 0, 0, 0};` 的初始化也因此不是必需的，但它便宜，留着无妨。

风险：无。

#### b4. 第 843 行的 hookRva == 0 分支不可达

原文摘录：

```
841    for (int i = 0; i < NPATCH; ++i) {
842      const PatchDef &p = g_patches[i];
843      if (p.hookRva == 0u) {
844        Log("!! hook %s: no hookRva in the table", p.desc);
845        continue;
846      }
847      unsigned long long target = g_base + p.hookRva;
848      void *detour = DetourFor(p.hookRva);
849      if (detour == nullptr) {
```

判据：表里四条 hookRva 全部非零；即使出现零，DetourFor(0) 也返回 nullptr，第 849 行的分支会兜住。一个不可达状态上有两道守卫。并入 c1 后这个字段有了真实含义（0 = 只校验不挂），那时保留一行 `if (!p.hookRva) continue;` 是有意义的；在现有结构下它是纯死分支。

收益：4 行。

## 检查过、确认没问题的

- 热路径复杂度。七个挂钩体逐个量过：HookOfflineFix 恒返回常量；HookSessionMask / HookNameGet / HookProfileCtor / HookLoadoutEdit / HookModelCtor 都是 O(1) 加一次 `_ReturnAddress()` 比较；HookReport 一次比较。没有循环、没有分配。唯一按规模展开的是 RawReadModel 的双层遍历（最多 3 槽 × 桶数 × 桶内节点，且有 kMapMaxBuckets 双重上限），触发点是菜单里点一次，不是每帧。所以"复杂度能不能优化"这一节除了 e1 那个轮询没有别的可动项，不必再找。
- 存盘路径的文件 IO（SaveStore 386-442）。已经是"写 .tmp、检查 fclose、MoveFileEx 替换、失败删 .tmp"的完整原子替换，没有手搓可以替换成 `ReplaceFile` 的收益（MoveFileEx 带 MOVEFILE_REPLACE_EXISTING 在这里够用，而 ReplaceFile 多出来的备份语义用不上）。fread 循环（324-329）换成 istreambuf_iterator 只会更慢。
- 启动等待（909-919）的轮询周期与总量（500ms / 180s）没有重复计算，`AllExpectedPresent` 里每一次读都是 ≤8 字节。
- 全局量清点。g_log、g_dir、g_base、g_p3_value、g_chars、g_save_dirty、七个 orig、三个 g_pX_orig、g_edit_orig/g_ctor_orig、g_model_lookup/g_write_auth/g_sync_preset/g_recalc、g_fakeNameObj/g_emptyName —— 除 g_p1_orig（b1）与 g_p1 的 typedef 外，每个都至少有一处读。
- 三条 helper-scripts 与本方向无关的项没有报：它们是部署与清档脚本，不参与这条 DLL 的运行时代码。build.bat 唯一相关的一点写进"不值得动"第 8 条。

## 看着重复或多余、但判定为刻意如此的

- 三个函数只允许 POD 进 __try（181、480、600 行那句话，以及 SafeReadBytes / RawReadModel / RawApplyRestore 三个外壳）。这是 MSVC C2712 的硬约束：函数里一旦有带析构的对象就不能用 __try。不是"没抽成模板"，而是抽不了。
- 每条日志都 fflush（177 行）。掉线或崩溃前的最后一行要留在盘上，代价是每次一行 write，量级可忽略。
- Worker 末尾的 `for (;;)`（938 行）永不退出。DLL 不卸载，线程没有退出路径，写 `while (g_running)` 反而会多一个永远为真的全局量。
- g_patches 同时存 rva 与 hookRva 两个地址（42-48 行）。这本身不是冗余：#2/#3/#6 的"已知原始字节的那一点"与"要挂的函数入口"确实不是同一处，这是逆向数据本身的性质。冗余的是 hookRva 又被两个 switch 各写了一遍（c1）。
- 表里 patch 4 只有注释、没有数据行（113-127 行）。停用条目刻意不参与等待集，否则会永远等一个不该等的字节。
- AllExpectedPresent 与 LogMissingPatterns 在超时路径上把同一批字节读两遍。只在超时那一次发生，换的是清晰的逐条失败输出，按 c4 合并后这个"重复"自然消失，但即使不合并也不构成运行时浪费。
- 三个 1024 项 POD 数组放在栈上（523 行 8KB、640 行 12KB）。只在菜单改动与建模时各一次，且缩小上限会把"截断"从不可能变成可能，见"不值得动"第 2 条。

## 看着该优化、但判定为不值得动的

1. FindSavedCharacter（620-626）与 SavePutCharacter（306-314）的线性扫。
   规模：g_chars 的元素个数就是存档里的角色数，与游戏的角色数量同级（几十）。频率：前者每个玩家槽建模一次，后者每次菜单改动一次。
   为什么不值得动：单次几十次整数比较，折合纳秒级。改成 lower_bound 需要引入"g_chars 始终按 id 有序"这条隐式不变量，而现在 SaveLoad 之后并不排序（只有 SaveStore 前调 SaveSort），等于给读路径加一个必须先满足的前提。风险不为零、收益为零。
2. 栈上两个 1024 项数组的大小（463 与 581 行）。
   为什么不值得动：真正的规模是每个角色三个槽位里几条到几十条选项，1024 是"绝不可能撞上"的余量；把它降到 64 能省 14KB 栈，但栈占用是瞬时的，而截断的风险从"不可能"变成"可能"。
3. SafeReadBytes 逐字节 volatile 读（183-185 行）换成 __try 里一次 memcpy。
   为什么不值得动：只在启动时调用 4 次，每次 ≤8 字节，省不到 100 纳秒；逐字节写法的好处是"读到第几个字节出错"这件事在形态上是明确的。
4. model+216 被读三次（492、604、631 行）。
   为什么不值得动：共享同一个 kModelCharId 常量，不存在分叉风险；为省一次解引用去给 RawApplyRestore 增加一个 charId 参数，会打破"一个函数一次 SEH"的现有布局。另外 631 行那次在 SEH 之外，属正确性方向（见交叉线索），不在这里改。
5. 11 个函数指针全局量合成一个 struct。
   为什么不值得动：纯口味，没有功能收益，改名类的建议不在本方向。
6. DirOfSelf（880-886 行）换 std::filesystem。
   为什么不值得动：要么改 /std 版本（影响可复现构建的既有基线），要么链 shlwapi 用 PathRemoveFileSpecA（多一个依赖），换回来 4 行。不值得。
7. 时间戳换 GetTimeFormatA。
   为什么不值得动：比一次 fprintf 的前缀更绕，还要处理 locale 与缓冲区，c5 的改法已经把那趟多余拷贝去掉了。
8. build.bat 的告警级别（第 69 行 /W3）。
   /W4 能顺手报出"静态函数无人引用"这类死代码（本方向以后能靠工具兜底），但 MinHook 的三个 .c 与 nlohmann 的头在同一趟 cl 调用里会带噪声，需要拆成两次编译。拆开是构建脚本的事，与本次优化无关，本轮不建议动；记在这里是给"死代码靠什么被发现"留个线索。

## 交叉线索

- 第 18-20 行表头写"g_patches 表里列的条目全部挂在函数入口（当前为 #1 ... #5 ...）"，表里没有 #5 这一行（注释方向）。
- 第 40 行"以及挂钩前确认函数没认错"：InstallHooks 的循环不做任何 hook 点校验，只有 AllExpectedPresent 在另一个地址上校验（注释方向；也是 c1、c2 的判据之一）。
- 第 239-247 行 LoadP3Value 放行 0..255，而注释明写合法枚举只有 0..5（正确性）。
- 第 631 行在 SEH 之外解引用 model+216（正确性 / 线程与内存安全）。
- 第 501、505 行 kMapMaxBuckets 同时当"桶数上限"和"单个桶的节点上限"两个语义用（正确性）。
- 第 751 行 `mask |= 0xFFu` 固定只补低 8 位，而掩码按槽位索引（正确性）。
- 第 936-944 行 g_save_dirty 是跨线程裸 bool；e1 的事件改写顺手消除（线程与内存安全）。
- 第 894-895 行 fopen 失败时不检查返回值，此后所有日志静默丢弃（正确性：这正是"静默降级"形态）。
- 第 882-885 行 GetModuleFileNameA 用 MAX_PATH，超长路径会被截断（正确性）。
- 第 169-177 行 Log 被多个线程调用且无同步，行可能交错（线程与内存安全）。
- 第 44 行 expected[8] 与第 217 行固定读 5 个字节：表里没有任何 explen > 5 的条目，8 字节的余量目前是空的（低；若将来加长模式需同步改日志，见 d2）。
