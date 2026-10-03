// ============================================================================
//  AutoOffline.dll  --  BFN 启动时自动放行连接(不做任何注入)
// ----------------------------------------------------------------------------
//  部署方式: 编译产物改名为 RtWorkQ.dll, 放进游戏目录。
//
//  原理: DLL 搜索顺序劫持。游戏进程按裸名 LoadLibrary("RtWorkQ.dll"),
//        Windows 先搜程序所在目录, 因此加载到本文件。DllMain 即入口,
//        不需要任何外部注入器。
//        (系统那份 RtWorkQ.dll 位于 System32, 有 37 个导出; 本 DLL 一个都不导出。
//         游戏实测不调用 RtWorkQ 的任何函数, 所以没有影响。)
//
//  启动时加载可能早于游戏代码解密(exe 加了壳, .sdata 运行时才解开)。
//  此时打补丁会写进仍处于加密状态的数据, 解密后即被覆盖, 补丁静默失效。因此本
//  DLL 先轮询等待补丁点的原始字节出现(字节吻合 = 已解密), 然后再打; 等不到就不打,
//  只记日志。
//
//  设计上只做三件事: 等解密 -> 打补丁 -> 结束。
//  没有开关文件、没有热键、没有探针、没有内存 dump。
//  g_patches 表里列的补丁全部应用(当前为 #1 OfflineFix 与 #3 clientType;
//  #2 与 #4 已注释停用)。增删补丁直接改表, 然后重启游戏。
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>

// --------------------------------------------------------------------------
//  内存补丁表(与 PvZBCurrencies.dll 逐字节一致,已实证匹配本 build)
//  expected = 该地址原本的字节, 用来判断代码是否已解密
// --------------------------------------------------------------------------
struct PatchDef {
  unsigned long long addr;
  unsigned char bytes[8];
  int len;
  unsigned char expected[8];
  int explen;
  const char *desc;
};

static const PatchDef g_patches[] = {
    {0x14156FA30ull, {0xB0, 0x01, 0xC3}, 3, {0x48, 0x83, 0xEC}, 3, "OfflineFix #1"},
    // ---- 补丁 2: 把条件写入改成无条件写入 ----
    //  原指令: setb byte[rsp+21h]        ; 按条件置 0 或 1
    //  改为:   mov  byte[rsp+21h], 1     ; 恒置 1
    //  单独关掉本补丁试过: 游戏能进, 主线照样进不去。即本补丁不挡主线, 但也没能
    //  解决主线, 实际作用尚未确认。
    {0x14178A8EDull,
     {0xC6, 0x44, 0x24, 0x21, 0x01},
     5,
     {0x0F, 0x92, 0x44, 0x24, 0x21},
     5,
     "mov byte[rsp+21h],1"},
    // ---- 补丁 3: UserProfileInfo+0x130 = clientType (必需) ----
    //
    //  位置: `UserProfileInfo` 的构造函数 sub_142546450 内
    //     1425464EE  c7 86 30 01 00 00 05 00 00 00   mov dword [rsi+130h], 5
    //                                               ^ 0x1425464F4 即被改写的字节
    //  类名串 0x14399FFE8 = "UserProfileInfo", 虚表 off_14399FFF8。
    //
    //  该字段的身份来自类型描述符 (sub_14254A3A0 -> off_1447CD8F0 字段表):
    //  UserProfileInfo 的第 12 个字段名为 "clientType", 类型 `Blaze::ClientType`,
    //  字段表记录的偏移恰为 0x130, 与构造函数写入的 [rsi+130h] 吻合。
    //
    //  `Blaze::ClientType` 枚举 (类型描述符 @0x1447AD4F0, 成员表 @0x1447AD420):
    //      0 = CLIENT_TYPE_GAMEPLAY_USER          普通游戏客户端
    //      1 = CLIENT_TYPE_HTTP_USER              网页/HTTP 客户端
    //      2 = CLIENT_TYPE_DEDICATED_SERVER       专用服务器
    //      3 = CLIENT_TYPE_TOOLS                  工具
    //      4 = CLIENT_TYPE_LIMITED_GAMEPLAY_USER  受限的游戏客户端
    //      5 = CLIENT_TYPE_INVALID                无效
    //
    //  构造函数把 clientType 初始化为 5 (INVALID), 即"身份未知"的占位值。正常流程
    //  由服务器在登录时告知客户端真实身份; 离线下拿不到, 于是永远是 5, 连接被拒,
    //  表现为"连不上 EA 服务器"。这是本补丁必须启用的原因。
    //  枚举最大只到 5, 因此 7 / 8 属于越界值, 写入必然无效。
    //
    //  实测过的取值 (只有 1 能进游戏):
    //      0 = GAMEPLAY_USER          进不去
    //      1 = HTTP_USER              唯一能进入游戏的取值 (但皮肤/天赋每次重置)
    //      4 = LIMITED_GAMEPLAY_USER  进不去
    //      5 = INVALID                连不上 EA 服务器 (即不打补丁时的原值)
    //      7 / 8                      不在枚举内, 无效
    //  规律: 凡是"游戏客户端"身份 (0 / 4) 都进不去, 只有"非游戏客户端"身份 (1) 能进。
    //  即离线状态下无法以游戏客户端身份通过校验; 这与"皮肤/天赋存不下来"很可能是
    //  同一个根因。
    //
    //  2 / 3 (DEDICATED_SERVER / TOOLS) 尚未试过, 但它们更不像会携带玩家的 loadout。
    //
    //  取值由游戏目录下的 `autooffline_p3.txt` 决定, 默认 1。
    {0x1425464F4ull, {0x01}, 1, {0x05}, 1, "UserProfileInfo+130h = clientType"},
    // ---- 补丁 4: 放行一条被补丁 1 抑制的 Blaze RPC (已停用) ----
    //
    //  sub_141775E00(玩家槽) 向某个玩家槽发送"会话更新"RPC:
    //      经 sub_1415C92A0 -> sub_1424A8E50 (Blaze 连接对象, 载荷 112 字节)
    //      完成回调 sub_14176D3C0 处理 Blaze 状态码 (0x00040004 成功 / 0x00980004 失败)
    //  函数开头:
    //      if ( sub_14156FA30() || *(DWORD*)(v5 + 88) ) { *(DWORD*)(this + 48) = 2; }
    //      else { ...发送 RPC... }
    //  补丁 1 使该判断恒走"直接返回"分支, RPC 永远不发送。
    //
    //  皮肤/天赋是服务器上的 24 字节 blob (loadout), 客户端只负责搬运, 推测随这条
    //  RPC 上传。本补丁只放行这一个调用点, 其余 6 个照旧抑制。
    //      call sub_14156FA30  ->  xor eax,eax ; nop x3
    //
    //  当前停用: 与补丁 3 一并注释, 使 g_patches 只剩补丁 1 一条, 恢复原始行为
    //  (补丁 1 继续抑制全部 7 个调用点, 含这一个)。
    // {
    // 0x141775E4Aull,
    //     {0x31, 0xC0, 0x90, 0x90, 0x90},
    //     5,
    //     {0xE8, 0xE1, 0x9B, 0xDF, 0xFF},
    //     5,
    //     "release RPC sub_141775E00"},
};

// --------------------------------------------------------------------------
//  补丁 1 为什么是 B0 01 C3  (2026-09-17 逆向 g_patches[0] 得到)
//
//  原函数:
//      14156FA30  48 83 EC 28      sub  rsp,28h
//      14156FA34  E8 F7 E5 FF FF   call sub_14156E030      <- 副作用(疑似启动拦截)
//      14156FA39  32 C0            xor  al,al              <- 本来就恒返回 false
//      14156FA3B  48 83 C4 28      add  rsp,28h
//      14156FA3F  C3               ret
//
//  注意: 它本来就返回 false。社区补丁改成 `mov al,1; ret`, 在跳过 call 的同时
//    把返回值也翻成了 true,于是所有调用者都走另一条分支。反编译一个调用者
//    (sub_1417CE1A0, 给条目生成状态字符串再 fire 事件)后可见:
//        if (sub_14156FA30() || ...) { if (v7) return 0; }
//        if (sub_14156FA30())        { if (!v7) return 0; }
//    强制 true 之后这两条合起来 = 无条件 return 0, 整个函数被废掉。
// --------------------------------------------------------------------------
static const int NPATCH = (int)(sizeof(g_patches) / sizeof(g_patches[0]));

// 轮询参数:最多等 3 分钟,每 500ms 试一次
#define WAIT_TOTAL_MS (180 * 1000)
#define WAIT_STEP_MS 500

static FILE *g_log = nullptr;
static std::string g_dir;

// --------------------------------------------------------------------------
//  日志(只写文件,无控制台;fopen "w" = 每次运行清空)
// --------------------------------------------------------------------------
static void Log(const char *fmt, ...) {
  char body[1024];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(body, sizeof(body), fmt, ap);
  va_end(ap);

  SYSTEMTIME st;
  GetLocalTime(&st);
  char line[1200];
  _snprintf_s(line, sizeof(line), _TRUNCATE, "[%02d:%02d:%02d] %s", st.wHour, st.wMinute,
              st.wSecond, body);

  if (g_log) {
    fputs(line, g_log);
    fputc('\n', g_log);
    fflush(g_log);
  }
}

// SEH 读内存的函数里不能有带析构的 C++ 对象(MSVC C2712),只用 POD
static bool SafeReadBytes(unsigned long long addr, unsigned char *out, int n) {
  __try {
    for (int i = 0; i < n; ++i)
      out[i] = *(volatile unsigned char *)(addr + i);
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

// 所有补丁点的原始字节是否都已就位(= 代码已解密)。
static bool AllExpectedPresent() {
  for (int i = 0; i < NPATCH; ++i) {
    const PatchDef &p = g_patches[i];
    unsigned char cur[8] = {0};
    if (!SafeReadBytes(p.addr, cur, p.explen))
      return false;
    if (memcmp(cur, p.expected, p.explen) != 0)
      return false;
  }
  return true;
}

// --------------------------------------------------------------------------
//  补丁 3 的那个字节做成可调, 不用重编译就能扫值
//
//  补丁 3 改的是 `Blaze::Authentication::UserProfileInfo+0x130` = `clientType`。
//  它是 `Blaze::ClientType` 枚举, 合法值只有 0..5 六个 (含义见上面那张表)。
//  默认 = 1 (CLIENT_TYPE_HTTP_USER), 实测唯一能进入游戏的取值。
//
//  游戏目录下放个 `autooffline_p3.txt`, 里面写个 0..5 的十进制数即可。
//  文件不存在 = 用 0x01。
// --------------------------------------------------------------------------
static unsigned char g_p3_value = 0x01;
#define P3_ADDR 0x1425464F4ull

static void LoadP3Value() {
  std::string path = g_dir + "\\autooffline_p3.txt";
  FILE *f = fopen(path.c_str(), "r");
  if (!f) {
    Log("patch3 value: no %s -> using 0x%02X", path.c_str(), g_p3_value);
    return;
  }
  int v = -1;
  if (fscanf(f, "%i", &v) != 1 || v < 0 || v > 255) {
    Log("patch3 value: bad content in %s -> using 0x%02X", path.c_str(), g_p3_value);
  } else {
    g_p3_value = (unsigned char)v;
    Log("patch3 value <- %s = 0x%02X (%d)", path.c_str(), g_p3_value, v);
  }
  fclose(f);
}

static void ApplyPatches() {
  for (int i = 0; i < NPATCH; ++i) {
    const PatchDef &p = g_patches[i];

    unsigned char blob[8] = {0};
    memcpy(blob, p.bytes, p.len);
    if (p.addr == P3_ADDR)
      blob[0] = g_p3_value;  // 补丁 3 的字节来自 autooffline_p3.txt

    DWORD old = 0;
    if (!VirtualProtect((LPVOID)p.addr, p.len, PAGE_EXECUTE_READWRITE, &old)) {
      Log("!! VirtualProtect FAILED @ %llX (%s) err=%lu", p.addr, p.desc, GetLastError());
      continue;
    }
    memcpy((void *)p.addr, blob, p.len);
    VirtualProtect((LPVOID)p.addr, p.len, old, &old);

    bool ok = (memcmp((void *)p.addr, blob, p.len) == 0);
    Log("Patch @ %llX  %s  %s   byte[0]=0x%02X", p.addr, ok ? "OK  " : "FAIL", p.desc, blob[0]);
  }
}

// --------------------------------------------------------------------------
//  网络超时改成超大值(2026-09-18)
// --------------------------------------------------------------------------
//  为什么不在 EBX 里改:`ServerSettings` / `PVZServerSettings` 是 SystemSettings,
//  运行时建的对象,**没有对应的 EBX 资产** —— 只能在运行时写进去。
//
//  取法:`0x14421CFD0` 是「类型 -> 实例」哈希表,`sub_14046F430(map, key)` 是查找函数。
//      表结构(反编译坐实):
//          v5 = *(u32*)(map + 208)            桶数
//          v6 = *(u64*)(map + 200)            桶数组
//          v7 = *(u64**)(v6 + 8*(key % v5))   桶; 串链是 {key, value, next}
//          return v7[1]                       value = 实例
//      key 是 TypeInfo 的地址, TypeInfo 前 0x70 字节里存着类型名的指针。
//  这里不猜 key, 而是直接遍历整张表按类型名匹配, 命中才写 —— 写错容器的风险为零。
//
//  字段偏移来自 SDK 的 ebx_offset(Float32):
//      GameplayClientServer.ServerSettings  IngameTimeout          +72 (0x48)
//                                           LoadingTimeout         +80 (0x50)
//      PVZShared.PVZServerSettings          ClientInActivityTimeOut +16
//                                           InActivityTimeOut      +20
// --------------------------------------------------------------------------
#define G_TYPE_INSTANCE_MAP 0x14421CFD0ull
#define TIMEOUT_SECONDS 126000.0f  // ~35 小时

static bool Rd64(unsigned long long a, unsigned long long *out) {
  __try {
    *out = *(volatile unsigned long long *)a;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

static bool Rd32(unsigned long long a, unsigned int *out) {
  __try {
    *out = *(volatile unsigned int *)a;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

static bool RdStr(unsigned long long a, char *out, int cap) {
  __try {
    for (int i = 0; i < cap - 1; ++i) {
      char c = *(volatile char *)(a + i);
      out[i] = c;
      if (!c)
        return true;
    }
    out[cap - 1] = 0;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    out[0] = 0;
    return false;
  }
}

static bool LooksLikeTypeName(const char *s) {
  int n = 0;
  for (; s[n]; ++n) {
    if (n >= 80)
      return false;
    if ((unsigned char)s[n] < 0x20 || (unsigned char)s[n] > 0x7E)
      return false;
  }
  return n >= 4 && strchr(s, ' ') == nullptr;  // 类型名不带空格
}

// 从类型信息里扫出类型名。两种形态都试:
//   (a) 槽里存的是指针, 指向字符串
//   (b) 槽里直接就是字符串本身
// 前 12 条实测都是 (b) —— fb::string 对短名字走 SSO, 字符直接存在对象里,
// 所以内联那种才是常态。
static bool CopyName(const char *buf, char *out, int cap) {
  for (int i = 0; i < cap - 1 && buf[i]; ++i)
    out[i] = buf[i], out[i + 1] = 0;
  return true;
}

static bool ScanForName(unsigned long long base, char *out, int cap) {
  for (unsigned long long off = 0; off < 0x100; off += 8) {
    char buf[96];
    unsigned long long p = 0;
    if (Rd64(base + off, &p) && p >= 0x10000 && RdStr(p, buf, sizeof(buf)) &&
        LooksLikeTypeName(buf))
      return CopyName(buf, out, cap);
    if (RdStr(base + off, buf, sizeof(buf)) && LooksLikeTypeName(buf))
      return CopyName(buf, out, cap);
  }
  return false;
}

// 表里每条 entry 的 key 不是类型描述符本身: 它第 0 个字是个指针, 指向真正的
// 描述符。所以要多解一层指针。
static bool ReadTypeName(unsigned long long ti, char *out, int cap) {
  out[0] = 0;
  if (ScanForName(ti, out, cap))
    return true;
  unsigned long long lvl1 = 0;
  if (Rd64(ti, &lvl1) && lvl1 >= 0x10000 && lvl1 != ti && ScanForName(lvl1, out, cap))
    return true;
  return false;
}

static void WriteFloat(unsigned long long addr, float v, const char *what, bool verbose) {
  DWORD old = 0;
  if (!VirtualProtect((LPVOID)addr, 4, PAGE_EXECUTE_READWRITE, &old)) {
    if (verbose)
      Log("   !! %s @ %llX: VirtualProtect failed (%lu)", what, addr, GetLastError());
    return;
  }
  memcpy((void *)addr, &v, 4);
  VirtualProtect((LPVOID)addr, 4, old, &old);
  if (verbose)
    Log("   %s <- %.1f  @ %llX", what, v, addr);
}

// 各类型的字段偏移不同, 必须按类型精确选择 —— 写错会覆盖别的字段甚至越界:
//   GameplayClientServer.ServerSettings   size 96, 自有字段从 +32 起 -> +72 / +80
//   PVZShared.PVZServerSettings           size 52, 自有字段 12..49   -> +16 / +20
//   (PVZDedicatedServerSettings 布局未知, 一律不碰)
static bool KnownLayout(const char *name, unsigned long long *oA, unsigned long long *oB,
                        const char **nA, const char **nB) {
  if (strcmp(name, "ServerSettings") == 0) {
    *oA = 72;
    *oB = 80;
    *nA = "IngameTimeout";
    *nB = "LoadingTimeout";
    return true;
  }
  if (strcmp(name, "PVZServerSettings") == 0) {
    *oA = 16;
    *oB = 20;
    *nA = "ClientInActivityTimeOut";
    *nB = "InActivityTimeOut";
    return true;
  }
  return false;
}

// 走一遍「类型 -> 实例」表。
//   返回 false = 表还没建好(调用方稍后重试); true = 走完了。
//   hit = 匹配到的容器数; ok = 其中写完并读回验证通过的个数。
//   命中即当场打印原值再写入, 不分"先探测、后正式"两遍 —— 那样探测那一遍什么
//   都看不到, 出问题时日志是空的, 无法诊断。
static bool WalkTypeMap(int *seenOut, int *hitOut, int *okOut, unsigned int *nbOut, bool verbose) {
  *seenOut = 0;
  *hitOut = 0;
  *okOut = 0;
  *nbOut = 0;

  unsigned long long map = 0;
  if (!Rd64(G_TYPE_INSTANCE_MAP, &map) || !map)
    return false;

  unsigned long long buckets = 0;
  unsigned int nb = 0;
  if (!Rd64(map + 200, &buckets) || !buckets || !Rd32(map + 208, &nb) || !nb || nb > 100000)
    return false;
  *nbOut = nb;

  float wf = TIMEOUT_SECONDS;
  unsigned int want = 0;
  memcpy(&want, &wf, 4);

  int seen = 0, hit = 0, ok = 0;
  for (unsigned int i = 0; i < nb; ++i) {
    unsigned long long e = 0;
    if (!Rd64(buckets + 8ull * i, &e))
      continue;
    for (int guard = 0; e && guard < 2048; ++guard) {
      unsigned long long key = 0, val = 0;
      if (Rd64(e, &key) && Rd64(e + 8, &val) && key >= 0x10000 && val >= 0x10000) {
        char name[96];
        if (ReadTypeName(key, name, sizeof(name))) {
          ++seen;
          unsigned long long oA = 0, oB = 0;
          const char *nA = nullptr, *nB = nullptr;
          if (strstr(name, "ServerSettings") && KnownLayout(name, &oA, &oB, &nA, &nB)) {
            ++hit;
            if (verbose) {
              Log("   [%s]  container=0x%llX", name, val);
              float cur = 0.0f;
              if (Rd32(val + oA, (unsigned int *)&cur))
                Log("      was %-22s = %.1f", nA, cur);
              if (Rd32(val + oB, (unsigned int *)&cur))
                Log("      was %-22s = %.1f", nB, cur);
            }
            WriteFloat(val + oA, TIMEOUT_SECONDS, nA, verbose);
            WriteFloat(val + oB, TIMEOUT_SECONDS, nB, verbose);
            unsigned int wa = 0, wb = 0;
            if (Rd32(val + oA, &wa) && Rd32(val + oB, &wb) && wa == want && wb == want)
              ++ok;
            else if (verbose)
              Log("      !! read-back mismatch on this container");
          } else if (verbose && strstr(name, "ServerSettings")) {
            Log("   [%s]  skipped (layout unknown - not touching it)", name);
          }
        }
      }
      unsigned long long next = 0;
      if (!Rd64(e + 16, &next))
        break;
      e = next;
    }
  }
  *seenOut = seen;
  *hitOut = hit;
  *okOut = ok;
  return true;
}

// 一次性诊断: 打印表里前 N 条的 key/val, 以及 key 前 0x70 字节里能读成字符串的槽。
// 用于确认 key 是不是 TypeInfo、名字指针位于第几个字节。
static void DumpTypeEntries(int maxN) {
  Log("   --- dumping first %d entries ---", maxN);
  unsigned long long map = 0;
  if (!Rd64(G_TYPE_INSTANCE_MAP, &map) || !map) {
    Log("   (map is null)");
    return;
  }
  unsigned long long buckets = 0;
  unsigned int nb = 0;
  if (!Rd64(map + 200, &buckets) || !buckets || !Rd32(map + 208, &nb) || !nb || nb > 100000) {
    Log("   (bad map shape: buckets=0x%llX nb=%u)", buckets, nb);
    return;
  }

  int shown = 0;
  for (unsigned int i = 0; i < nb && shown < maxN; ++i) {
    unsigned long long e = 0;
    if (!Rd64(buckets + 8ull * i, &e))
      continue;
    for (int g = 0; e && g < 64 && shown < maxN; ++g) {
      unsigned long long key = 0, val = 0;
      if (Rd64(e, &key) && Rd64(e + 8, &val)) {
        ++shown;
        Log("   #%-2d key=%016llX  val=%016llX", shown, key, val);
        if (shown <= 6) {  // 前 6 条给 key 的原始视图, 看布局用
          for (unsigned long long r = 0; r < 0x40; r += 16) {
            unsigned char row[16];
            char hex[64], asc[20];
            if (!SafeReadBytes(key + r, row, 16))
              break;
            for (int q = 0; q < 16; ++q)
              _snprintf_s(hex + q * 3, 4, _TRUNCATE, "%02X ", row[q]);
            for (int q = 0; q < 16; ++q)
              asc[q] = (row[q] >= 0x20 && row[q] < 0x7F) ? (char)row[q] : '.';
            asc[16] = 0;
            Log("        key+%02llX  %s |%s|", r, hex, asc);
          }
          // 再解一层指针 —— 名字多半在 *(key) 里
          unsigned long long lv1 = 0;
          if (Rd64(key, &lv1) && lv1 >= 0x10000 && lv1 != key) {
            Log("        *(key) = %016llX", lv1);
            for (unsigned long long r = 0; r < 0x40; r += 16) {
              unsigned char row[16];
              char hex[64], asc[20];
              if (!SafeReadBytes(lv1 + r, row, 16))
                break;
              for (int q = 0; q < 16; ++q)
                _snprintf_s(hex + q * 3, 4, _TRUNCATE, "%02X ", row[q]);
              for (int q = 0; q < 16; ++q)
                asc[q] = (row[q] >= 0x20 && row[q] < 0x7F) ? (char)row[q] : '.';
              asc[16] = 0;
              Log("        [*(key)]+%02llX  %s |%s|", r, hex, asc);
            }
          }
        }
        for (unsigned long long off = 0; off < 0x70; off += 8) {
          unsigned long long p = 0;
          if (!Rd64(key + off, &p) || p < 0x10000)
            continue;
          char buf[80];
          if (!RdStr(p, buf, sizeof(buf)))
            continue;
          int n = 0;
          bool pr = true;
          for (; buf[n]; ++n) {
            if (n >= 72 || (unsigned char)buf[n] < 0x20 || (unsigned char)buf[n] > 0x7E) {
              pr = false;
              break;
            }
          }
          if (pr && n >= 4)
            Log("        key+0x%02llX -> \"%s\"", off, buf);
        }
      }
      unsigned long long nx = 0;
      if (!Rd64(e + 16, &nx))
        break;
      e = nx;
    }
  }
  Log("   --- end dump (%d shown) ---", shown);
}

static void BumpTimeouts() {
  Log("");
  Log("---- network timeouts -> %.0f s ----", TIMEOUT_SECONDS);

  // 不判断"表什么时候建好", 而是持续写入, 直到连续 10 秒每个容器都能读回目标值。
  // 好处: 一是不需要判断就绪时机; 二是自带验证 —— 值若被重置, 稳定计数即清零并重写。
  const DWORD WATCH_S = 300;

  DWORD t0 = GetTickCount();
  int stable = 0;
  bool logged = false, dumped = false, everHit = false, lastReady = false;
  int lastSeen = -1;

  for (int attempt = 0;; ++attempt) {
    int seen = 0, hit = 0, ok = 0;
    unsigned int nb = 0;
    bool ready = WalkTypeMap(&seen, &hit, &ok, &nb, !logged);  // 头一次命中才打细节

    // 表第一次起来时, 把前几条的真实形状打出来(只做一次)
    if (ready && !dumped) {
      dumped = true;
      DumpTypeEntries(12);
    }

    if (hit > 0) {
      everHit = true;
      if (!logged) {
        logged = true;
        Log("   writing...");
      }
      if (ok == hit)
        ++stable;  // 每个匹配到的容器都写进去了, 且读回一致
      else
        stable = 0;  // 有容器被重置(或写不进) -> 重新数
    } else {
      stable = 0;
    }

    DWORD el = (GetTickCount() - t0) / 1000;

    if (stable >= 10) {
      Log("   stable at %.0f for %d s -> done (%lu s total)", TIMEOUT_SECONDS, stable,
          (unsigned long)el);
      return;
    }

    // 心跳: 状态变了就打, 否则每 10 秒一次
    if (ready != lastReady || seen != lastSeen || (attempt % 10) == 0) {
      if (!ready)
        Log("   [%3lus] map ptr at 0x%llX is NULL - not built yet", (unsigned long)el,
            G_TYPE_INSTANCE_MAP);
      else if (hit == 0)
        Log("   [%3lus] table up (buckets=%u, %d named types) - no match yet", (unsigned long)el,
            nb, seen);
      else
        Log("   [%3lus] written; waiting for it to hold (stable %d/10 s)", (unsigned long)el,
            stable);
      lastReady = ready;
      lastSeen = seen;
    }

    if (el >= WATCH_S) {
      Log("   !! gave up after %lu s (map %s, matches %s)", (unsigned long)el,
          lastReady ? "up" : "never built", everHit ? "found" : "none");
      return;
    }
    Sleep(1000);
  }
}

static std::string DirOfSelf(HMODULE self) {
  char p[MAX_PATH] = {0};
  GetModuleFileNameA(self, p, MAX_PATH);
  std::string s(p);
  size_t k = s.find_last_of("\\/");
  return (k == std::string::npos) ? std::string(".") : s.substr(0, k);
}

// --------------------------------------------------------------------------
//  等代码解密 -> 打补丁 -> 结束
// --------------------------------------------------------------------------
static DWORD WINAPI Worker(LPVOID self) {
  g_dir = DirOfSelf((HMODULE)self);

  std::string logPath = g_dir + "\\autooffline_log.txt";
  g_log = fopen(logPath.c_str(), "w");  // "w" = 每次运行清空

  Log("========================================================");
  Log("AutoOffline loaded (as RtWorkQ.dll). Dir: %s", g_dir.c_str());
  LoadP3Value();
  Log("Waiting for the game code to be decrypted before patching...");

  DWORD t0 = GetTickCount();
  bool ready = false;
  for (;;) {
    if (AllExpectedPresent()) {
      ready = true;
      break;
    }
    if (GetTickCount() - t0 >= WAIT_TOTAL_MS)
      break;
    Sleep(WAIT_STEP_MS);
  }

  if (!ready) {
    Log("!! Gave up after %lu s: the expected original bytes never appeared.",
        (unsigned long)((GetTickCount() - t0) / 1000));
    Log("!! NOTHING was patched.");
    Log("========================================================");
    return 0;
  }

  Log("Code is decrypted (byte patterns matched) after %lu s.",
      (unsigned long)((GetTickCount() - t0) / 1000));
  ApplyPatches();
  BumpTimeouts();
  Log("Done.");
  Log("========================================================");
  return 0;
}

BOOL WINAPI DllMain(HINSTANCE self, DWORD reason, LPVOID) {
  if (reason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(self);
    HANDLE h = CreateThread(nullptr, 0, Worker, self, 0, nullptr);
    if (h)
      CloseHandle(h);
  }
  return TRUE;
}
