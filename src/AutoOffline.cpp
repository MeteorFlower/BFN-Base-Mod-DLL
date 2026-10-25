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
//  g_patches 表里列的补丁全部应用(当前为 #1 OfflineFix、#2 flag、#3 clientType、
//  #5 interaction kill switch、#6 client inactivity kick; #4 已注释停用)。
//  增删补丁直接改表, 然后重启游戏。
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>

// --------------------------------------------------------------------------
//  内存补丁表(与 PvZBCurrencies.dll 逐字节一致,已实证匹配本 build)
//  rva      = 相对主模块基址的偏移, 运行时加基址得到绝对地址
//  expected = 该地址原本的字节, 用来判断代码是否已解密
// --------------------------------------------------------------------------
struct PatchDef {
  unsigned int rva;
  unsigned char bytes[8];
  int len;
  unsigned char expected[8];
  int explen;
  const char *desc;
};

static const PatchDef g_patches[] = {
    {0x156FA30u, {0xB0, 0x01, 0xC3}, 3, {0x48, 0x83, 0xEC}, 3, "OfflineFix #1"},
    // ---- 补丁 2: 把条件写入改成无条件写入 ----
    //  原指令: setb byte[rsp+21h]        ; 按条件置 0 或 1
    //  改为:   mov  byte[rsp+21h], 1     ; 恒置 1
    //  单独关掉本补丁试过: 游戏能进, 主线照样进不去。即本补丁不挡主线, 但也没能
    //  解决主线, 实际作用尚未确认。
    {0x178A8EDu,
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
    {0x25464F4u, {0x01}, 1, {0x05}, 1, "UserProfileInfo+130h = clientType"},
    // ---- 补丁 5: 交互禁用判定直接放行 ----
    //  位置: 交互分发函数 sub_141727C50(交互实体, 玩家)
    //    141727CC3  48 8B 08              mov  rcx,[rax]
    //    141727CC6  80 39 00              cmp  byte [rcx],0     ; KillSwitch 名字是否为空
    //    141727CC9  0F 84 B9 00 00 00     jz   +0xB9           ; 空 -> 允许
    //  非空时会继续查 killswitch 定义(GameInteractionKillSwitch+16 = DisableInteraction)
    //  并判玩家资格, 命中拒绝分支就弹 "This interaction is currently disabled!"。
    //  改成 E9 BA 00 00 00 90 = 无条件跳到允许分支, 一次覆盖 KillSwitch 与
    //  DisableInteraction 两种闸门; 不再需要按资产删连接。
    {0x1727CC9u,
     {0xE9, 0xBA, 0x00, 0x00, 0x00, 0x90},
     6,
     {0x0F, 0x84, 0xB9, 0x00, 0x00, 0x00},
     6,
     "interaction kill switch"},
    // ---- 补丁 6: 关掉挂机检测 ----
    //  sub_141D0F4B0 是每个玩家的空闲计时器: 每帧把 delta 累加到 +176, 再读
    //  PVZServerSettings 的阈值(+36 击杀阈值 / +44 预警阈值 / +64 总开关)。
    //  超过 +36 后调用 sub_141D05580(a1, 0x961799A3) 上报 ClientInactivity,
    //  最终映射到 ExitToMenuReason_ClientInactivity + ID_ERROR_EXITTOMENU_CLIENTINACTIVITY
    //  (就是"检测到你不在玩"然后退回主菜单)。
    //  这里把上报调用改成 xor eax,eax; nop, 计数照常清零, 不会再触发。
    {0x1D0F6F6u,
     {0x31, 0xC0, 0x90, 0x90, 0x90},
     5,
     {0xE8, 0x85, 0x5E, 0xFF, 0xFF},
     5,
     "client inactivity kick"},
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
    //  当前停用: 这个调用点保持被补丁 1 抑制, 不单独放行。
    // {
    // 0x1775E4Au,
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
// 主模块基址, Worker 启动时取; 补丁表的 rva 全部相对它
static unsigned long long g_base = 0;

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
    if (!SafeReadBytes(g_base + p.rva, cur, p.explen))
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
#define P3_RVA 0x25464F4u

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
    if (p.rva == P3_RVA)
      blob[0] = g_p3_value;  // 补丁 3 的字节来自 autooffline_p3.txt

    unsigned long long addr = g_base + p.rva;

    // RW 而不是 RWX: 写入窗口里页面短暂不可执行, 但不再出现可写又可执行的
    // 页属性组合。补丁在开局前一次性写完, 不存在别的线程正在执行这几页的情况。
    DWORD old = 0;
    if (!VirtualProtect((LPVOID)addr, p.len, PAGE_READWRITE, &old)) {
      Log("!! VirtualProtect FAILED @ %llX (%s) err=%lu", addr, p.desc, GetLastError());
      continue;
    }
    memcpy((void *)addr, blob, p.len);
    VirtualProtect((LPVOID)addr, p.len, old, &old);

    bool ok = (memcmp((void *)addr, blob, p.len) == 0);
    Log("Patch @ %llX  %s  %s   byte[0]=0x%02X", addr, ok ? "OK  " : "FAIL", p.desc,
        blob[0]);
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
  g_base = (unsigned long long)GetModuleHandleA(nullptr);
  if (!g_base) {
    Log("!! Cannot resolve the main module base.");
    Log("========================================================");
    return 0;
  }
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
