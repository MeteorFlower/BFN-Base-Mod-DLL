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
//  此时挂钩会对着还没解密的字节做指令解码, 得到错误的跳板。因此本 DLL 先轮询等待
//  挂钩点的原始字节出现(字节吻合 = 已解密), 然后再挂; 等不到就不挂, 只记日志。
//
//  设计上只做三件事: 等解密, 挂钩, 结束。之后在后台维护本地存档。
//  没有开关文件、没有热键、没有探针、没有内存 dump, 也不改写游戏代码里的任何字节。
//  g_patches 表里的七条全部挂在函数入口: 离线放行、会话掩码、clientType、交互解锁、
//  挂机上报、配置模型构造、配置改动漏斗。增删条目直接改表, 然后重启游戏。
//  玩家当前装备的皮肤与 Perk 记在 autooffline_save.json, 见配置捕获与配置恢复两节。
//  记的是配置, 不是解锁状态: 拥有什么、解锁了什么、进度如何, 这个文件一概不碰。
// ============================================================================
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>
#include "../third_party/minhook/include/MinHook.h"
#include "../third_party/nlohmann/json.hpp"

// --------------------------------------------------------------------------
//  挂钩表
//  rva      = 校验原始字节的位置(相对主模块基址), 用来判断代码是否已解密
//  expected = 该地址原本的字节
//  hookRva  = 实际挂钩的函数入口(相对主模块基址)
//  保留 rva/expected 有两个用处: 判断壳解完了没有, 以及挂钩前确认函数没认错。
// --------------------------------------------------------------------------
struct PatchDef {
  unsigned int rva;  // 校验原始字节的位置, 用来等代码解密
  unsigned char expected[8];
  int explen;
  const char *desc;
  unsigned int hookRva;  // 挂 hook 的函数入口
};

static const PatchDef g_patches[] = {
    {0x156FA30u, {0x48, 0x83, 0xEC}, 3, "OfflineFix #1", 0x156FA30u},
    // ---- 补丁 2: "该槽玩家在会话中" 恒为真 ----
    //  原指令: sub_14178A650 里的 setb byte[rsp+21h], 位置 14178A8ED。
    //  它测的是 sub_140447450() 返回的掩码 dword_14421902C 的第 [rsi+70h] 位。
    //  掩码只由网络事件写入(玩家加入置位、离开清位), 离线时永远收不到"加入",
    //  掩码恒 0, 于是这个属性恒为假, 玩家信息不显示。
    //
    //  这里不改指令, 改成挂读掩码的 getter sub_140447450: 只有在
    //  sub_14178A650 里那一次调用时把返回值补成"所有位都在", 该属性于是恒为真。
    //  掩码本身不动, 其它读它的地方(网络事件、会话状态机)拿到的仍是原值。
    {0x178A8EDu, {0x0F, 0x92, 0x44, 0x24, 0x21}, 5, "player in session", 0x447450u},
    // ---- 补丁 3: UserProfileInfo+0x130 = clientType (必需) ----
    //
    //  位置: UserProfileInfo 的构造函数 sub_142546450 内
    //     1425464EE  c7 86 30 01 00 00 05 00 00 00   mov dword [rsi+130h], 5
    //                                               ^ 0x1425464F4 即被改写的字节
    //  类名串 0x14399FFE8 = "UserProfileInfo", 虚表 off_14399FFF8。
    //
    //  该字段的身份来自类型描述符 (sub_14254A3A0 与 off_1447CD8F0 字段表):
    //  UserProfileInfo 的第 12 个字段名为 "clientType", 类型 Blaze::ClientType,
    //  字段表记录的偏移恰为 0x130, 与构造函数写入的 [rsi+130h] 吻合。
    //
    //  Blaze::ClientType 枚举 (类型描述符 @0x1447AD4F0, 成员表 @0x1447AD420):
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
    //      5 = INVALID                连不上 EA 服务器 (即不挂钩时的原值)
    //      7 / 8                      不在枚举内, 无效
    //  规律: 凡是"游戏客户端"身份 (0 / 4) 都进不去, 只有"非游戏客户端"身份 (1) 能进。
    //  即离线状态下无法以游戏客户端身份通过校验; 这与"皮肤/天赋存不下来"很可能是
    //  同一个根因。
    //
    //  2 / 3 (DEDICATED_SERVER / TOOLS) 尚未试过, 但它们更不像会携带玩家的 loadout。
    //
    //  取值由游戏目录下的 autooffline_p3.txt 决定, 默认 1。
    {0x25464F4u, {0x05}, 1, "UserProfileInfo+130h = clientType", 0x2546450u},
    // ---- 补丁 5: 交互解锁 (挂取 KillSwitch 名字的函数) ----
    //  交互是否被禁, 判定依据是取到的 KillSwitch 名字是否为空(sub_141727C50 里
    //  cmp byte[名字], 0 / jz 走允许分支)。名字由 sub_140450180 取出。
    //  这里挂取名字的函数, 只在 0x141727CBB 那一处调用时返回空串对象, 判定自然走
    //  "名字为空就允许"; 其它调用者拿到的仍是原值。
    // ---- 补丁 6: 关掉挂机检测 ----
    //  sub_141D0F4B0 是每个玩家的空闲计时器: 每帧把 delta 累加到 +176, 再读
    //  PVZServerSettings 的阈值(+36 击杀阈值 / +44 预警阈值 / +64 总开关)。
    //  超过 +36 后调用 sub_141D05580(a1, 0x961799A3) 上报 ClientInactivity,
    //  最终映射到 ExitToMenuReason_ClientInactivity + ID_ERROR_EXITTOMENU_CLIENTINACTIVITY
    //  (就是"检测到你不在玩"然后退回主菜单)。
    //  这里挂上报函数 sub_141D05580, 只吞掉 ClientInactivity 这一个原因码, 计数照常清零。
    {0x1D0F6F6u, {0xE8, 0x85, 0x5E, 0xFF, 0xFF}, 5, "client inactivity kick", 0x1D05580u},
    // ---- 补丁 4: 放行一条被补丁 1 抑制的 Blaze RPC (已停用) ----
    //
    //  sub_141775E00(玩家槽) 向某个玩家槽发送"会话更新"RPC:
    //      经 sub_1415C92A0 到 sub_1424A8E50 (Blaze 连接对象, 载荷 112 字节)
    //      完成回调 sub_14176D3C0 处理 Blaze 状态码 (0x00040004 成功 / 0x00980004 失败)
    //  函数开头:
    //      if ( sub_14156FA30() || *(DWORD*)(v5 + 88) ) { *(DWORD*)(this + 48) = 2; }
    //      else { ...发送 RPC... }
    //  补丁 1 使该判断恒走"直接返回"分支, RPC 永远不发送。
    //
    //  皮肤/天赋是服务器上的 24 字节 blob (loadout), 客户端只负责搬运, 推测随这条
    //  RPC 上传。放行的做法是让那一次 sub_14156FA30 调用返回 0(调用点 0x141775E4A),
    //  其余 7 个调用点照旧抑制。
    //
    //  当前停用: 这个调用点保持被补丁 1 抑制, 不单独放行。
    // ---- 配置存档相关的三条 ----
    //  交互解锁与两条配置钩子原先各自单独安装, 现在并进这张表: 它们同样要等解密,
    //  装不上时日志也就不会把"版本不对"和"解密晚了一步"混成一句。
    {0x450180u, {0x48, 0x89, 0x5C, 0x24}, 4, "interaction unlock", 0x450180u},
    {0x16AD770u, {0x4C, 0x89, 0x44, 0x24, 0x18}, 5, "config model ctor", 0x16AD770u},
    {0x16B74C0u, {0x44, 0x89, 0x4C, 0x24, 0x20}, 5, "config edit funnel", 0x16B74C0u},
};

// --------------------------------------------------------------------------
//  补丁 1 的语义 (2026-09-17 逆向得到)
//
//  原函数:
//      14156FA30  48 83 EC 28      sub  rsp,28h
//      14156FA34  E8 F7 E5 FF FF   call sub_14156E030      副作用(疑似启动拦截)
//      14156FA39  32 C0            xor  al,al              本来就恒返回 false
//      14156FA3B  48 83 C4 28      add  rsp,28h
//      14156FA3F  C3               ret
//
//  注意: 它本来就返回 false。社区补丁改成 mov al,1; ret, 在跳过 call 的同时
//    把返回值也翻成了 true,于是所有调用者都走另一条分支。反编译一个调用者
//    (sub_1417CE1A0, 给条目生成状态字符串再 fire 事件)后可见:
//        if (sub_14156FA30() || ...) { if (v7) return 0; }
//        if (sub_14156FA30())        { if (!v7) return 0; }
//    强制 true 之后这两条合起来 = 无条件 return 0, 整个函数被废掉。
// --------------------------------------------------------------------------
static const int NPATCH = (int)(sizeof(g_patches) / sizeof(g_patches[0]));

// 轮询参数: 最多等 3 分钟, 每 500ms 试一次
constexpr unsigned int kWaitTotalMs = 180 * 1000;
constexpr unsigned int kWaitStepMs = 500;

static FILE *g_log = nullptr;
static std::string g_dir;
// 主模块基址, Worker 启动时取; 表里的 rva 全部相对它
static unsigned long long g_base = 0;

// --------------------------------------------------------------------------
//  日志(只写文件,无控制台;fopen "w" = 每次运行清空)
//
//  先写游戏目录; 那里写不了就退到临时目录, 免得整个程序在日志上静默。
// --------------------------------------------------------------------------
static void Log(const char *fmt, ...) {
  if (!g_log)
    return;
  SYSTEMTIME st;
  GetLocalTime(&st);
  fprintf(g_log, "[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
  va_list ap;
  va_start(ap, fmt);
  vfprintf(g_log, fmt, ap);
  va_end(ap);
  fputc('\n', g_log);
  fflush(g_log);
}

static bool OpenLog() {
  g_log = fopen((g_dir + "\\autooffline_log.txt").c_str(), "w");
  if (g_log)
    return true;
  char tmp[MAX_PATH] = {0};
  DWORD n = GetTempPathA(MAX_PATH, tmp);
  if (n == 0 || n >= MAX_PATH)
    return false;
  std::string alt = std::string(tmp) + "autooffline_log.txt";
  g_log = fopen(alt.c_str(), "w");
  if (!g_log)
    return false;
  Log("!! could not write the log next to the game, using %s", alt.c_str());
  return true;
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

// 所有挂钩点的原始字节是否都已就位(= 代码已解密)。
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

// 等待超时后逐条报出哪一条没对上。只有超时才调用, 不会在轮询里刷屏。
static void BytesToText(const unsigned char *b, int n, char *out, int cap) {
  int used = 0;
  out[0] = 0;
  for (int i = 0; i < n; ++i) {
    if (used + 4 >= cap)
      break;
    int w = snprintf(out + used, (size_t)(cap - used), "%02X ", b[i]);
    if (w < 0) {
      out[0] = 0;
      return;
    }
    used += w;
  }
}

static void LogMissingPatterns() {
  for (int i = 0; i < NPATCH; ++i) {
    const PatchDef &p = g_patches[i];
    unsigned char cur[8] = {0};
    unsigned long long addr = g_base + p.rva;
    if (!SafeReadBytes(addr, cur, p.explen)) {
      Log("  %-28s @ %llX: unreadable", p.desc, addr);
      continue;
    }
    if (memcmp(cur, p.expected, p.explen) == 0)
      continue;
    char want[40];
    char have[40];
    BytesToText(p.expected, p.explen, want, (int)sizeof(want));
    BytesToText(cur, p.explen, have, (int)sizeof(have));
    Log("  %-28s @ %llX: want %s have %s", p.desc, addr, want, have);
  }
}

// --------------------------------------------------------------------------
//  补丁 3 写入的那个值做成可调, 不用重编译就能扫值
//
//  补丁 3 改的是 Blaze::Authentication::UserProfileInfo+0x130 处的 clientType。
//  它是 Blaze::ClientType 枚举, 合法值只有 0..5 六个 (含义见上面那张表)。
//  默认 = 1 (CLIENT_TYPE_HTTP_USER), 实测唯一能进入游戏的取值。
//
//  游戏目录下放个 autooffline_p3.txt, 里面写个 0..5 的十进制数即可。
//  文件不存在 = 用 0x01。
// --------------------------------------------------------------------------
static unsigned char g_p3_value = 0x01;

static void LoadP3Value() {
  std::string path = g_dir + "\\autooffline_p3.txt";
  FILE *f = fopen(path.c_str(), "r");
  if (!f) {
    Log("patch3 value: no %s, using 0x%02X", path.c_str(), g_p3_value);
    return;
  }
  int v = -1;
  if (fscanf(f, "%i", &v) != 1 || v < 0 || v > 5) {
    Log("patch3 value: bad content in %s, using 0x%02X", path.c_str(), g_p3_value);
  } else {
    g_p3_value = (unsigned char)v;
    Log("patch3 value <- %s = 0x%02X (%d)", path.c_str(), g_p3_value, v);
  }
  fclose(f);
}

// --------------------------------------------------------------------------
//  本地存档
//
//  离线时服务器不会把玩家的存档发回来, 当前装备的皮肤和 Perk 每次都要重新配一遍。
//  这里把这份配置记在 autooffline_save.json, 之后由本地交回游戏, 不等服务器回答。
//  记的是配置, 不是解锁状态: 拥有什么、解锁了什么、进度如何, 一概不存也不改。
//
//  内容按角色分。每个角色有三个配置槽位, 每个槽位是一张 选项 key 到值 的表;
//  key 和值都是游戏自己的 u32 哈希, 另外存一份名字, 便于人看, 也便于哈希口径
//  变化时对照。JSON 可以直接打开改。写入先落 .tmp 再替换, 中途断电不会留下半个
//  文件。
//
//  结构:
//      {
//        "version": 1,
//        "characters": [
//          {
//            "id": 1234567,           角色 id
//            "name": "Soldier",       角色名, 仅用于人读
//            "presets": [
//              { "options": [ { "key": 285258545, "key_name": "Outfit",
//                               "value": 987654321, "value_name": "Skin_A" } ] },
//              { "options": [] },
//              { "options": [] }
//            ]
//          }
//        ]
//      }
// --------------------------------------------------------------------------
constexpr unsigned int kSaveVersion = 1;
constexpr int kPresetCount = 3;

struct LoadoutOption {
  unsigned int key;
  unsigned int value;
  std::string keyName;
  std::string valueName;
};

struct LoadoutPreset {
  std::vector<LoadoutOption> options;
};

struct LoadoutCharacter {
  unsigned int id = 0;
  std::string name;
  LoadoutPreset presets[kPresetCount];
};

static std::vector<LoadoutCharacter> g_chars;
static std::mutex g_save_mutex;  // 保护 g_chars: 游戏线程写, 落盘线程读
static std::atomic<bool> g_save_dirty{false};
// 每次捕获递增。写盘完成时若已经变了, 说明期间又有新改动, 不能把脏标记清掉。
static std::atomic<unsigned int> g_save_gen{0};
static HANDLE g_save_event = nullptr;  // 有改动时叫醒落盘线程
// 存档读失败之后禁止写盘, 否则一次改动就会用空库把剩下的角色覆盖掉
static bool g_save_writable = true;

static std::string SavePath() {
  return g_dir + "\\autooffline_save.json";
}

// 调用方必须已经持有 g_save_mutex。
static void SavePutLocked(const LoadoutCharacter &c) {
  for (LoadoutCharacter &e : g_chars) {
    if (e.id == c.id) {
      e = c;
      return;
    }
  }
  g_chars.push_back(c);
}

static void SavePutCharacter(const LoadoutCharacter &c) {
  std::lock_guard<std::mutex> lock(g_save_mutex);
  SavePutLocked(c);
}

static bool SaveHasCharacter(unsigned int charId) {
  std::lock_guard<std::mutex> lock(g_save_mutex);
  for (const LoadoutCharacter &e : g_chars) {
    if (e.id == charId)
      return true;
  }
  return false;
}

static bool SaveLoad() {
  std::string path = SavePath();
  FILE *f = fopen(path.c_str(), "rb");
  if (!f) {
    Log("save: no %s, nothing saved yet", path.c_str());
    return false;
  }
  std::string text;
  char buf[4096];
  size_t n = 0;
  while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    text.append(buf, n);
  fclose(f);
  // 记事本另存会带 UTF-8 BOM, 解析器不认, 先剥掉
  if (text.size() >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB &&
      (unsigned char)text[2] == 0xBF)
    text.erase(0, 3);

  nlohmann::json doc = nlohmann::json::parse(text, nullptr, false);
  if (doc.is_discarded() || !doc.is_object()) {
    Log("!! save: %s is not valid JSON, will not be overwritten", path.c_str());
    g_save_writable = false;
    return false;
  }
  std::vector<LoadoutCharacter> loaded;
  try {
    unsigned int version = doc.value("version", 0u);
    if (version != kSaveVersion)
      Log("!! save: version %u, expected %u, reading it anyway", version, kSaveVersion);
    const nlohmann::json &chars = doc.at("characters");
    if (!chars.is_array()) {
      Log("!! save: characters is not an array, will not be overwritten");
      g_save_writable = false;
      return false;
    }
    for (const nlohmann::json &cj : chars) {
      LoadoutCharacter c;
      c.id = cj.at("id").get<unsigned int>();
      c.name = cj.value("name", std::string());
      const nlohmann::json &presets = cj.at("presets");
      int count = (int)presets.size();
      for (int p = 0; p < kPresetCount && p < count; ++p) {
        const nlohmann::json &opts = presets[(size_t)p].at("options");
        for (const nlohmann::json &oj : opts) {
          LoadoutOption o;
          o.key = oj.at("key").get<unsigned int>();
          o.value = oj.at("value").get<unsigned int>();
          o.keyName = oj.value("key_name", std::string());
          o.valueName = oj.value("value_name", std::string());
          c.presets[p].options.push_back(o);
        }
      }
      loaded.push_back(c);
    }
  } catch (const std::exception &e) {
    Log("!! save: %s, will not be overwritten", e.what());
    g_save_writable = false;
    return false;
  }
  std::lock_guard<std::mutex> lock(g_save_mutex);
  g_chars.swap(loaded);
  Log("save: loaded %d characters", (int)g_chars.size());
  return true;
}

// 排序只对副本做, 不动 g_chars: 那份数据同时被游戏线程写。
static void SortCharacters(std::vector<LoadoutCharacter> &chars) {
  std::sort(chars.begin(), chars.end(), [](const LoadoutCharacter &a, const LoadoutCharacter &b) {
    return a.id < b.id;
  });
  for (LoadoutCharacter &c : chars) {
    for (int p = 0; p < kPresetCount; ++p) {
      std::vector<LoadoutOption> &opts = c.presets[p].options;
      std::sort(opts.begin(), opts.end(), [](const LoadoutOption &a, const LoadoutOption &b) {
        return a.key < b.key;
      });
    }
  }
}

// 先排好序再写, 同样的内容一定得到同样的文件。写成功才清脏标记。
static bool SaveStore() {
  if (!g_save_writable) {
    Log("!! save: file was unreadable, refusing to overwrite it");
    return false;
  }
  std::vector<LoadoutCharacter> copy;
  unsigned int gen = g_save_gen.load();
  {
    std::lock_guard<std::mutex> lock(g_save_mutex);
    copy = g_chars;
  }
  SortCharacters(copy);
  nlohmann::json doc;
  doc["version"] = kSaveVersion;
  nlohmann::json chars = nlohmann::json::array();
  for (const LoadoutCharacter &c : copy) {
    nlohmann::json cj;
    cj["id"] = c.id;
    if (!c.name.empty())
      cj["name"] = c.name;
    nlohmann::json presets = nlohmann::json::array();
    for (int p = 0; p < kPresetCount; ++p) {
      nlohmann::json opts = nlohmann::json::array();
      for (const LoadoutOption &o : c.presets[p].options) {
        nlohmann::json oj;
        oj["key"] = o.key;
        oj["value"] = o.value;
        if (!o.keyName.empty())
          oj["key_name"] = o.keyName;
        if (!o.valueName.empty())
          oj["value_name"] = o.valueName;
        opts.push_back(oj);
      }
      nlohmann::json pj;
      pj["options"] = opts;
      presets.push_back(pj);
    }
    cj["presets"] = presets;
    chars.push_back(cj);
  }
  doc["characters"] = chars;
  std::string text = doc.dump(2);
  text += "\n";
  if (text.size() > 0x7FFFFFFFu) {
    Log("!! save: file would be %llu bytes, refusing", (unsigned long long)text.size());
    return false;
  }

  std::string path = SavePath();
  std::string tmp = path + ".tmp";
  HANDLE h = CreateFileA(tmp.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, nullptr);
  if (h == INVALID_HANDLE_VALUE) {
    Log("!! save: cannot create %s (err=%lu)", tmp.c_str(), GetLastError());
    return false;
  }
  DWORD written = 0;
  bool ok = WriteFile(h, text.data(), (DWORD)text.size(), &written, nullptr) != 0;
  if (ok && written != text.size())
    ok = false;
  if (ok && !FlushFileBuffers(h))
    ok = false;
  CloseHandle(h);
  if (!ok) {
    Log("!! save: write failed for %s", tmp.c_str());
    DeleteFileA(tmp.c_str());
    return false;
  }
  if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
    Log("!! save: cannot replace %s (err=%lu)", path.c_str(), GetLastError());
    DeleteFileA(tmp.c_str());
    return false;
  }
  // 写盘期间又有改动: 不清脏标记, 叫醒循环再写一次
  if (g_save_gen.load() == gen) {
    g_save_dirty = false;
  } else if (g_save_event) {
    SetEvent(g_save_event);
  }
  Log("save: wrote %d characters", (int)copy.size());
  return true;
}

// --------------------------------------------------------------------------
//  配置捕获
//
//  改动漏斗 sub_1416B74C0(管理器, 玩家槽, 角色id, 选项 key, 新值) 是五件套和 Perk
//  共同的写入口, 菜单里每点一次都经过它。挂在这里, 每次写完就把该角色的三个槽位
//  整份读出来存进库里, 不需要区分改的是哪个部位。
//
//  模型布局(已核对):
//      +216 角色 id      +280 三个 56 字节的槽位
//  每个槽位的 +8 是哈希表: +8 桶数组, +16 桶数, +20 元素数;
//  节点 16 字节: +0 键, +4 值, +8 下一个。
// --------------------------------------------------------------------------
constexpr unsigned int kModelCharId = 216;
constexpr unsigned int kModelPresetArray = 280;
constexpr unsigned int kPresetSize = 56;
constexpr unsigned int kPresetMap = 8;
constexpr unsigned int kMapBuckets = 8;
constexpr unsigned int kMapBucketCount = 16;
constexpr unsigned int kMapSize = 20;
constexpr unsigned int kMapMaxBuckets = 4096;
constexpr unsigned int kMapMaxNodes = 4096;
constexpr int kRawMaxOptions = 1024;
constexpr unsigned int kModelLookupRva = 0x16AEB60u;

struct RawOption {
  unsigned int key;
  unsigned int value;
};

typedef void *(__fastcall *ModelLookupFn)(void *, unsigned int, unsigned int);
typedef void(__fastcall *LoadoutEditFn)(void *, unsigned int, unsigned int, unsigned int,
                                        unsigned int);

static ModelLookupFn g_model_lookup = nullptr;
static void *g_edit_orig = nullptr;
// 恢复期间不许快照: recalc 会转回改动漏斗, 那一刻模型是半恢复状态
static thread_local bool g_in_restore = false;

// 只接管"读游戏内存读炸了"这类异常。别的异常(包括游戏自己抛的)继续往外走,
// 不被我们悄悄吞掉。
static int OurFaultFilter(unsigned int code) {
  if (code == EXCEPTION_ACCESS_VIOLATION || code == EXCEPTION_IN_PAGE_ERROR ||
      code == EXCEPTION_ILLEGAL_INSTRUCTION || code == EXCEPTION_PRIV_INSTRUCTION)
    return EXCEPTION_EXECUTE_HANDLER;
  return EXCEPTION_CONTINUE_SEARCH;
}

// 只有 POD, 才能放进 __try 里。返回 -1 表示读的时候出错。
static int RawReadModel(void *model, unsigned int *charId, int *presetStart, RawOption *out,
                        int cap) {
  __try {
    int n = 0;
    *charId = 0;
    presetStart[0] = 0;
    if (!model)
      return 0;
    *charId = *(unsigned int *)((unsigned char *)model + kModelCharId);
    unsigned char *presets = *(unsigned char **)((unsigned char *)model + kModelPresetArray);
    if (!presets)
      return 0;
    for (int p = 0; p < kPresetCount; ++p) {
      unsigned char *map = presets + p * kPresetSize + kPresetMap;
      unsigned int buckets = *(unsigned int *)(map + kMapBucketCount);
      unsigned int elems = *(unsigned int *)(map + kMapSize);
      unsigned char **arr = *(unsigned char ***)(map + kMapBuckets);
      if (arr && buckets && buckets <= kMapMaxBuckets) {
        unsigned int left = (elems <= kMapMaxNodes) ? elems : kMapMaxNodes;
        for (unsigned int b = 0; b < buckets && left; ++b) {
          unsigned char *node = arr[b];
          int guard = 0;
          while (node && n < cap && left && guard < (int)kMapMaxBuckets) {
            out[n].key = *(unsigned int *)node;
            out[n].value = *(unsigned int *)(node + 4);
            ++n;
            ++guard;
            --left;
            node = *(unsigned char **)(node + 8);
          }
        }
      }
      presetStart[p + 1] = n;
    }
    return n;
  } __except (OurFaultFilter(GetExceptionCode())) {
    return -1;
  }
}

static void SnapshotModel(void *model) {
  RawOption raw[kRawMaxOptions];
  unsigned int charId = 0;
  int presetStart[4] = {0, 0, 0, 0};
  int n = RawReadModel(model, &charId, presetStart, raw, kRawMaxOptions);
  if (n < 0) {
    Log("!! capture: fault while reading the model, skipped");
    return;
  }
  if (charId == 0)
    return;
  // 三个槽位全清空也要存下来, 否则上次存的值下次会自己回来;
  // 但从没存过的角色不必写空条目
  if (n == 0 && !SaveHasCharacter(charId))
    return;
  LoadoutCharacter c;
  c.id = charId;
  for (int p = 0; p < kPresetCount; ++p) {
    for (int i = presetStart[p]; i < presetStart[p + 1]; ++i) {
      LoadoutOption o;
      o.key = raw[i].key;
      o.value = raw[i].value;
      c.presets[p].options.push_back(o);
    }
  }
  SavePutCharacter(c);
  g_save_gen.fetch_add(1);
  g_save_dirty = true;
  if (g_save_event)
    SetEvent(g_save_event);
}

// --------------------------------------------------------------------------
//  配置恢复
//
//  挂模型构造器 sub_1416AD770(管理器, 玩家槽, 角色资产, 标记, Perk 描述) 的返回处。
//  选择这个点是因为游戏对模型是硬依赖: 发布路径先按角色 id 找模型, 找不到直接返回,
//  而发布是角色组件容器的唯一写入者、组件又是进图装配的唯一数据来源。所以在这里
//  写进去, 对该模型的任何读取和任何一次装配都必然更早, 不靠时序巧合, 也不等进图。
//  建模本身由模块初始化驱动, 与菜单和对局状态无关, 每个角色条目构造一个模型。
//
//  写的是 UI 管理器里的权威表(sub_141766580), 不是模型里的 preset 表: 后者只是
//  缓存, 每次 sub_1416AF1D0 都会先清空再从权威表重灌。写完再逐槽位重灌一次缓存,
//  最后重算一次活字段(sub_1416ABF60), 让模型立刻反映新数据。
// --------------------------------------------------------------------------
constexpr unsigned int kWriteAuthRva = 0x1766580u;
constexpr unsigned int kSyncPresetRva = 0x16AF1D0u;
constexpr unsigned int kRecalcRva = 0x16ABF60u;
constexpr unsigned int kUiManagerRva = 0x4659DB0u;
constexpr int kRawMaxRestore = 1024;

typedef void *(__fastcall *ModelCtorFn)(void *, unsigned int, void *, unsigned char *, void *);
typedef void(__fastcall *WriteAuthFn)(void *, unsigned int, unsigned int, unsigned int,
                                      unsigned int, unsigned int);
typedef void(__fastcall *SyncPresetFn)(void *, unsigned int, void *, unsigned int, void *);
typedef void(__fastcall *RecalcFn)(void *, unsigned int, void *);

struct RawEntry {
  unsigned int preset;
  unsigned int key;
  unsigned int value;
};

static void *g_ctor_orig = nullptr;
static WriteAuthFn g_write_auth = nullptr;
static SyncPresetFn g_sync_preset = nullptr;
static RecalcFn g_recalc = nullptr;

// 只有 POD, 才能放进 __try 里。返回 -1 表示调用过程中出错。
static int RawApplyRestore(void *mgr, unsigned int slot, void *model, void *ui,
                           const RawEntry *entries, int count) {
  __try {
    unsigned int charId = *(unsigned int *)((unsigned char *)model + kModelCharId);
    for (int i = 0; i < count; ++i)
      g_write_auth(ui, slot, charId, entries[i].preset, entries[i].key, entries[i].value);
    unsigned char *presets = *(unsigned char **)((unsigned char *)model + kModelPresetArray);
    if (presets) {
      for (int p = 0; p < kPresetCount; ++p)
        g_sync_preset(mgr, slot, model, (unsigned int)p, presets + p * kPresetSize);
    }
    g_recalc(mgr, slot, model);
    return 0;
  } __except (OurFaultFilter(GetExceptionCode())) {
    return -1;
  }
}

static void *SafeModelLookup(void *mgr, unsigned int slot, unsigned int charId) {
  __try {
    return g_model_lookup(mgr, slot, charId);
  } __except (OurFaultFilter(GetExceptionCode())) {
    return nullptr;
  }
}

// UI 管理器还没建好时恢复做不了。模型是按角色条目构造的, 错过那一刻就得等下次
// 构造, 所以把 (槽, 角色) 记下来, 等下一次有游戏线程的机会再补, 否则整局都是默认外观。
struct PendingRestore {
  unsigned int slot;
  unsigned int charId;
};

constexpr int kMaxPending = 64;
static PendingRestore g_pending[kMaxPending];
static int g_pending_count = 0;

static void PendingAdd(unsigned int slot, unsigned int charId) {
  for (int i = 0; i < g_pending_count; ++i) {
    if (g_pending[i].slot == slot && g_pending[i].charId == charId)
      return;
  }
  if (g_pending_count == kMaxPending) {
    Log("!! restore: pending list is full, character %u dropped", charId);
    return;
  }
  g_pending[g_pending_count].slot = slot;
  g_pending[g_pending_count].charId = charId;
  ++g_pending_count;
}

// 按角色 id 取一份存档副本。拷贝在锁内, 之后的操作全在锁外。
static bool CopySavedCharacter(unsigned int charId, LoadoutCharacter *out) {
  std::lock_guard<std::mutex> lock(g_save_mutex);
  for (const LoadoutCharacter &e : g_chars) {
    if (e.id == charId) {
      *out = e;
      return true;
    }
  }
  return false;
}

static void ApplySaved(void *mgr, unsigned int slot, void *model, void *ui,
                       const LoadoutCharacter &c) {
  RawEntry entries[kRawMaxRestore];
  int count = 0;
  for (int p = 0; p < kPresetCount; ++p) {
    for (const LoadoutOption &o : c.presets[p].options) {
      if (count == kRawMaxRestore) {
        Log("!! restore: too many values for character %u, truncated", c.id);
        break;
      }
      entries[count].preset = (unsigned int)p;
      entries[count].key = o.key;
      entries[count].value = o.value;
      ++count;
    }
  }
  if (count == 0)
    return;  // 存档里这一角色就是空的, 不用写任何值
  g_in_restore = true;
  int rc = RawApplyRestore(mgr, slot, model, ui, entries, count);
  g_in_restore = false;
  if (rc != 0) {
    Log("!! restore: fault while applying character %u", c.id);
    return;
  }
  Log("restore: character %u, %d values", c.id, count);
}

static void RestoreModel(void *mgr, unsigned int slot, void *model) {
  if (!model)
    return;
  unsigned int charId = *(unsigned int *)((unsigned char *)model + kModelCharId);
  LoadoutCharacter c;
  if (!CopySavedCharacter(charId, &c))
    return;
  void *ui = *(void **)(g_base + kUiManagerRva);
  if (!ui) {
    Log("!! restore: UI manager is null, character %u queued", charId);
    PendingAdd(slot, charId);
    return;
  }
  ApplySaved(mgr, slot, model, ui, c);
}

static void RetryPending(void *mgr) {
  if (g_pending_count == 0 || !g_model_lookup)
    return;
  void *ui = *(void **)(g_base + kUiManagerRva);
  if (!ui)
    return;
  for (int i = 0; i < g_pending_count;) {
    unsigned int slot = g_pending[i].slot;
    unsigned int charId = g_pending[i].charId;
    void *model = SafeModelLookup(mgr, slot, charId);
    LoadoutCharacter c;
    if (model && CopySavedCharacter(charId, &c))
      ApplySaved(mgr, slot, model, ui, c);
    g_pending[i] = g_pending[g_pending_count - 1];
    --g_pending_count;
  }
}

static void *__fastcall HookModelCtor(void *mgr, unsigned int slot, void *asset,
                                      unsigned char *flag, void *perkDesc) {
  void *model =
      g_ctor_orig ? ((ModelCtorFn)g_ctor_orig)(mgr, slot, asset, flag, perkDesc) : nullptr;
  // 先把之前没恢复成的补上, 再处理这一个
  RetryPending(mgr);
  RestoreModel(mgr, slot, model);
  return model;
}

static void __fastcall HookLoadoutEdit(void *mgr, unsigned int slot, unsigned int charId,
                                       unsigned int key, unsigned int value) {
  if (g_edit_orig)
    ((LoadoutEditFn)g_edit_orig)(mgr, slot, charId, key, value);
  // 恢复过程里 recalc 会转回这里, 此刻模型还没写完, 快照会把半成品存进去
  if (g_in_restore)
    return;
  RetryPending(mgr);
  void *model = SafeModelLookup(mgr, slot, charId);
  if (model)
    SnapshotModel(model);
}

// --------------------------------------------------------------------------
//  挂钩实现
//
//  每一条都在函数入口接管: 语义写在代码里, 不会把指令切坏, 也不依赖某一条
//  指令的编码。原始字节仍写在 g_patches 的 expected 里, 挂钩前先核对, 避免对着
//  还没解密的乱码做指令解码。
// --------------------------------------------------------------------------
typedef void *(__fastcall *P3Fn)(void *, void *, void *);
typedef void(__fastcall *P6Fn)(void *, unsigned int);
typedef unsigned int(__fastcall *MaskGetFn)();
typedef void *(__fastcall *NameGetFn)(__int64 *, __int64);

// 原函数指针统一用 void*, 便于在一张表里登记; 各 detour 自己按签名转换。
static void *g_p3_orig = nullptr;
static void *g_p6_orig = nullptr;
static void *g_maskget_orig = nullptr;
static void *g_nameget_orig = nullptr;

constexpr unsigned int kSessionMaskSiteRva = 0x178A8C1u;
constexpr unsigned int kInteractCallSiteRva = 0x1727CC0u;

// 补丁 1: 原函数会在每次调用时按槽取一次玩家对象(取到再加引用释放), 然后恒返回 0。
// 离线态下这次探测会让游戏在进图时崩, 所以一律不执行探测, 一律回答"不可用"。
// 逐点放开的实验做过一轮, 结论是: 放开第 1 点会破坏进入流程(加载完弹回主菜单),
// 放开第 5 点会闪退, 放开第 2/6/7 点没有可观察的差别。所以维持整体抑制。
static char __fastcall HookOfflineFix(unsigned int slot) {
  (void)slot;
  return 1;
}

// 补丁 2: "该槽玩家在会话中" 读的是掩码 dword_14421902C 的对应位。掩码只由网络
// 事件置位和清位, 离线时恒为 0。这里挂读掩码的 getter, 只在 sub_14178A650 里那一次
// 调用时把返回值补满, 于是那个属性恒为真; 掩码本身不动, 其它读取方拿到的仍是原值。
static unsigned int __fastcall HookSessionMask() {
  unsigned int mask = g_maskget_orig ? ((MaskGetFn)g_maskget_orig)() : 0u;
  if ((unsigned long long)_ReturnAddress() == g_base + kSessionMaskSiteRva)
    mask |= 0xFFu;
  return mask;
}

// 补丁 3: 构造函数把 clientType 初始化成 5, 构造完直接覆盖成配置值。
static void *__fastcall HookProfileCtor(void *self, void *a2, void *a3) {
  void *ret = g_p3_orig ? ((P3Fn)g_p3_orig)(self, a2, a3) : nullptr;
  if (self)
    *(unsigned int *)((unsigned char *)self + 0x130) = g_p3_value;
  return ret;
}

// 补丁 6: 挂机检测把 ClientInactivity 交给这个上报函数, 只吞这一种原因码。
static void __fastcall HookReport(void *peer, unsigned int reason) {
  if (reason == 0x961799A3u)
    return;
  if (g_p6_orig)
    ((P6Fn)g_p6_orig)(peer, reason);
}

// --------------------------------------------------------------------------
//  交互解锁 (补丁 5)
//
//  sub_141727C50 判断交互是否被禁用, 依据是取到的 KillSwitch 名字是否为空:
//      mov rcx,[rax] / cmp byte[rcx],0 / jz 走允许分支
//  名字由 sub_140450180 取出。这里挂取名字的函数, 只在 0x141727CBB 那一处调用时
//  换成一个空串对象, 于是判定自然走"名字为空就允许"。不改写那条 jz 指令,
//  其它调用者拿到的仍是原值。
// --------------------------------------------------------------------------
static const char g_emptyName[1] = {0};
static void *g_fakeNameObj[2] = {(void *)g_emptyName, nullptr};

static void *__fastcall HookNameGet(__int64 *a1, __int64 a2) {
  void *ret = g_nameget_orig ? ((NameGetFn)g_nameget_orig)(a1, a2) : nullptr;
  if ((unsigned long long)_ReturnAddress() == g_base + kInteractCallSiteRva)
    return (void *)g_fakeNameObj;
  return ret;
}

static void *DetourFor(unsigned int hookRva) {
  switch (hookRva) {
    case 0x156FA30u:
      return (void *)&HookOfflineFix;
    case 0x447450u:
      return (void *)&HookSessionMask;
    case 0x2546450u:
      return (void *)&HookProfileCtor;
    case 0x1D05580u:
      return (void *)&HookReport;
    case 0x450180u:
      return (void *)&HookNameGet;
    case 0x16AD770u:
      return (void *)&HookModelCtor;
    case 0x16B74C0u:
      return (void *)&HookLoadoutEdit;
    default:
      return nullptr;
  }
}

// 每条 hook 的原函数指针放这里; 补丁 1 不调原函数, 返回 nullptr。
static void **OrigSlotFor(unsigned int hookRva) {
  switch (hookRva) {
    case 0x447450u:
      return &g_maskget_orig;
    case 0x2546450u:
      return &g_p3_orig;
    case 0x1D05580u:
      return &g_p6_orig;
    case 0x450180u:
      return &g_nameget_orig;
    case 0x16AD770u:
      return &g_ctor_orig;
    case 0x16B74C0u:
      return &g_edit_orig;
    default:
      return nullptr;
  }
}

static void InstallHooks() {
  MH_STATUS init = MH_Initialize();
  if (init != MH_OK) {
    Log("!! hooks: MH_Initialize failed: %s, nothing is hooked", MH_StatusToString(init));
    return;
  }
  g_model_lookup = (ModelLookupFn)(g_base + kModelLookupRva);
  g_write_auth = (WriteAuthFn)(g_base + kWriteAuthRva);
  g_sync_preset = (SyncPresetFn)(g_base + kSyncPresetRva);
  g_recalc = (RecalcFn)(g_base + kRecalcRva);

  for (int i = 0; i < NPATCH; ++i) {
    const PatchDef &p = g_patches[i];
    unsigned long long target = g_base + p.hookRva;
    void *detour = DetourFor(p.hookRva);
    if (!detour) {
      Log("!! hook %s: no detour for %llX", p.desc, target);
      continue;
    }
    void *orig = nullptr;
    MH_STATUS st = MH_CreateHook((LPVOID)target, detour, &orig);
    if (st != MH_OK) {
      Log("!! hook %s @ %llX: MH_CreateHook %s", p.desc, target, MH_StatusToString(st));
      continue;
    }
    // 先发布原函数再启用: 启用一返回, 别的线程就可能进来, 那时指针必须是好的
    void **slot = OrigSlotFor(p.hookRva);
    if (slot)
      *slot = orig;
    st = MH_EnableHook((LPVOID)target);
    if (st != MH_OK) {
      Log("!! hook %s @ %llX: MH_EnableHook %s", p.desc, target, MH_StatusToString(st));
      continue;
    }
    Log("hook @ %llX  %s", target, p.desc);
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
//  等代码解密, 挂钩, 结束
// --------------------------------------------------------------------------
static DWORD WINAPI Worker(LPVOID self) {
  g_dir = DirOfSelf((HMODULE)self);
  OpenLog();

  Log("========================================================");
  Log("AutoOffline loaded (as RtWorkQ.dll). Dir: %s", g_dir.c_str());
  g_base = (unsigned long long)GetModuleHandleA(nullptr);
  if (!g_base) {
    Log("!! Cannot resolve the main module base.");
    Log("========================================================");
    return 0;
  }
  LoadP3Value();
  SaveLoad();
  g_save_event = CreateEventA(nullptr, FALSE, FALSE, nullptr);
  Log("Waiting for the game code to be decrypted before hooking...");

  DWORD t0 = GetTickCount();
  bool ready = false;
  for (;;) {
    if (AllExpectedPresent()) {
      ready = true;
      break;
    }
    if (GetTickCount() - t0 >= kWaitTotalMs)
      break;
    Sleep(kWaitStepMs);
  }

  if (!ready) {
    Log("!! Gave up after %lu s: the expected original bytes never appeared.",
        (unsigned long)((GetTickCount() - t0) / 1000));
    LogMissingPatterns();
    Log("!! NOTHING was hooked.");
    Log("========================================================");
    return 0;
  }

  Log("Code is decrypted (byte patterns matched) after %lu s.",
      (unsigned long)((GetTickCount() - t0) / 1000));
  InstallHooks();
  Log("Done.");
  Log("========================================================");

  // 捕获到的改动攒一下再落盘: 连续点选合成一次写盘, 但间隔要短, 玩家改完立刻
  // 关游戏也不能丢。写失败就保留脏标记, 退避后重试。
  for (;;) {
    if (!g_save_event) {
      Sleep(200);
      if (g_save_dirty)
        SaveStore();
      continue;
    }
    WaitForSingleObject(g_save_event, INFINITE);
    Sleep(300);
    while (g_save_dirty && !SaveStore())
      Sleep(5000);
  }
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
