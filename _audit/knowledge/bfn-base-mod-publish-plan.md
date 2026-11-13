---
name: bfn-base-mod-publish-plan
description: BFN Base Mod 已发布：GitHub 仓库已上线、Nexus 隔离与申诉流程、构建时间戳验证法
metadata:
  node_type: memory
  type: project
  originSessionId: 3f98f455-8ff5-4585-9f84-657fefa98270
  modified: 2026-10-26T16:22:33.964Z
---

# BFN Base Mod

## 它是什么

跑别的 mod 用的"基础 mod"。机制 = DLL 搜索顺序劫持：游戏裸名调 LoadLibrary("RtWorkQ.dll")，
同目录的我们的 DLL 优先于 System32 的被加载。没有注入器，游戏自己加载我们。
DLL 本身叫 AutoOffline.dll，发布时改名为 RtWorkQ.dll。

主卖点：社区方案是"换旧版 exe + 注入 DLL 进离线模式"，关卡进度全丢；
我们这个留在新版、仍连 EA 服务器（但只能单人，进 PvP 会被踢），Explore 进度保住。

## 页面与仓库

- Nexus mod 页：https://www.nexusmods.com/plantsvszombiesbattleforneighborville/mods/38
  （版块路径段就是 BFN 的 slug，别手打错）
- B 站专栏：https://www.bilibili.com/opus/1263548411806744592
  （2026-10-27 换成这个；旧的是 1252300489436954661，其它 mod 的 b 站版里"前置 mod 专栏链接"都指向这里）
- GitHub：https://github.com/MeteorFlower/BFN-Base-Mod-DLL
  本地仓库在 Mods_dev\BFN\开源仓库\BFN-Base-Mod\（用户名 MeteorFlower，commit 邮箱 drplant666@qq.com）
- Nexus 主页：https://www.nexusmods.com/profile/MeteorFlower
  Nexus 对自动抓取返回 403，别用 WebFetch 去验，验不出来

提交后被自动安全检查隔离。隔离原因：DLL 代理 + 两个 bat，触发"可执行文件"规则 +
VirusTotal 3/71（全是启发式，Trojan:Win32/Wacatac.B!ml 的 !ml = 机器学习猜测不是特征码）。
申诉的关键是给源码链接。别删被隔离的文件（会打乱版本历史）。

**★2026-10-14：更新（NPC 交互那批 fbmod）又被隔离一次。** 这轮的申诉口径特意写短：
只改了 `.fbmod` 这一个文件（纯游戏资产、不含任何可执行代码），其余文件与上次通过的那版完全一致；
带上 mod 页链接与作者主页链接。没有再放源码仓库链接（要的话可补）。

## 申诉与催稿（流程知识）

- 系统自动回复（Help Scout）会创建工单，不用补发。**规矩是"别为同一个工单另开新邮件"**
  （自动回复里写"在原邮件里回复即可更新工单"；另开一封会变成第二个工单）。
  ★2026-10-14 澄清：这句话**不是**"永远回最早的旧线程"。每一次新事件（比如 mod 更新后又被隔离）
  会有**它自己的**通知邮件，也就是**它自己的**工单 —— 要回的是**那封新的**隔离通知。
  只有在"没收到新通知、主动追问某个已有工单"时才回旧线程。
- 那条加粗要求（用账号邮箱发 + 正文带用户名）约束的是"创建工单"：自动回复开头会把用户名写出来
  （Hello 那一行），说明用户名被解析出来了，收件人也对上了，缺任一项都不会有回信。
- 催稿要短，措辞用"还缺什么我马上补"，不要用"怎么还没回"。人工审核队列里前者有效得多。
- 时限：这封工单邮件没有时限承诺，只说 "as soon as possible"。别引用 "1-2 周"（那个数字来自
  Nexus 账号封禁申诉页 help article 33，是另一个流程，不适用这里）。真正管用的是
  business hours 09:00-17:00 GMT，一般 2~5 个工作日，别在周末发。

## 2026-10-01：仓库瘦身 + 可复现构建 + 不再强调哈希

定案：release 只是给你一个构建，不是所谓的金标准，自己编译一个不一样也没什么。
据此，README 里所有哈希验证内容已删除，.gitignore 忽略 dist/，dist/RtWorkQ.dll 和 verify-build.py
都移出仓库。仓库现在只有源码 + 文档 + 两个 helper。

构建改成可复现：三个工程（Base Mod / AutoUnlock / AutoPlayers）的 build.bat 都加了 /Brepro。
实测：不加时同名输出间隔两秒编两次得到不同哈希，加了就固定。
/Brepro 只在同一工具链内保证同哈希，换 MSVC 版本照样不同，但这已经不重要了。

工具链：本机是 Build Tools for Visual Studio 2026（18.7.4，MSVC 19.51.36248），
装在 C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools。还装了 VS 2022 Community
（17.14.34，在 D 盘），那是编 Frosty MCP 插件时装的另一套。build.bat 里 vswhere -latest
会挑最新那套，所以用的是 2026。

MSVC 工具链会自己更新（14.50 起与 VS 解耦，每 6 个月发一次），VS 安装器默认自动更新，
所以"同一个 VS"也会变二进制。

## 推送：git ls-remote / git push 能通，curl 不行

2026-10-01 实测：Bash 沙箱里 curl https://api.github.com 返回 HTTP 000、ping 不通，
但 git ls-remote 和 git push 正常。所以要推仓库直接推，别说"没网络"。

## 构建验证：重编译永远不等于原哈希

改注释不会影响二进制。重编译唯一的差异是链接器写进去的两处构建时间戳：
PE COFF 头的 TimeDateStamp，以及 debug 目录里 IMAGE_DEBUG_TYPE_REPRO(type=13) 条目的
TimeDateStamp。其余字节全同。

仓库根目录有 verify-build.py，把这两处清零后比对。实测通过：清完注释重新编译的 DLL
与已发布的 dist/RtWorkQ.dll 字节完全一致。

## src/build.bat 里那条 'vswhere.exe' is not recognized

不要再去追这个，已用 stderr 打标记二分定位到，发出者是微软自己的 vcvars64.bat，
我们的探测段完全干净。非致命，只走 stderr。（排查时注意：cmd 里 stdout 重定向到文件是带缓冲的，
stderr 不带，混在一个文件里顺序会错乱，必须用 stderr 打标记才能定位。）

兜底列表原本写死 VS 2019/2022，漏掉新版 VS（本机是 VS 18 BuildTools，装在
Program Files (x86) 下），已改成扫描 Microsoft Visual Studio\* 版本目录。

相关：[[bfn-build-switch]] [[bfn-fbmod-format]] [[bfn-autoplayers-hud-design]] [[bfn-unlock-dll-project]]
