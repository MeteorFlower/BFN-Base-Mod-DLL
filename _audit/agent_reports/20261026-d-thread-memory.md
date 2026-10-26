# AutoOffline.dll 线程与内存安全审计

日期: 2026-10-26
方向: 线程与内存安全（第 4 方向）
对象: src/AutoOffline.cpp（955 行），以及 third_party/minhook 的调用方式（只读，不审第三方本身）

审计方式: 纯静态阅读，未改任何文件，未运行游戏。
重入链与结构偏移用 IDA 库 BFN_2026_decrypted.exe.i64 核对（地址为绝对地址，模块基址 0x140000000，文件里的 rva 加 0x140000000 即得）。

构建参数取自 src/build.bat: cl /LD /O2 /MT /EHsc /W3 /Brepro。
MinHook 版本取自 third_party/minhook/README.md: v1.3.4（2025-03-28）。

严重度分级:
A = 可导致进程崩溃，或静默毁掉用户存档；
B = 特定条件下崩溃或丢数据；
C = 健壮性缺口，当前难触发但修起来很便宜。

---

## 0. 总览

最危险的是三件事，都是“游戏线程和 Worker 线程同时动 g_chars”这一类:

1. Worker 的 SaveStore 里 SaveSort 直接就地排序 g_chars，而游戏线程在同一个容器里 push_back 或整体赋值。要么 std::sort 在已释放的旧缓冲区上继续写（堆损坏），要么正在被序列化的 std::string 被撕裂（读越界崩溃，或写出垃圾内容）。
2. FindSavedCharacter 返回的是指向 g_chars 元素的裸指针，RestoreModel 拿它在没有 SEH 的代码里遍历；Worker 的排序/扩容会让这个指针悬空或指向被搬空的对象。这是进图加载路径上的崩溃，且时序与存档写盘高度耦合（改完皮肤马上进图正好撞上）。
3. 模型构造器 hook 里调用 recalc，recalc 经 1416B6CF0 到 1416B8930 会回调到我们自己挂钩的 1416B74C0，也就是重入 HookLoadoutEdit；重入里的 SnapshotModel 会把“恢复做到一半”的状态整份替换进 g_chars，随后 100 ms 内落盘。存档文件可能在第一次恢复时就被游戏自己的超标裁剪结果覆盖掉。这一段已在 IDA 里核对到具体调用点。

另有一个与线程无关但属于安装期内存安全的确定缺陷: InstallOneHook 先 MH_EnableHook 再由调用方发布 orig 指针，中间窗口里 HookModelCtor 会把 nullptr 当作模型返回给游戏。见 H1。

---

## 1. 线程与共享状态

共享状态清单（会跨线程的）:

- g_chars（301 行，std::vector<LoadoutCharacter>，内含 std::string 和三层嵌套 vector）
- g_save_dirty（478 行，普通 bool）
- g_log（153 行，FILE*，两个线程都会 fputs）
- g_dir、g_base、g_p3_value、各 orig/detour 函数指针（Worker 写一次，之后只读；除 orig 指针存在 H1 的发布顺序问题）

读写方:
- Worker 线程: SaveLoad（906 行，挂钩之前，无并发）、SaveStore/SaveSort（942 行）、SavePath、Log。
- 游戏线程: HookLoadoutEdit 到 SnapshotModel 到 SavePutCharacter（写）、HookModelCtor 到 RestoreModel 到 FindSavedCharacter（读）、Log。

### T1（A）SaveSort 就地改容器，与游戏线程的写并发

行号与原文:

    301: static std::vector<LoadoutCharacter> g_chars;
    307-313:
        for (LoadoutCharacter &e : g_chars) {
          if (e.id == c.id) {
            e = c;
            return;
          }
        }
        g_chars.push_back(c);
    374-375: std::sort(g_chars.begin(), g_chars.end(), ...);
    391:     for (const LoadoutCharacter &c : g_chars) { ... }

注意 386 行的 SaveStore 第一句就是 SaveSort()，它不是只读: 外层 vector 会按 id 重排，每个槽位的 options vector 也会被重排。也就是说 Worker 在“写” g_chars，不只是读。

交错场景一（外层扩容，最坏）:

    T_worker  SaveStore 到 SaveSort 到 std::sort，手里是 [begin, end) 两个指针，正在用移动赋值交换元素
    T_game    SnapshotModel 到 SavePutCharacter，charId 没找到，走 313 行 push_back
              push_back 发现 size == capacity，分配新块，搬移元素，然后 operator delete 旧块
    T_worker  std::sort 继续往旧块（已释放）里写

后果: 往已释放内存写。通常不是当场崩，而是污染堆元数据或别的对象，在之后的某次分配里崩在完全无关的子系统，日志上没有任何线索。属崩溃，概率取决于“新角色第一次改配置”是否正好落在一次存盘期间（存盘在 dirty 后 100 ms 内触发，存盘耗时毫秒级，窗口很小但存在）。

交错场景二（不扩容，同样致命）:

    T_worker  save 正在 391 到 415 行把 g_chars 序列化成 json，手里有 const LoadoutCharacter& 引用
    T_game    313 行 e = c 整体拷贝赋值同一个元素
              LoadoutCharacter 含 1 个 std::string 加 3 个 vector<LoadoutOption>，每个 option 又含 2 个 std::string

后果分两种:
- 被序列化的 std::string 被撕裂（指针来自旧缓冲区、长度来自新缓冲区），doc.dump 按超长长度去读，读越界，Worker 线程上发生访问违例。Worker 没有 __try、没有 try/catch，非主线程未处理异常等于整个游戏进程退出。属崩溃。
- 没崩的话，写进 json 的是半新半旧的值，下次启动按这份垃圾恢复，写进游戏权威表。属静默毁数据。

另一个方向: 313 行 e = c 在释放旧 std::string 缓冲区的同时，Worker 可能正在读那个缓冲区，读到的是已释放内容。

最小修法（不动业务逻辑）:

    static std::mutex g_saveMu;

- SavePutCharacter（306 行）整体加 lock_guard。
- SaveStore（386 行）改成先在锁内做一份深拷贝（std::vector<LoadoutCharacter> snapshot = g_chars;），出锁之后对 snapshot 排序并序列化。
- 不要在持锁期间调用任何游戏函数（见 R1，重入会自锁死，除非用 recursive_mutex；本方案不需要）。

### T2（A）FindSavedCharacter 的裸指针跨线程失效，且失效点在没有 SEH 的代码里

行号与原文:

    620-626:
        static const LoadoutCharacter *FindSavedCharacter(unsigned int charId) {
          for (const LoadoutCharacter &c : g_chars) {
            if (c.id == charId)
              return &c;
          }
          return nullptr;
        }
    631: unsigned int charId = *(unsigned int *)((unsigned char *)model + kModelCharId);
    632: const LoadoutCharacter *c = FindSavedCharacter(charId);
    642-653:
        for (int p = 0; p < kPresetCount; ++p) {
          for (const LoadoutOption &o : c->presets[p].options) {
            ... entries[count].key = o.key; entries[count].value = o.value; ...

交错场景:

    T_game    进图加载，模型构造器 hook 触发，RestoreModel 拿到 c = &g_chars[i]
    T_worker  同一时刻 dirty 触发 SaveStore 到 SaveSort，std::sort 把元素 i 移到别处，
              或外层 vector 因 push_back 扩容，旧块被释放
    T_game    642 行继续用 c 遍历 c->presets[p].options

后果:
- 没有扩容时: c 指向被移动过的对象，options 已被搬空（vector 的 size 变 0），count == 0，654 到 655 行直接 return。表现是“这次进图没恢复皮肤”，静默，用户以为 mod 坏了。
- 有扩容时: c 悬空，读的是已释放内存里的 vector 头。拿到的 data 指针和 size 都是垃圾，642 行的 range-for 会按垃圾 size 遍历已释放缓冲区。这一段（628 到 661 行）完全没有 __try 保护，访问违例直接崩进程，发生在加载路径上。

概率说明: 这不是纯理论。dirty 由“改配置”置位，Worker 在 0 到 100 ms 内写盘；而“改完配置马上进图/开一局”正好会让模型构造器在这个时间窗里跑。两者是同一动作触发的，相关性很强。

最小修法: 去掉“返回指针再遍历”的用法。在 T1 的锁内完成查找并把 options 复制进 RawEntry 数组，出锁后只带 count 和 entries 去调 RawApplyRestore。FindSavedCharacter 可以只返回索引，或者直接内联进 RestoreModel 的锁区。

### T3（B）g_save_dirty 非原子，存在丢更新

行号与原文:

    478: static bool g_save_dirty = false;
    544:   g_save_dirty = true;
    940-942:
        if (g_save_dirty) {
          g_save_dirty = false;
          SaveStore();

数据竞争本身是未定义行为（两个线程无同步地读写同一个非原子对象）。x86 上单字节读写不会撕裂，但语义上会丢更新:

    T_worker  940 行读到 true（上一次改动留下的）
    T_game    544 行置 true（新一次改动，数据已经写进 g_chars）
    T_worker  941 行写 false
    T_worker  SaveStore 开始。如果新改动落在 SaveStore 读 g_chars 之前读到的那部分之后，
              这次改动就没有任何机会再被写盘

后果: 静默丢一次存档（本次会话后续没有新改动的话，退出即丢）。概率不高（要求新改动正好落在存盘开始前后、且落在已序列化过的角色上），但后果是静默。

最小修法: 改成 std::atomic<bool>，Worker 用 exchange(false) 取走；SaveStore 失败时再 store(true) 重试。

### T4（B）SnapshotModel 可能被多个游戏线程同时进入（未验证）

HookLoadoutEdit（547 行）在游戏线程上跑，本身没有串行化假设。如果游戏在建模型阶段用作业线程并行构建多个玩家槽的模型，而构造器内部会调 recalc（已确认，见 R2），recalc 可能走到 edit funnel 到 HookLoadoutEdit，那么两个线程会同时进 SavePutCharacter，317 行级别的 vector 并发写，堆损坏。

未验证: 没有证据表明游戏的模型构造会在多线程里并行跑两个槽。标记为未验证，不要在报告里当成已经发生的缺陷。但 T1 的修法（一把锁）顺带覆盖了它，所以修法成本是零。

### T5（C）Worker 线程没有任何故障兜底

386 到 442 行（SaveStore）、938 到 944 行（循环）都没有 __try，也没有 try/catch。nlohmann::json 的分配失败、std::string 的 bad_alloc、上面 T1/T2 描述的任何越界读，只要发生在 Worker 线程，就是未处理异常，Windows 直接结束进程。游戏看起来是“自己闪退”，日志最后一行还停在正常内容。

最小修法: Worker 的循环体包一层 try/catch(...)，捕获后 Log 一行并继续；SaveStore 里对 g_chars 的访问按 T1 改成读快照，越界读的概率随之消失。

### T6（C）Log 在两个线程上并发写同一个 FILE*

161 到 179 行: fputs(line) 和 fputc('\n') 是两次独立的锁操作，两个线程同时 Log 时行会交错（时间戳和正文被别的行插进来）。MSVC 的 stdio 对单个 FILE 有内部锁，所以不会破坏 FILE 结构本身，只是日志难读。

另外 895 行 fopen 失败时 g_log 为 null，Log 静默丢弃全部内容，也就是说“目录不可写”这种情况下所有“大声失败”的机制一起消失。这与项目约定里的“要么正常工作要么大声失败”冲突，归到交叉线索。

---

## 2. 重入

### R1（A）已确认的重入: 模型构造器 hook 到 recalc 到 edit funnel 到自己的 HookLoadoutEdit

调用链（IDA 核对，均为本文件挂钩的目标）:

    HookModelCtor（663 行）
      到 RestoreModel（628 行）
      到 RawApplyRestore（601 行）
      到 g_recalc = 0x1416ABF60（kRecalcRva，579 行常量）
      到 0x1416B6CF0（recalc 里有 4 个调用点: 0x1416AC0FF / 0x1416AC190 / 0x1416AC1B7 / 0x1416AC1DB）
      到 0x1416B8930（0x1416B6CF0 里的条件分支: 当累加值 v4 > *(u32*)(model+172) 时调用）
      到 0x1416B74C0（0x1416B89DD 处的调用，就是 kLoadoutEditRva，我们的 HookLoadoutEdit）

0x1416B8930 反编译要点（摘录）:

    if ( v4 <= *(_DWORD *)(a3 + 172) ) { *(_DWORD *)(a3 + 192) = v4; }
    else { sub_1416B8930(a1, a2, a3, 0LL); *(_DWORD *)(a3 + 192) = 0; }

以及 0x1416B8930 内部:

    *(_DWORD *)(v12 + 40) = v14;                                // v14 = dword_14465346C
    sub_1416B74C0(a1, a2, *(a3 + 216), *(v12 + 24), v14);       // 0x1416B89DD

也就是说: 我们在恢复时写进权威表的数据，如果总量超过模型自己的预算字段 (model+172)，游戏会把超标项逐个改写成 dword_14465346C（默认/无效值），而每一次改写都经过我们挂钩的 edit funnel。

重入后的具体时序（同一线程，非数据竞争，是逻辑重入）:

    1. RawApplyRestore 逐条 g_write_auth（把存档写进权威表）
    2. g_sync_preset 逐槽位重灌缓存
    3. g_recalc 发现超预算，进入 0x1416B8930，逐个调用 0x1416B74C0 把条目改回默认值
    4. 我们的 HookLoadoutEdit 被调用，先执行 g_edit_orig（默认值真的写进去了）
    5. 接着 g_model_lookup 取模型，SnapshotModel 读到的正是“恢复做到一半、部分条目已被改回默认”的模型
    6. SavePutCharacter 用这份快照整份覆盖该角色的存档记录，并置 g_save_dirty
    7. Worker 在 100 ms 内把它落盘

后果: 用户存档被游戏自己的“超标裁剪”结果永久替换。下次启动按这份已经被裁剪的数据恢复，原始配置无从找回。属静默毁数据，且是“第一次恢复就发生”的那种，不是偶发。

概率: 取决于是否走到超预算分支（v4 > model+172），与具体配置有关，未验证实际触发频率；但这条路径在代码上是通的，且被我们自己在同一次调用里必然经过。

同一路径还有两个次级风险:
- 第 5 步的 g_model_lookup 在构造器尚未返回（模型可能还没登记进管理器）时可能返回 null。返回 null 时不会有快照，也就不会毁数据。这一点未验证，取决于 0x1416AD770 内部登记模型的先后。存在“有时毁有时不毁”的可能。
- 若 g_write_auth / g_sync_preset 中途出异常被 615 行 __except 捕获，恢复是半完成的，但上面的第 6 步照样会把半完成状态落盘（见 S2）。

修法（最小）:

    static thread_local int g_hook_depth = 0;

在 HookModelCtor 和 HookLoadoutEdit 顶部各加一个自增/自减的守卫，SnapshotModel 只在 g_hook_depth == 1 时执行。这样“在恢复过程中触发的 edit”只执行原始函数，不再反向覆盖 g_chars。这与 T1 的锁不冲突（锁不跨游戏调用）。

已排除: 没有找到无界递归。HookLoadoutEdit 自己的调用方链（0x1416B74C0 到 0x1416AEB60 / 0x141009BC0 / 0x141766580 / 0x141765910，以及 0x141765910 的 13 个被调）在两层深度内都不回到 recalc 或构造器，所以重入深度最多加 1，不会栈溢出。这只是两层扫描的结论，不是形式化证明，按“未验证的全链路”对待。

### R2（B）模型构造过程中 edit hook 就会被触发，SnapshotModel 会读半成品模型

已确认 0x1416AD770（构造器）直接调用 0x1416ABF60（recalc，调用点 0x1416ADDDD），并且构造器自己也调 0x1416AF1D0（sync，调用点 0x1416ADC6F）。所以在我们执行 g_ctor_orig 的过程中，游戏自身就会经 recalc 到 0x1416B6CF0 到 0x1416B8930 到 edit funnel，触发我们的 HookLoadoutEdit。

此时构造器还没返回，模型对象处于“部分构造”状态。HookLoadoutEdit 用 g_model_lookup 取到它以后，SnapshotModel 会去读 +216（角色 id）和 +280（三个槽位的哈希表）。如果这两个字段已经写好，读到的是真实数据；如果哈希表还在建，读到的是空表或半成品，SEH 只挡“没映射的地址”，映射着但内容是垃圾的读取会被当成合法数据接受，然后写进存档。

后果: 可能存进垃圾键值对，之后由恢复侧写进游戏权威表。属静默污染。未验证: 没有核对构造器里 0x1416ADDDD 那次 recalc 相对于 +280 初始化的先后顺序，所以无法断言一定会读到半成品。修法同 R1 的深度守卫。

### R3（C）各 hook 的防重入现状

逐个核对了 8 个 detour，全部没有任何防重入标记（没有 thread_local 深度、没有 in_hook 标志、没有原子交换）:

- HookOfflineFix（733 行）: 不调用原函数，天然不会重入自己。
- HookSessionMask（748 行）: 调 0x140447450（纯 getter），未发现回调路径。
- HookProfileCtor（756 行）: 调原函数后只写 +0x130，不回调。
- HookReport（764 行）: 透传，未发现回调。
- HookNameGet（803 行）: 调原函数后可能返回假对象，不回调。
- HookLoadoutEdit（547 行）: 可被 R1 路径重入，无保护。
- HookModelCtor（663 行）: 是 R1 的起点，无保护。
- HookNameGet 与 HookSessionMask 依赖 _ReturnAddress 判调用点: 若游戏内部另有转发（例如经 thunk 间接调），判据失配只会退化成“不做替换”，不会误伤，属安全方向。

---

## 3. SEH

### S4（先给结论）POD 边界: 成立；但保护范围不止“读内存”

四个 __try 分别在 183 行（SafeReadBytes）、483 行（RawReadModel）、553 行（HookLoadoutEdit 包住 g_model_lookup）、603 行（RawApplyRestore）。

逐个核对“__try 所在函数里有没有需要析构的局部对象”:
- SafeReadBytes: 参数全是指针和 int，无局部对象。成立。
- RawReadModel: 参数全是指针和 POD，无局部对象。成立。
- HookLoadoutEdit: 局部只有 void *model，POD。成立。
- RawApplyRestore: 参数全是指针、unsigned int、int，无局部对象。成立。

所以 MSVC 的 C2712（__try 函数里不许有需要展开的对象）不会触发，编译通过也印证了这一点。带 std::vector/std::string 的对象都在 SnapshotModel（522 行）、RestoreModel（628 行）、SaveStore（386 行）里，这三个函数都没有 __try，边界是干净的。

但“边界成立”不等于“异常安全”，下面三条是实际缺口。

### S1（B）__except 不过滤异常码，会吞掉 C++ 异常和游戏自己的异常

行号与原文（483 与 603 行同形）:

    } __except (EXCEPTION_EXECUTE_HANDLER) {
      return -1;
    }

EXCEPTION_EXECUTE_HANDLER 会匹配全部异常码，包括 C++ 异常 0xE06D7363，以及 RaiseException、调试断点。RawApplyRestore 的 __try 横跨 g_write_auth / g_sync_preset / g_recalc 三个游戏函数（604 到 613 行），所以:

- 游戏代码在这三个调用里抛出的 C++ 异常，会被我们当作“内存故障”接住，然后返回 -1，我们继续正常返回，游戏继续跑。异常被吞掉，游戏那些帧上的析构不会执行（/EHsc 下 __except 与 C++ 展开的关系属于未定义/实现相关，具体的展开行为标为未验证），后果是锁、引用计数、迭代器状态留在半更新状态。
- 游戏若用 RaiseException 做内部控制流（Frostbite 里常见），同样被吞。

后果: 概率低（要求这三个函数抛异常），但一旦发生，后续崩溃点离现场很远。

修法:

    __except (GetExceptionCode() == EXCEPTION_ACCESS_VIOLATION ||
              GetExceptionCode() == EXCEPTION_IN_PAGE_ERROR ||
              GetExceptionCode() == EXCEPTION_ILLEGAL_INSTRUCTION
              ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {

只接硬件类异常，其它原样放行。

### S2（B）RawApplyRestore 抓到异常后，半完成状态会被当成成功落盘

603 到 617 行: 写权威表是 `for (i < count) g_write_auth(...)`，中途出错就跳到 615 行返回 -1。此时前面的若干条已经写进去了，没有回滚。656 行只打一行日志就 return，HookModelCtor 照常把 model 返回给游戏。

叠加 R1: recalc 里那次重入触发的 SnapshotModel 会把这份半完成状态存进 g_chars 并置 dirty。也就是说，“恢复失败”这件事在存档上表现为“恢复成功了一部分”，而这一部分随后覆盖了原始存档。

后果: 静默的半恢复加存档覆盖。概率: 需要内存故障或 S1 的异常，低；但一旦发生不可能自愈。

修法: 至少在 RawApplyRestore 返回 -1 时，抑制本次调用链内的 SnapshotModel（同一个 thread_local 深度标志可用），并且不要把这次状态标记为 dirty。

补充一个容易忽略的点: 603 到 614 行的 __try 覆盖的不只是游戏函数，还覆盖了 R1 那条重入路径上我们自己的 detour。也就是说 HookLoadoutEdit 到 SnapshotModel 到 SavePutCharacter 到 std::vector 的 push_back 全都跑在这个 __except 里面。后果有两层:
- 我们自己代码里的越界读或堆损坏触发的访问违例，会被这个外层 __except 吞掉，然后以“restore: fault while applying character %u”的形式记一行日志。日志指向恢复失败，实际故障在快照路径上，现场被改写。
- 堆已经损坏的情况下吞掉异常继续跑，游戏后面会在别处崩，且这条日志会误导排查方向。
所以 S1 的异常码过滤在这里更必要: 至少不要把我们自己代码里的 C++ 异常（bad_alloc）也当成“游戏内存读失败”。

### S3（B）RestoreModel 里有一批游戏内存读在 SEH 之外

行号与原文:

    631: unsigned int charId = *(unsigned int *)((unsigned char *)model + kModelCharId);
    635: void *ui = *(void **)(g_base + kUiManagerRva);
    642-653: for (const LoadoutOption &o : c->presets[p].options) { ... }

631 行是解引用游戏对象；635 行是读游戏模块里的全局槽（地址本身有效，值可能是垃圾指针，636 行只判了 null 没判有效性）；642 行是 T2 描述的那次裸指针遍历。这三处都在任何 __try 之外，一旦 model 是悬空/半构造指针，就是游戏线程上的未捕获访问违例，进程直接退出，日志停在上一行。

修法: 631 行改成一个 SafeReadU32 之类的 POD 小函数（照 SafeReadBytes 的写法），642 行的遍历按 T2 挪进锁内并复用已复制出来的数据，635 行读到的 ui 在传给 RawApplyRestore 之前只能判 null，进一步的有效性没法验证（可以标注为已知风险）。

---

## 4. 缓冲区与指针

### B0（结论，别“修”错方向）模型结构偏移是对的

文件里 456 到 462 行的注释把哈希表字段写成“+8 桶数组 / +16 桶数 / +20 元素数”，而代码（498 到 500 行）是以 preset+8 为 map 基址，再读 map+8（即 preset+16）为桶数组、map+16（即 preset+24）为桶数。注释的编号看起来像相对槽位，代码是相对 map 基址，两者读起来差 8 字节，很容易被后来人当成 bug 去“修”。

用游戏自己的实现核对过，代码是对的:
- 0x141009BC0（插入）: 用 `*(u32*)(a1+16)` 取桶数做取模，用 `*(u64*)(a1+8)` 取桶数组，并 `++*(u32*)(a1+20)` 维护元素数。
- 0x14047C1C0（清空）: `v2 = *(u64*)(a1+8)`，`count = *(u32*)(a1+16)`，清完把 `*(u32*)(a1+20) = 0`。
- 0x1416AF1D0（sync，我们恢复侧调的 0x1416AF1D0）对该容器做的第一件事就是 `sub_14047C1C0(a5 + 8)`，即容器基址 = preset+8。
- 节点 16 字节、键在 +0、值在 +4、next 在 +8，也与代码一致（插入函数只写 +0 键和 +8 next，值由调用方写 +4）。

结论: 偏移不用改。只有注释的编号基准容易误导，属于注释方向，列进交叉线索。

### B1（B）哈希桶校验不足，垃圾数据会被当成合法配置

行号与原文:

    499-505:
        unsigned int buckets = *(unsigned int *)(map + kMapBucketCount);
        unsigned char **arr = *(unsigned char ***)(map + kMapBuckets);
        if (arr && buckets && buckets <= kMapMaxBuckets) {
          for (unsigned int b = 0; b < buckets; ++b) {
            unsigned char *node = arr[b];
            int guard = 0;
            while (node && n < cap && guard < (int)kMapMaxBuckets) {

校验只有三条: arr 非空、buckets 非零、buckets 不超过 4096。缺的两条恰好是最有用的:
- 元素数（map+20，游戏自己维护的那个）完全没读。元素数是判断“这个桶数/链结构是否自洽”的最直接交叉验证。
- 桶数组的实际长度无从校验，4096 这个上界等于允许我们读 32KB 的数组。

触发条件与后果: 模型处于半构造（R2）、被重建（注释里 566 行提到模型会重建）、或字段被别的东西写坏时，buckets 可能是个“看起来合理”的垃圾值。此时 arr[0..buckets-1] 里只要落在已映射内存，就不会触发 SEH，读到的垃圾键值会被当作真实配置: 存进 json，下次启动经 g_write_auth 写进游戏权威表。表现是配置里出现不存在的选项、或角色外观异常，离现场很远。属静默污染，不是崩溃。

若落到未映射页，SEH 接住，RawReadModel 返回 -1，SnapshotModel 打一行“fault while reading the model, skipped”并放弃，行为是可接受的。

最小修法: 加读元素数（map+20），要求 `count <= kRawMaxOptions` 且 `count != 0` 且 `buckets <= 1024`；循环改成按 count 累计（总数到 count 就停），链上的 guard 保留作第二道。任一校验失败就整次快照作废（返回 -1），不要“跳过这一槽继续”。

### B2（B）kRawMaxOptions 截断是静默的，且会整份覆盖旧存档

行号与原文:

    505: while (node && n < cap && guard < (int)kMapMaxBuckets) {
    514: presetStart[p + 1] = n;
    543: SavePutCharacter(c);

cap = 1024（463 行）。达到 cap 后，内层 while 直接停止，外层继续跑完剩下的桶和槽位，presetStart 里后面的槽位起点都等于 cap（遍历时贡献 0 条），函数照常返回 n == cap，没有任何日志。

后果: 单角色选项超过 1024（或数据被污染导致虚假条目很多，见 B1）时，超出的部分被丢弃，而 SavePutCharacter 是整份替换（307 到 313 行），所以存档里原来那些选项被永久删掉。完全没有提示。这跟恢复侧不一样（恢复侧 644 到 646 行至少有日志）。

最小修法: RawReadModel 里当 n 达到 cap 时置一个溢出标志，返回 n 的同时让调用方打一行日志；并且在这种情况下按“快照失败”处理（不覆盖存档），而不是把截断结果当真。

### B3（C）恢复侧截断只 break 内层循环

行号与原文:

    642-652:
        for (int p = 0; p < kPresetCount; ++p) {
          for (const LoadoutOption &o : c->presets[p].options) {
            if (count == kRawMaxRestore) {
              Log("!! restore: too many values for character %u, truncated", charId);
              break;

break 只跳出内层，外层继续，于是最多打 3 行重复日志，实际恢复的是“前 1024 条”。后果: 截断后部分槽位完全没恢复（配置看起来“丢了一半”），有日志但内容有误导（看起来像三个槽位都截断了）。最小修法: 用标志位配合外层 break，或者把 break 换成 goto/return。

### B4（C）游戏线程上的栈用量

    523: RawOption raw[kRawMaxOptions];        // 1024 * 8 = 8 KB
    640: RawEntry entries[kRawMaxRestore];      // 1024 * 12 = 12 KB

raw 在 SnapshotModel 里，跑在调用 edit funnel 的游戏线程上；entries 在 RestoreModel 里，跑在模型构造线程（加载路径）上，通常已经比较深。R1 的重入会再叠一层 8KB。若某个线程的栈较小（游戏自家作业线程常见 64KB 到 256KB），有溢出风险。

SEH 抓不住栈溢出（除非配合 _resetstkoflw），所以后果是立即崩溃且没有日志。概率低，但修法很便宜: 把两个上限降到 256（2KB / 3KB），或者把数组放成 `static thread_local`（POD，无析构问题）。

### B5（C）g_fakeNameObj 不是游戏字符串类型的真实实例

行号与原文:

    800-801: static const char g_emptyName[1] = {0};
             static void *g_fakeNameObj[2] = {nullptr, nullptr};
    806:     return (void *)g_fakeNameObj;

按注释，唯一消费者是 0x141727CBB 那一处，只做 `mov rcx,[rax] / cmp byte[rcx],0`，也就是只读第一个指针指向的首字节。当前用法没问题。风险在于: 我们把一个静态的、只有 16 字节的伪对象当作游戏的字符串/名字对象交出去。如果调用方改成拷贝、赋值、析构这个对象（这类对象通常自带小字符串优化和堆指针），就会对一个静态地址调用 operator delete，或者往 g_emptyName 写入。后者是 const 数据，落在只读段，写入直接访问违例。

未验证: 0x141727C50 里那一处具体做了什么（没有反编译该函数），只按文件注释的结论采用。建议至少把 g_emptyName 改成可写的 16 字节缓冲区（带一个合法的空串表示），并在注释里写死“此对象只可读，不可析构”。

### B6（C）RawApplyRestore 跨多次游戏调用持有 model 与 ui

行号与原文:

    604: unsigned int charId = *(unsigned int *)((unsigned char *)model + kModelCharId);
    605-606: for (i < count) g_write_auth(ui, slot, charId, ...);
    607-608: unsigned char *presets = *(unsigned char **)((unsigned char *)model + kModelPresetArray);
    613: g_recalc(mgr, slot, model);

presets 是在写循环之后重新读的（说明写这个函数时已经考虑了模型可能变），但 model 和 ui 本身在 count 次游戏调用期间一直持有，最后又交给 g_recalc。如果写权威表的过程会重建模型或换掉 UI 管理器，这里就是悬空指针。

未验证: 没有核对 0x141766580 是否可能重建模型（它的被调只有 0x14175DE10 和 0x140819AF0，看起来是容器和字符串操作，不像重建）。列出来是因为“模型会重建”这个前提已经被逆向确认，而这个函数是唯一跨调用持有模型指针的地方。

关于“别缓存指针”这条要求: 其余地方都合规。g_base 是模块基址，稳定；g_model_lookup / g_write_auth / g_sync_preset / g_recalc 是代码地址，稳定；ui 每次从 g_base + 0x4659DB0 现读（635 行）；model 在 HookModelCtor 和 HookLoadoutEdit 里都是取到即用。没有跨帧缓存游戏对象。

---

## 5. 文件写入

### F1（B）dirty 先清后存，任何写失败都永久丢这次存档

行号与原文:

    940-942:
        if (g_save_dirty) {
          g_save_dirty = false;
          SaveStore();

SaveStore 有 5 个失败出口（424 fopen 失败、431 写失败或 fclose 失败、436 MoveFileEx 失败），全部只打一行日志返回 false，而 dirty 已经在 941 行被清掉，并且没有重试。也就是说: 磁盘满、目录只读、存档被别的进程以拒绝共享的方式打开（编辑器、杀软扫描、OneDrive 同步、备份代理），这几种最常见的情况，结果都是“日志里有一行，用户这次改的配置永久丢失”，直到下一次改配置才可能写成功。

最小修法: `if (!SaveStore()) g_save_dirty = true;`（配合 T3 的 atomic）。

### F2（C）没有 FlushFileBuffers，也没有 MOVEFILE_WRITE_THROUGH

    427-435: fwrite 到 tmp，fclose，然后 MoveFileExA(..., MOVEFILE_REPLACE_EXISTING)

同卷改名在 NTFS 上是原子的，所以“读者永远看不到半个文件”这个设计目标是达到了。但改名只保证元数据顺序，数据页可能还在缓存里。断电或硬复位时可能得到“文件名换了、内容是空的或不完整”的结果，而旧内容已经被替换掉，等于存档被清空。概率很低（需要掉电/蓝屏），但这是存档类程序最不该留的缺口。

最小修法: fclose 之前对句柄 FlushFileBuffers（需要改成 CreateFile/WriteFile，或者 _commit(_fileno(f))），并给 MoveFileExA 加 MOVEFILE_WRITE_THROUGH。

### F3（C）目标被占用时删掉 tmp，等于把新数据扔掉

    435-439:
        if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING)) {
          Log("!! save:cannot replace %s (err=%lu)", ...);
          DeleteFileA(tmp.c_str());
          return false;
        }

改名失败最常见的原因不是“tmp 有问题”，而是“目标文件被别人打开着”。此时删掉 tmp 丢掉的是唯一一份新数据。配合 F1，这次改动彻底没了。

最小修法: 改名失败时保留 tmp（下次写会覆盖，不会堆积），并且按 F1 让 dirty 保持为真、下一轮重试。

### F4（C）硬杀进程会留下 autooffline_save.json.tmp，没人清理

如果进程在 fwrite 中途被杀（任务管理器结束进程、崩在 SaveStore 里），tmp 会留在游戏目录。启动时 SaveLoad（316 行）只读 autooffline_save.json，从不看 tmp 也不删它。文件不会造成错误，只是永远躺在那儿，容易被用户误认为是残留垃圾。

最小修法: Worker 启动时无条件 DeleteFileA(SavePath() + ".tmp")。

### F5（C）退出时不做最后一次落盘

DllMain（947 行）只处理 DLL_PROCESS_ATTACH，没有 DLL_PROCESS_DETACH 分支。Worker 是 100 ms 轮询，所以进程退出前最后 100 ms 内的改动必然丢失。注释（936 到 937 行）说“间隔要短，玩家改完立刻关游戏也不能丢”，但只把间隔压到 100 ms 并不能覆盖“改完立刻 Alt+F4”。

修法: 在 DllMain 的 DLL_PROCESS_DETACH 里，如果 g_save_dirty 为真就同步 SaveStore 一次（注意此时其它线程可能已被终止，见 T7 的注意事项，只能做最小动作、不能分配太多）。或者在每次 SnapshotModel 之后立刻写（代价是频繁 IO，属性能方向，不在此展开）。

### T7（C）进程退出时静态 g_chars 的析构可能与 Worker 的写入交叉

g_chars 有非平凡析构（vector 套 string），DLL 卸载时 CRT 会销毁它。ExitProcess 的顺序是“先终止其它线程，再跑 DLL detach”，所以正常情况下不会交叉。但如果 Worker 是在 SaveSort 中途被终止的（它的 vector 内部指针正处于搬移中间态），随后 g_chars 的析构会按撕裂的指针释放，退出阶段多一次崩溃。后果只是退出时多一个崩溃框，不影响存档（此时 json 已在盘上）。列出来是因为修 F5 时容易忽略这一点: 析构期间不要再让任何线程碰 g_chars。

---

## 6. Hook 安装时机与 MinHook

### H1（A）orig 指针在 MH_EnableHook 之后才发布，存在把 nullptr 当模型返回给游戏的窗口

行号与原文:

    671-693（InstallOneHook）:
        st = MH_CreateHook((LPVOID)target, detour, &orig);
        ...
        st = MH_EnableHook((LPVOID)target);     // 684 行，hook 已经生效
        ...
        if (origOut) *origOut = orig;           // 689 行，orig 才交出去
    703-705:
        if (InstallOneHook(..., &orig, "loadout edit hook"))
          g_edit_orig = (LoadoutEditFn)orig;    // 705 行，才发布
    709-711:
        if (InstallOneHook(..., &orig, "model constructor hook"))
          g_ctor_orig = (ModelCtorFn)orig;      // 711 行

窗口 = 684 行 EnableHook 返回到 705/711 行赋值之间。这段里任何游戏线程调用这两个函数都会进我们的 detour，而 g_edit_orig / g_ctor_orig 还是 nullptr。

后果:
- HookModelCtor（665 行）: `void *model = g_ctor_orig ? g_ctor_orig(...) : nullptr;` 然后 `return model;`。游戏拿到 nullptr 当模型，构造器调用点（0x1416AE140 内 0x1416AE299）后面必然解引用，加载路径上确定崩溃。这是本报告里唯一“一定崩、不依赖时序巧合”的内存安全缺陷，只需要正好有一次模型构造落在这个微秒级窗口里。
- HookLoadoutEdit（549 行）: 原函数不会被调用，玩家的这次编辑被静默丢弃，随后 SnapshotModel 读到未修改的模型，等于这次改动没发生。

注意另外两个安装器是对的: InstallInteractionHook 在 825 行先赋 g_nameget_orig、826 行才 Enable；InstallHooks 的表循环在 859 到 866 行先赋 orig、867 行才 Enable。所以只有走 InstallOneHook 的这两条有这个问题。

最小修法: 把 EnableHook 挪到 origOut 赋值之后。

    st = MH_CreateHook(...);
    if (origOut) *origOut = orig;
    st = MH_EnableHook(...);

调用方要在 InstallOneHook 之前就把全局指针准备好（或者让 InstallOneHook 直接接收一个二级指针）。更彻底的做法是先把所有 hook 都 Create 好、所有 orig 发布完，再逐个 Enable。

### H2（C）MinHook 自己会冻结全部线程，我们不需要额外动作；但有两个它管不到的残余窗口

MinHook v1.3.4 的 EnableHook（src/hook.c 的 EnableHook 到 Freeze 到 EnableHookLL 到 Unfreeze）流程:
1. EnterSpinLock。
2. Freeze: CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD) 枚举本进程其它线程，逐个 OpenThread + SuspendThread，然后 ProcessThreadIPs 用 GetThreadContext/SetThreadContext 把“正好停在将被覆盖的 5 字节里的 RIP”改写到跳板对应位置（FindNewIP/FindOldIP）。
3. EnableHookLL: VirtualProtect 改可写，写 5 字节 jmp（或短跳加长跳），再改回保护。
4. Unfreeze: 逐个 ResumeThread。

也就是说“要不要额外暂停线程”这个问题的答案是: 不需要，MinHook 已经做了，而且它比我们自己写 suspend 更完整（它会修正停在补丁区里的 IP）。我们的 Worker 在冻结窗口内只调用 EnumerateThreads（MinHook 自己的私有堆）、OpenThread/SuspendThread、VirtualProtect，不碰 loader lock 也不碰进程堆，所以不会和“被挂起的线程正持有某把锁”形成死锁。这一点核对过了，是安全的。

残余窗口（MinHook 自身限制，我们这边只能知情）:
- SuspendThread 失败时 MinHook 把该线程标记为“未挂起”然后继续打补丁，返回值仍然是 MH_OK。也就是说“hooked OK”这行日志不保证真的原子。一个未能挂起、且正好在执行目标函数前 5 字节的线程，可能执行到半条 jmp 上。
- 快照之后新建的线程没有被冻结，它可能从函数入口开始执行，正好撞上写入中间态。

可做的缓解: 没有能完全关闭的办法（除非注入更早、在目标函数还没被任何线程用过时装好）。当前策略已经是“字节一出现就装”，这是最优点，不必改。真正能加的是: 安装前给目标函数所在页做一次“是否已被调用”的观测是做不到的，所以只能接受。建议在日志里明确写一句“hooked（MinHook 已冻结其它线程，但无法保证全部挂起成功）”，避免以后误以为这是绝对原子。

### H3（C）部分安装失败不回滚

834 到 876 行按表顺序装，每条独立判断成功与否并 continue。patch 1（0x156FA30）的 detour 是直接 return 1、不调用原函数的（733 到 736 行），一旦它装上，游戏行为立刻改变；如果后面的条目失败，进程就停在“改了一半”的状态，只有一行日志，没有任何补救或提示。按项目约定“要么正常工作要么大声失败”，这里属于后者不合格。

修法: 记录失败条数，全部装完后如果有失败，写一行醒目的汇总（或者在全部 Create 成功之前不 Enable 任何一条，做成两阶段提交）。

---

## 7. 未验证清单

- T4: 游戏是否会在多个线程上并行构建两个玩家槽的模型（决定 SnapshotModel 会不会并发重入）。
- R1 的实际触发频率: 恢复后总量是否经常超过 model+172 从而走 0x1416B8930 分支。路径已确认，概率未测。
- R1 第 5 步: 构造器尚未返回时 g_model_lookup 是否已经能查到该模型（决定重入时到底会不会产生快照）。
- R2: 构造器内部 0x1416ADDDD 那次 recalc 相对于 +280 槽位初始化的先后（决定会不会读到半成品）。
- S1: /EHsc 下 C++ 异常穿过 __except(EXCEPTION_EXECUTE_HANDLER) 的具体展开行为（确认会被吞，但析构是否执行的细节未在真机验证）。
- S3: 635 行读到的 UI 管理器指针是否可能非空但无效。
- B5: 0x141727C50 在 0x141727CBB 处对返回对象除了读首字节还做了什么。
- B6: 0x141766580 写权威表是否会重建模型或换掉 UI 管理器。
- H2: 实测中有没有出现 SuspendThread 失败（MinHook 不暴露该信息，只能靠现象推断）。

---

## 8. 交叉线索（各一句话，不展开）

- 正确性方向: 522 到 545 行在 charId == 0 或 n == 0 时直接 return，用户把一个角色的配置全部清空后，存档里的旧记录不会被清除，下次仍会恢复旧配置。
- 正确性方向: 456 到 462 行的偏移注释编号基准与代码不一致（代码正确，见 B0），容易被后来人误改。
- 优化方向: Log 每次 fputs 加 fflush，且会被游戏线程在模型构造路径上调用，属阻塞 IO 落在热路径上。
- 优化方向: SaveStore 每 100 ms 最多一次全量序列化，与业务量无关。
- 注释方向: 566 到 574 行说明了为什么选这个挂钩点，但没有写“模型会被重建、指针不可跨调用持有”这个前提，B6 的跨调用持有 model 正好踩在这个前提上。
- 正确性方向: 899 行 g_base 与 905 到 906 行 LoadP3Value/SaveLoad 的顺序没问题，但 g_base 是非原子全局，被游戏线程的 detour 读取（实际由 EnableHook 的内部同步与 x86 存储序兜住）。
- 生命周期方向: 947 到 955 行在 DllMain 里 CreateThread，没有对自身模块做 pin；若游戏对 RtWorkQ.dll 调 FreeLibrary，Worker 会执行已卸载内存。用 GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_PIN) 可以一行解决（属本方向的边界，列出来供决策）。
- 失败可见性: 895 行 fopen 日志失败时全部日志静默丢弃，与项目“不要静默降级”的约定冲突。

---

## 9. 最小修法清单（按性价比排序）

1. H1: InstallOneHook 里把 EnableHook 移到 origOut 赋值之后。3 行改动，消掉唯一的确定性崩溃窗口。
2. T1 + T2 + T3: 一把 std::mutex 加 std::atomic<bool>。SavePutCharacter 全体加锁；RestoreModel 在锁内完成查找和 options 复制；SaveStore 在锁内做深拷贝后出锁序列化；dirty 用 exchange，失败回置。这是本报告里收益最大的一处。
3. R1 + S2: 加 thread_local 深度守卫，SnapshotModel 只在最外层执行；恢复失败时抑制快照。约 10 行。
4. F1 + F3: SaveStore 失败时保持 dirty 为真、保留 tmp，下一轮重试。
5. B1 + B2: 读 map+20 的元素数做交叉校验；达到 cap 时按失败处理并记日志。
6. S1: __except 加异常码过滤，只接访问违例和页错误。
7. S3: 631 行的 model 字段读取搬进 SafeRead 风格的小函数。
8. B4: 把 kRawMaxOptions / kRawMaxRestore 降到 256，或改成 static thread_local。
9. F2: FlushFileBuffers 加 MOVEFILE_WRITE_THROUGH。
10. F4 + F5: 启动清 tmp；DLL_PROCESS_DETACH 做最后一次落盘。

以上 1 到 3 项合起来，可以把本方向 A 级风险全部消掉。
