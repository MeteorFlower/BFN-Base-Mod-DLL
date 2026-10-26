# BFN Base Mod - source code

Source for the DLL and helper scripts shipped with the Nexus release
**"Base Mod for the New Version"** for *Plants vs. Zombies:
Battle for Neighborville*.

This repository exists so that anyone - players, and Nexus Mods staff reviewing
the upload - can read exactly what the files do before running them.

---

## ⚠️ Why the upload gets flagged as "suspicious"

The Nexus upload is flagged by the automated safety check, and antivirus tools
may flag `RtWorkQ.dll` too. **This is a false positive, and here is precisely
why it happens:**

**1. `RtWorkQ.dll` is a DLL proxy.**

The mod works by *DLL search-order hijacking*. The game process calls
`LoadLibrary("RtWorkQ.dll")` by bare name, so Windows looks in the game's own
folder first - and loads ours instead of the system copy in `System32`.

That is a legitimate, decades-old modding technique. It is also a technique
malware uses, so **any DLL proxy trips pattern-based scanners**. There is no
way to ship this mod without tripping them.

Note that the game never calls any function *from* `RtWorkQ.dll` - the file
name is only used as an entry point. Our DLL exports nothing. See
[How it works](#how-it-works) below.

**2. The `.bat` files rename and copy files inside the game folder.**

`1-disable-eaac.bat` renames `EAAntiCheat.GameServiceLauncher.exe` to
`.exe.bak` and copies `RtWorkQ.dll` into the game folder.
`2-enable-eaac.bat` puts the anti-cheat launcher back, removes that copy of
`RtWorkQ.dll` and also removes `CryptBase.dll`, a Frosty Mod Manager leftover
the anti-cheat rejects. `3-clear-save.bat` deletes your saved loadout.

They are plain text. **Open them in Notepad and read every line.** They contain
no obfuscation, no downloads, no encoded blobs.

**3. What the DLL does *not* do.**

- It does **not** connect to the network. There is no socket, no HTTP, no WinINet.
- It does **not** read, collect, or transmit any personal data.
- It does **not** inject into another process. It *is* the process - the game loads it.
- It does **not** modify any file belonging to the game. It writes two files next
  to itself: `autooffline_log.txt`, and `autooffline_save.json`, which records
  which skins and perks you have **equipped**. It does not store or change what
  you own: no unlocks, no items, no progress.
- It does **not** rewrite the body of any game function. It installs a small
  number of entry hooks, listed below - each one is a jump at the function's
  first bytes plus a trampoline, and it is gone when the game exits.

---

## What's in here

| Path | What it is |
|---|---|
| `src/AutoOffline.cpp` | The DLL source. This is the whole program. |
| `src/build.bat` | Builds it with MSVC. |
| `third_party/minhook/` | MinHook, BSD-2-Clause, vendored and compiled in. |
| `third_party/nlohmann/` | JSON for Modern C++, MIT, single header, compiled in. |
| `helper-scripts/1-disable-eaac.bat` | Disables EAAC and installs `RtWorkQ.dll`. |
| `helper-scripts/2-enable-eaac.bat` | Undoes that. |
| `helper-scripts/3-clear-save.bat` | Deletes your local save. |

### Getting the DLL

Either take `RtWorkQ.dll` from the **Releases** page of this repository, or
build it yourself from `src/` - see [Building](#building). Both are the same
program. There is no single canonical binary.

---

## Building

**Requirements**

- **Build Tools for Visual Studio 2026** with the *Desktop development with C++*
  workload. It is free and includes no IDE:

  <https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2026>

  The installer is `vs_BuildTools.exe`. By default `vcvars64.bat` ends up in
  `C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Auxiliary\Build\`.

  Or via winget:

  ```
  winget install Microsoft.VisualStudio.BuildTools --force --override "--wait --passive --add Microsoft.VisualStudio.Component.VC.Tools.x86.x64"
  ```

  Older toolsets (VS 2019 / 2022) work too - they just produce a different
  binary.

**Steps**

```
cd src
build.bat
```

`build.bat` calls `vcvars64.bat` and then:

```
set MINHOOK=..\third_party\minhook\src\hook.c ^
            ..\third_party\minhook\src\trampoline.c ^
            ..\third_party\minhook\src\buffer.c ^
            ..\third_party\minhook\src\hde\hde64.c
cl /nologo /LD /O2 /MT /EHsc /W3 /Brepro /D_CRT_SECURE_NO_WARNINGS ^
   AutoOffline.cpp %MINHOOK% /Fe:AutoOffline.dll /Fo:obj\ ^
   /link kernel32.lib
```

`build.bat` locates the toolchain itself: it asks `vswhere.exe` first and falls
back to scanning the install roots. If it finds nothing it stops and tells you
what to install.

`/Brepro` makes the build reproducible, so the same source always produces the
same bytes on the same toolchain. Without it the linker stamps the build time
into the binary - twice, in the COFF header and again in the
`IMAGE_DEBUG_TYPE_REPRO` debug entry - and no two builds would ever match.

**Toolchain**

For reference, the released binary was built with:

```
Build Tools for Visual Studio 2026, version 18.7.4
Microsoft (R) C/C++ Optimizing Compiler Version 19.51.36248 for x64
Microsoft (R) Incremental Linker Version 14.51.36248.0
```

`build.bat` prints its own versions when you run it.

Any current MSVC builds this source. A different one links different library
code and so produces a different binary - expected, and harmless. What is worth
checking is the source, not the bytes.

---

## How it works

The full explanation is in the comment block at the top of
`src/AutoOffline.cpp`. In short:

**1. Getting loaded.** The game loads `RtWorkQ.dll` by bare name, so our copy in
the game folder wins. Our `DllMain` is the entry point. No injector, no
external tool - the game loads us itself.

**2. Waiting for decryption.** The executable is protected, and its code is
decrypted at runtime. Hooking too early would decode still-encrypted bytes and
produce a broken trampoline. So the DLL **polls until the expected original
bytes appear**, then hooks. If they never appear, it hooks nothing and only
writes to its log - including which pattern did not match.

**3. The hooks.** A small table in the source (`g_patches`) lists each entry as
*verification address + expected original bytes + the function to hook*. The
expected bytes are what proves the code has decrypted. Each hook takes over the
function's entry, calls it, and changes exactly one behaviour; the offline-fix
hook is the exception and answers without calling the original. The only bytes
that change are the few at each hooked entry, which MinHook writes and restores
itself - no game instruction is edited by hand, so there is nothing to get
wrong about instruction encoding. Each entry is documented in-line with what the
original function does and why it is being intercepted.

**4. One value is configurable.** The `clientType` hook writes a value that can
be changed without rebuilding: put `autooffline_p3.txt` next to `RtWorkQ.dll`
with the number to use. Everything else is fixed at compile time.

**5. Your loadout is kept locally.** Offline the server never sends your equipped
skins and perks back, so they used to reset on every launch. The DLL now records
which items you have equipped - per character, for each of the three loadout
slots - as soon as you change it in the menus, and writes it back when the game
builds that character's config model, which happens before anything can read it.
The file is `autooffline_save.json` next to `RtWorkQ.dll`: plain JSON, one entry
per option, editable by hand. `3-clear-save.bat` deletes it.

To be clear about the scope: this is a record of the current setup, not of what
you own. Unlocks, items and progress are not stored, not changed, and not sent
anywhere - installing or removing the mod cannot cost you anything you have
earned. If the file is deleted, the next launch simply starts from whatever is
equipped at that moment.

---

## The helper scripts

The scripts are self-contained and **ask for administrator rights**, because
they change files inside the game folder.

- **They find your game automatically** - Steam registry, Steam library folders,
  the EA app registry, then common install locations. You can also drag your
  game folder onto the `.bat` if detection fails.
- **Nothing is deleted without saying so.** A foreign `RtWorkQ.dll` is moved to a
  `stale\` folder instead of being overwritten; `2-enable-eaac.bat` only removes a
  `RtWorkQ.dll` that is byte-identical to the one shipped here. The one
  exception is `3-clear-save.bat`: it deletes `autooffline_save.json`
  (and asks for a confirmation first), because that is the whole point of it.
- **They refuse to run while the game is open**, so files are never changed
  underneath a running game.
- **They are idempotent** - running them repeatedly is safe.

---

## License

MIT - see [LICENSE](LICENSE).

`third_party/minhook` is MinHook by Tsuda Kageyu, BSD-2-Clause - see
`third_party/minhook/LICENSE.txt`. `third_party/nlohmann` is JSON for Modern
C++ by Niels Lohmann, MIT - see the header for its notice. Both are compiled
into the DLL; nothing is downloaded at build time.

This project is not affiliated with, endorsed by, or sponsored by Electronic
Arts Inc. It is an independent, community-developed mod for educational and
preservation purposes. *Plants vs. Zombies* is a trademark of its respective
owners.
