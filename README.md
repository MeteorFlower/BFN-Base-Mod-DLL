# BFN Base Mod - source code

Source for the DLL and helper scripts shipped with the Nexus release
**"Base Mod for the New Version - No Downgrade"** for *Plants vs. Zombies:
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

**2. The two `.bat` files rename and copy files inside the game folder.**

`1-disable-eaac.bat` renames `EAAntiCheat.GameServiceLauncher.exe` to
`.exe.bak` and copies `RtWorkQ.dll` into the game folder.
`2-enable-eaac.bat` undoes exactly that.

Both are plain text. **Open them in Notepad and read every line.** They contain
no obfuscation, no downloads, no encoded blobs.

**3. What the DLL does *not* do.**

- It does **not** connect to the network. There is no socket, no HTTP, no WinINet.
- It does **not** read, collect, or transmit any personal data.
- It does **not** inject into another process. It *is* the process - the game loads it.
- It does **not** modify any file. It writes one log file, `autooffline_log.txt`,
  next to itself.
- It does **not** touch the game's memory beyond the handful of byte patches listed below.

---

## What's in here

| Path | What it is |
|---|---|
| `src/AutoOffline.cpp` | The DLL source. This is the whole program - 670 lines. |
| `src/build.bat` | Builds it with MSVC. |
| `helper-scripts/1-disable-eaac.bat` | Disables EAAC and installs `RtWorkQ.dll`. |
| `helper-scripts/2-enable-eaac.bat` | Undoes that. |

### Getting the DLL

Either take `RtWorkQ.dll` from the **Releases** page of this repository, or
build it yourself from `src/` - see [Building](#building). Both are the same
program. There is no single canonical binary.

---

## Building

**Requirements**

- Windows 10 / 11
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
cl /nologo /LD /O2 /MT /EHsc /W3 /Brepro /D_CRT_SECURE_NO_WARNINGS ^
   AutoOffline.cpp /Fe:AutoOffline.dll /Fo:obj\ ^
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
decrypted at runtime. Patching too early would write into still-encrypted data
and silently do nothing once it decrypts. So the DLL **polls until the expected
original bytes appear**, then patches. If they never appear, it patches nothing
and only writes to its log.

**3. The patches.** A small table in the source (`g_patches`) lists each patch as
*address + new bytes + expected original bytes*. The expected bytes are what
proves the code has decrypted. There are a handful of them, each documented
in-line with what the original instruction was and why it's changed.

**4. Runtime settings.** A few network timeouts and one profile field are set at
runtime rather than patched, because they live in objects rather than in code.

---

## The helper scripts

Both scripts are self-contained and **ask for administrator rights**, because
they rename and copy files inside the game folder.

- **They find your game automatically** - Steam registry, Steam library folders,
  the EA app registry, then common install locations. You can also drag your
  game folder onto the `.bat` if detection fails.
- **Nothing is ever deleted.** A foreign `RtWorkQ.dll` is moved to a `stale\`
  folder instead of being overwritten. `2-enable-eaac.bat` only removes a
  `RtWorkQ.dll` that is byte-identical to the one shipped here.
- **They refuse to run while the game is open**, so files are never changed
  underneath a running game.
- **They are idempotent** - running them repeatedly is safe.

---

## License

MIT - see [LICENSE](LICENSE).

This project is not affiliated with, endorsed by, or sponsored by Electronic
Arts Inc. It is an independent, community-developed mod for educational and
preservation purposes. *Plants vs. Zombies* is a trademark of its respective
owners.
