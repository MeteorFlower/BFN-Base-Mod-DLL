# BFN Base Mod — source code

Source for the DLL and helper scripts shipped with the Nexus release
**"Base Mod for the New Version - No Downgrade"** for *Plants vs. Zombies:
Battle for Neighborville*.

This repository exists so that anyone — players, and Nexus Mods staff reviewing
the upload — can read exactly what the files do before running them.

---

## ⚠️ Why the upload gets flagged as "suspicious"

The Nexus upload is flagged by the automated safety check, and antivirus tools
may flag `RtWorkQ.dll` too. **This is a false positive, and here is precisely
why it happens:**

**1. `RtWorkQ.dll` is a DLL proxy.**

The mod works by *DLL search-order hijacking*. The game process calls
`LoadLibrary("RtWorkQ.dll")` by bare name, so Windows looks in the game's own
folder first — and loads ours instead of the system copy in `System32`.

That is a legitimate, decades-old modding technique. It is also a technique
malware uses, so **any DLL proxy trips pattern-based scanners**. There is no
way to ship this mod without tripping them.

Note that the game never calls any function *from* `RtWorkQ.dll` — the file
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
- It does **not** inject into another process. It *is* the process — the game loads it.
- It does **not** modify any file. It writes one log file, `autooffline_log.txt`,
  next to itself.
- It does **not** touch the game's memory beyond the handful of byte patches listed below.

---

## What's in here

| Path | What it is |
|---|---|
| `src/AutoOffline.cpp` | The DLL source. This is the whole program — 670 lines. |
| `src/build.bat` | Builds it with MSVC. |
| `verify-build.py` | Compares a rebuild against the published binary (see below). |
| `helper-scripts/1-disable-eaac.bat` | Disables EAAC and installs `RtWorkQ.dll`. |
| `helper-scripts/2-enable-eaac.bat` | Undoes that. |
| `dist/RtWorkQ.dll` | The **exact binary** published on Nexus. |

### Verifying the published binary

The `dist/RtWorkQ.dll` in this repository is the same file that was uploaded to
Nexus. SHA-256:

```
6403c7d608260337f52cee4aeb53ab92ed99c8e63a090a2b61bc5364ceeb9a28
```

Build it yourself and compare — see [Building](#building). Note that a correct
rebuild will **not** produce that hash; the next section explains why.

---

## Building

**Requirements**

- Windows 10 / 11
- Visual Studio 2019 or 2022 with the **C++ build tools**
  (the free *Build Tools for Visual Studio* is enough)

**Steps**

```
cd src
build.bat
```

`build.bat` calls `vcvars64.bat` and then:

```
cl /nologo /LD /O2 /MT /EHsc /W3 /D_CRT_SECURE_NO_WARNINGS ^
   AutoOffline.cpp /Fe:AutoOffline.dll /Fo:obj\ ^
   /link kernel32.lib
```

If your Visual Studio lives somewhere other than the default path, edit the
`VCVARS` variable at the top of `build.bat`.

**Comparing your build with the published one**

A rebuild is *not* hash-identical to `dist/RtWorkQ.dll`, and a matching hash is
not the right test. The linker stamps the build time into the binary twice: in
the COFF header `TimeDateStamp`, and again in the `TimeDateStamp` field of the
`IMAGE_DEBUG_TYPE_REPRO` entry in the debug directory. Those two 4-byte fields
always differ from one build to the next — even between two builds of identical
source. **Every other byte is identical.**

So compare the files with those two fields zeroed:

```
python verify-build.py AutoOffline.dll ..\dist\RtWorkQ.dll
```

It zeroes the fields in both files and prints one hash each. Both should be:

```
23a4081a780f2027606719c57e7f13d0a68bbdcbb096ab10ee9f6709070ad075
```

You can see the two timestamps without any tooling:

```
dumpbin /headers AutoOffline.dll
```

---

## How it works

The full explanation is in the comment block at the top of
`src/AutoOffline.cpp`. In short:

**1. Getting loaded.** The game loads `RtWorkQ.dll` by bare name, so our copy in
the game folder wins. Our `DllMain` is the entry point. No injector, no
external tool — the game loads us itself.

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

- **They find your game automatically** — Steam registry, Steam library folders,
  the EA app registry, then common install locations. You can also drag your
  game folder onto the `.bat` if detection fails.
- **Nothing is ever deleted.** A foreign `RtWorkQ.dll` is moved to a `stale\`
  folder instead of being overwritten. `2-enable-eaac.bat` only removes a
  `RtWorkQ.dll` that is byte-identical to the one shipped here.
- **They refuse to run while the game is open**, so files are never changed
  underneath a running game.
- **They are idempotent** — running them repeatedly is safe.

---

## License

MIT — see [LICENSE](LICENSE).

This project is not affiliated with, endorsed by, or sponsored by Electronic
Arts Inc. It is an independent, community-developed mod for educational and
preservation purposes. *Plants vs. Zombies* is a trademark of its respective
owners.
