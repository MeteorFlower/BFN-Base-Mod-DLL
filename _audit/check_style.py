#!/usr/bin/env python3
"""Scan AutoOffline.cpp for banned AI-style markers.

Run this after every comment edit, before building:

    python _audit/check_style.py

Exits non-zero if anything is found.
"""

import os
import re
import sys

SRC = (sys.argv[1] if len(sys.argv) > 1
       else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src",
                         "AutoOffline.cpp"))

# Banned characters. Keep this list complete: every one of these has been
# caught in a real edit at least once.
BANNED_CHARS = {
    "★": "star",
    "【": "lenticular-open",
    "】": "lenticular-close",
    "—": "em-dash",
    "⇒": "double-arrow",
    "「": "corner-open",
    "」": "corner-close",
    "─": "box-drawing",
    "`": "backtick",
}
for _c in range(0x2460, 0x2474):
    BANNED_CHARS[chr(_c)] = "circled-number"
for _c in range(0x1F300, 0x1FAFF):
    BANNED_CHARS[chr(_c)] = "emoji"
# The whole Arrows block, not just the double arrow: a bare U+2192 sat in the
# source for months because the 0x2600 scan below and the prose-arrow regex
# both miss it.
for _c in range(0x2190, 0x2200):
    BANNED_CHARS.setdefault(chr(_c), "arrow")
for _c in range(0x2600, 0x27C0):
    BANNED_CHARS.setdefault(chr(_c), "symbol")
# U+FE0F is the variation selector that turns e.g. U+26A0 into an emoji.
BANNED_CHARS["️"] = "variation-selector"


def body_of(lines, start):
    """Text of the function whose opening brace is on lines[start] (0-based)."""
    out, depth, started = [], 0, False
    for i in range(start, len(lines)):
        out.append(lines[i])
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth == 0:
            break
    return "\n".join(out)


def global_line(lines, name):
    """1-based line where a file-scope variable `name` is defined, else None."""
    pat = re.compile(r"^(?:static\s+)?[\w:<>,\*&\s]+?\b" + re.escape(name) + r"\s*(\[|=|;)")
    for i, l in enumerate(lines, 1):
        if l.startswith((" ", "\t", "#", "//")):
            continue
        if pat.match(l):
            return i
    return None


def main():
    if not os.path.exists(SRC):
        print("ERROR: not found: %s" % SRC)
        return 2
    lines = open(SRC, encoding="utf-8").read().splitlines()
    hits = 0

    print("=== banned characters ===")
    for i, line in enumerate(lines, 1):
        found = []
        for ch in line:
            if ch in BANNED_CHARS:
                found.append("%s U+%04X" % (BANNED_CHARS[ch], ord(ch)))
        if found:
            hits += 1
            print("%5d [%s] %s" % (i, ", ".join(found), line.strip()[:100]))

    # Markdown bold. Must be paired **text** so that C dereferences like
    # *(void**)ctx are not reported.
    print("=== markdown bold ===")
    for i, line in enumerate(lines, 1):
        if re.search(r"\*\*[^*\n]{2,}\*\*", line):
            hits += 1
            print("%5d | %s" % (i, line.strip()[:100]))

    # Prose arrows.
    #
    # "=>" is never C++ syntax, so every occurrence counts.
    #
    # "->" needs care, it has three legitimate C++ uses that must stay:
    #   ctx->member            (no spaces)
    #   [&](args) -> Out {     (lambda return type, " -> " with spaces)
    # Leave those alone; flag only arrows that read as prose separators.
    print("=== prose arrows ===")
    for i, line in enumerate(lines, 1):
        bad = []
        if "=>" in line:
            bad.append("=>")
        # 带空格的 lambda 返回类型（`) -> T {` / `)-> T;`）是合法 C++，两条箭头判据都要放它过去。
        # 右侧限定成 ASCII 类型名：中文散文里的 "（x）-> 结果" 不该被豁免，而它用的是全角括号，
        # 本来也过不了 `\)` 这一关。
        lambda_ok = re.search(r"\)\s*->\s*[A-Za-z_][A-Za-z0-9_:<>]*\s*[*&]*\s*(\{|;|$)", line)
        spaced = " -> " in line and not lambda_ok
        if spaced:
            bad.append("spaced ->")
        elif not lambda_ok and re.search(r"(?:^|[^\w\s])\s*->", line):
            # 左侧不是标识符字符，就不可能是成员访问，读起来是散文分隔符。
            # 这一条补的正是 "（ScanPool 猜的）-> ..." 那种漏：上面那条要求左边有空格，
            # 底下那条只认行首，两边都够不着它。
            bad.append("bare ->")
        if "<->" in line:
            bad.append("<->")
        if re.match(r"^\s*//\s*->\s+", line):
            bad.append("leading ->")
        # 左箭头同样是散文箭头，规矩里"全库清掉"没分左右。只在注释行上查：
        # 日志字符串里的 "  <- no owner" 是输出标注，不是散文。
        # 相邻的 "<-" 不会误伤 C++ 的 "a < -b"（那中间有空格，不构成 "<-"）。
        if line.lstrip().startswith("//") and "<-" in line:
            bad.append("<- prose")
        if bad:
            hits += 1
            print("%5d [%s] %s" % (i, ", ".join(bad), line.strip()[:100]))

    # Useless forward declarations.
    #
    # A forward declaration is only acceptable when something forces it: the
    # definition has to sit further down because it needs a global that is
    # itself declared further down. If nothing forces it, the declaration is
    # noise and the definition should simply be moved above the first call.
    #
    # Reported but NOT counted (allowed): a forced declaration tells you which
    # globals would have to move up first, so it is worth printing.
    print("=== useless forward declarations ===")
    fwd_re = re.compile(r"^(?:static\s+)?[\w:<>,\*&\s]*?\b(\w+)\s*\([^;{}]*\)\s*;\s*(?://.*)?$")
    for i, line in enumerate(lines, 1):
        if line.startswith(("typedef", "return", "#", " ")):
            continue
        m = fwd_re.match(line)
        if not m:
            continue
        name = m.group(1)
        def_re = re.compile(r"^(?:static\s+)?[\w:<>,\*&\s]*?\b" + re.escape(name) +
                            r"\s*\([^;{}]*\)\s*\{")
        def_line = None
        for k in range(i, len(lines)):
            if def_re.match(lines[k]):
                def_line = k + 1
                break
        if def_line is None:
            continue
        blockers = []
        for g in sorted(set(re.findall(r"\bg_\w+", body_of(lines, def_line - 1)))):
            gl = global_line(lines, g)
            if gl is not None and gl > i:
                blockers.append("%s@%d" % (g, gl))
        if blockers:
            print("%5d  %-24s def@%-5d  forced by %s" % (i, name, def_line, ", ".join(blockers)))
        else:
            hits += 1
            print("%5d  %-24s def@%-5d  nothing forces this, move the definition up" %
                  (i, name, def_line))

    # Third-person "user" references.
    #
    # These comments are the developer's own notes. Calling the developer
    # "用户" (the user) reads like an assistant documenting someone else's
    # requirements; state the requirement itself instead (2026-10-03 rule).
    print("=== third-person 'user' references ===")
    for i, line in enumerate(lines, 1):
        if "用户" in line:
            hits += 1
            print("%5d %s" % (i, line.strip()[:100]))

    # Local file references inside comments.
    #
    # Comments belong to the source, not to a notebook on one machine. Pointing
    # them at audit scratch files or at absolute paths makes them dangle as soon
    # as the work is cleaned up, and whoever reads the source later cannot open
    # them anyway. State the reasoning in the comment instead of the location.
    # Only audit/scratch paths and absolute paths are flagged: project inputs
    # that are part of the build (unit_names.inc, spawn_buff_table.inc) are real
    # filenames and stay allowed.
    print("=== local file references in comments ===")
    # 路径形态之外，裸文件名也要抓：审计文档、临时导出、日志、脚本这些扩展名的
    #   文件都不是构建输入，注释里提到它们就是指向本机文件。.inc 例外，那是真正的
    #   构建输入（unit_names.inc、spawn_buff_table.inc）。
    local_ref = re.compile(
        r"_audit[/\\]|[A-Za-z]:[\\/]|%(TEMP|TMP|APPDATA|LocalAppData)%"
        r"|\b[\w.-]+\.(?:md|py|txt|log|json|i64|exe|bak)\b"
        # memory 条目同样是只在这台机器上存在的笔记，注释里指过去一样会悬空。
        r"|\bmemory\b",
        re.IGNORECASE)
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("//"):
            comment = stripped
        elif stripped.startswith(("/*", "*")):
            comment = stripped
        else:
            k = line.find("//")
            if k < 0:
                continue
            comment = line[k:]
        # 本 DLL 自己写的产品文件不算"作者工作文件"：SummonAI 的 summonai_log.txt，
        #   以及 BFN Base Mod 的 autooffline_log.txt / autooffline_p3.txt /
        #   autooffline_save.json。除这几个名字之外一律不改判据。
        probe = comment
        for own in ("summonai_log.txt", "autooffline_log.txt", "autooffline_p3.txt",
                    "autooffline_save.json"):
            probe = probe.replace(own, "")
        if local_ref.search(probe):
            hits += 1
            print("%5d %s" % (i, stripped[:100]))

    # Colon watch. Warning only, NOT a failure: full-width colons in comments
    # are legal, but "label: explanation" openers stack up and read like
    # generated docs. Review every hit and turn the needless ones into a
    # comma and normal speech; keep the ones doing real work (lists, quotes).
    # Full-width colons only occur in comments in this file (code and log
    # strings are ASCII), so a plain line scan is enough.
    print("=== colon watch (review each; not a failure) ===")
    ncol = 0
    for i, line in enumerate(lines, 1):
        if "：" in line:
            ncol += 1
            print("%5d %s" % (i, line.strip()[:100]))
    print("      %d line(s) carry a full-width colon" % ncol)

    # Half-width bracket glued straight onto Chinese text.
    #
    # Chinese prose in this file always uses full-width brackets, even when what
    # sits inside them is a code fragment: （vt[296]）（sub_141CD9220）. A
    # half-width "(" with no space before it and a Chinese character right before
    # that is the one form the file's own style never uses, so it is safe to flag
    # without false positives. Punctuation *inside* a bracket wrapping code, and
    # list markers like "2)" or "b)", are fine and are not checked.
    # BFN Base Mod 的注释从首次提交起就在中文里统一用半角括号，改判会让整份文件
    #   大改一遍而收益为零，所以这一项只提示、不计入失败。
    print("=== half-width bracket after Chinese (warning only) ===")
    hw_re = re.compile("[一-鿿]\\(")
    for i, line in enumerate(lines, 1):
        if hw_re.search(line):
            print("%5d %s" % (i, line.strip()[:100]))

    # Doubled punctuation left behind by mechanical replacements.
    print("=== doubled punctuation ===")
    for i, line in enumerate(lines, 1):
        for pair in ("。，", "，。", "：，", "；，", "，、", "，，"):
            if pair in line:
                hits += 1
                print("%5d [%s] %s" % (i, pair, line.strip()[:100]))
                break

    print()
    if hits:
        print("FAIL: %d line(s) need cleanup." % hits)
        return 1
    print("OK: clean.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
