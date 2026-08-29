#!/usr/bin/env python3
"""Render README screenshots from the real binary running in --demo mode.

Runs the tool inside a pseudo-terminal, answers the terminal queries Lip Gloss
sends (background color, cursor position), replays the ANSI stream into a
small virtual screen, converts the final frame to HTML and screenshots it with
headless Chrome. No screen recording tools needed.

Usage: docs/screenshots/render.py [--bin bin/fwall] [--out docs/screenshots]
"""
from __future__ import annotations

import argparse
import fcntl
import html
import os
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import termios
import time

COLS, ROWS = 104, 26
PALETTE = {
    30: "#15161e", 31: "#f7768e", 32: "#9ece6a", 33: "#e0af68", 34: "#7aa2f7",
    35: "#bb9af7", 36: "#7dcfff", 37: "#a9b1d6", 90: "#414868", 91: "#f7768e",
    92: "#9ece6a", 93: "#e0af68", 94: "#7aa2f7", 95: "#bb9af7", 96: "#7dcfff",
    97: "#c0caf5",
}
# name -> (keys to press after startup, caption)
SCREENS = {
    "main": (b"", "Rules table with status, defaults and logging"),
    "add": (b"a", "Add rule form"),
    "delete": (b"d", "Delete: the exact command is previewed before it runs"),
    "policies": (b"p", "Default policies picker"),
    "help": (b"?", "Help"),
}


def capture(binary: str, keys: bytes) -> bytes:
    pid, fd = pty.fork()
    if pid == 0:
        os.environ["TERM"] = "xterm-256color"
        os.environ["COLORTERM"] = "truecolor"
        os.execv(binary, [binary, "--demo"])
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    out = b""
    started = time.time()
    answered = sent = False
    while time.time() - started < 5:
        ready, _, _ = select.select([fd], [], [], 0.2)
        if ready:
            try:
                out += os.read(fd, 65536)
            except OSError:
                break
        if not answered and (b"]11;?" in out or b"[6n" in out or b"[c" in out):
            os.write(fd, b"\x1b]11;rgb:1a1a/1b1b/2626\x1b\\\x1b[1;1R\x1b[?62;c")
            answered = True
        if answered and keys and not sent and time.time() - started > 2.0:
            for k in keys:
                os.write(fd, bytes([k]))
                time.sleep(0.15)
            sent = True
    try:
        os.kill(pid, 9)
    except OSError:
        pass
    return out


def color_css(col):
    if col is None:
        return None
    if col[0] == "rgb":
        return "#%02x%02x%02x" % col[1:]
    if col[0] == "idx":
        return PALETTE.get(col[1], "#c0caf5")
    n = col[1]
    if n < 16:
        return PALETTE.get(30 + n if n < 8 else 90 + n - 8, "#c0caf5")
    if n < 232:
        n -= 16
        r, g, b = n // 36, (n // 6) % 6, n % 6
        lv = lambda v: 0 if v == 0 else 55 + v * 40  # noqa: E731
        return "#%02x%02x%02x" % (lv(r), lv(g), lv(b))
    gray = 8 + (n - 232) * 10
    return "#%02x%02x%02x" % (gray, gray, gray)


def to_html(raw: bytes) -> str:
    raw = re.sub(
        rb"\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1bP[^\x1b]*\x1b\\|\x1b\[\?[0-9;]*[hl]|\x1b[=>]",
        b"", raw)
    txt = raw.decode("utf-8", "replace")
    rows = [[(" ", None)] * COLS for _ in range(ROWS)]
    r = c = 0
    fg = bg = None
    bold = False
    i = 0
    while i < len(txt):
        ch = txt[i]
        if ch == "\x1b" and i + 1 < len(txt) and txt[i + 1] == "[":
            m = re.match(r"\x1b\[([0-9;?]*)([A-Za-z])", txt[i:])
            if not m:
                i += 1
                continue
            params, cmd = m.group(1), m.group(2)
            i += m.end()
            p = [int(x) if x else 0 for x in params.replace("?", "").split(";")] if params else [0]
            if cmd == "m":
                j = 0
                while j < len(p):
                    v = p[j]
                    if v == 0:
                        fg = bg = None
                        bold = False
                    elif v == 1:
                        bold = True
                    elif v == 22:
                        bold = False
                    elif v == 39:
                        fg = None
                    elif v == 49:
                        bg = None
                    elif 30 <= v <= 37 or 90 <= v <= 97:
                        fg = ("idx", v)
                    elif 40 <= v <= 47 or 100 <= v <= 107:
                        bg = ("idx", v - 10)
                    elif v in (38, 48) and j + 1 < len(p):
                        col = None
                        if p[j + 1] == 2 and j + 4 < len(p):
                            col = ("rgb", p[j + 2], p[j + 3], p[j + 4])
                            j += 4
                        elif p[j + 1] == 5 and j + 2 < len(p):
                            col = ("256", p[j + 2])
                            j += 2
                        if v == 38:
                            fg = col
                        else:
                            bg = col
                    j += 1
            elif cmd in ("H", "f"):
                r = (p[0] if p and p[0] else 1) - 1
                c = (p[1] if len(p) > 1 and p[1] else 1) - 1
            elif cmd == "J":
                rows = [[(" ", None)] * COLS for _ in range(ROWS)]
            elif cmd == "K":
                for k in range(c, COLS):
                    rows[r][k] = (" ", None)
            elif cmd == "A":
                r = max(0, r - (p[0] or 1))
            elif cmd == "B":
                r = min(ROWS - 1, r + (p[0] or 1))
            elif cmd == "C":
                c = min(COLS - 1, c + (p[0] or 1))
            elif cmd == "D":
                c = max(0, c - (p[0] or 1))
            elif cmd == "G":
                c = (p[0] or 1) - 1
            continue
        if ch == "\r":
            c = 0
        elif ch == "\n":
            r = min(ROWS - 1, r + 1)
        elif ch >= " ":
            if c < COLS and r < ROWS:
                rows[r][c] = (ch, (fg, bg, bold))
            c += 1
        i += 1
    lines = []
    for row in rows:
        line, cur, buf, css = "", object(), "", ""
        for ch, st in row:
            if st != cur:
                if buf:
                    line += f'<span style="{css}">{html.escape(buf)}</span>' if css else html.escape(buf)
                buf, cur, css = "", st, ""
                if st:
                    f, b, bo = st
                    css = (f"color:{color_css(f)};" if f else "") + (f"background:{color_css(b)};" if b else "") + ("font-weight:bold;" if bo else "")
            buf += ch
        if buf:
            line += f'<span style="{css}">{html.escape(buf)}</span>' if css else html.escape(buf)
        lines.append(line.rstrip())
    return "\n".join(lines)


PAGE = """<html><body style="margin:0;background:#0f0f14;padding:24px;font-family:'Noto Sans Mono','JetBrains Mono',monospace">
<div style="display:inline-block;background:#1a1b26;color:#c0caf5;border-radius:10px;padding:16px 20px;box-shadow:0 8px 30px #0008">
<pre style="margin:0;font:14px/1.28 'Noto Sans Mono','JetBrains Mono',monospace;white-space:pre">{body}</pre></div></body></html>"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", default="bin/fwall")
    ap.add_argument("--out", default="docs/screenshots")
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    chrome = shutil.which("google-chrome") or shutil.which("chromium") or shutil.which("chromium-browser")
    if not chrome:
        print("no chrome/chromium found", file=sys.stderr)
        return 1
    os.makedirs(args.out, exist_ok=True)
    for name, (keys, _) in SCREENS.items():
        if args.only and name != args.only:
            continue
        frame = to_html(capture(args.bin, keys))
        page = os.path.join(args.out, f".{name}.html")
        with open(page, "w") as fh:
            fh.write(PAGE.replace("{body}", frame))
        png = os.path.join(args.out, f"fwall-{name}.png")
        subprocess.run([chrome, "--headless=new", "--no-sandbox", "--hide-scrollbars",
                        "--window-size=1000,540", f"--screenshot={png}", f"file://{os.path.abspath(page)}"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.remove(page)
        print(png)
    return 0


if __name__ == "__main__":
    sys.exit(main())
