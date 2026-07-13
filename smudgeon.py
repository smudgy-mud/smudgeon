#!/usr/bin/env python3
"""smudgeon - an adversarial MUD server that bludgeons clients.

A deliberately hostile MUD server. It speaks just enough of the telnet/ANSI
wire to get a client to connect, then feeds it a gauntlet of malformed,
degenerate, and outright abusive input - the things a real client's
ingest/display pipeline has to survive: SGR poison, carriage-return
overprint, unterminated escape and telnet sequences, invalid UTF-8, clipboard
and link social-engineering, and more.

It is a TEST INSTRUMENT, not an exploit. Every attack is bounded (no genuine
out-of-memory), local by default, and labeled so you can read a client's
behavior section by section. Point any MUD client at it and watch.

Usage:
    python smudgeon.py                 # all attacks, once, on 127.0.0.1:4123
    python smudgeon.py --loop          # keep accepting connections
    python smudgeon.py --list          # print the attack catalog and exit
    python smudgeon.py --only sgr_poison,cr_overprint
    python smudgeon.py --exclude mccp_garbage
    python smudgeon.py --port 5000 --delay-ms 800

No third-party dependencies; standard library only.

Copyright (C) 2026 smudgeon contributors.
This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version. This program is distributed WITHOUT ANY WARRANTY; see the GNU General
Public License (the LICENSE file) for details.
"""

from __future__ import annotations

import argparse
import socket
import sys
import threading
import time

# ---- telnet vocabulary -------------------------------------------------------

IAC = 255
DONT, DO, WONT, WILL, SB, SE = 254, 253, 252, 251, 250, 240
GA, EOR_CMD = 249, 239

OPT_ECHO, OPT_SGA, OPT_EOR = 1, 3, 25
OPT_TTYPE, OPT_NAWS, OPT_MXP = 24, 31, 91
OPT_COMPRESS2, OPT_GMCP = 86, 201

ESC = b"\x1b"
ST = ESC + b"\\"  # OSC/string terminator
BEL = b"\x07"


# ---- connection wrapper ------------------------------------------------------


class Peer:
    """One connected client, plus the shared state the reader thread fills in."""

    def __init__(self, sock: socket.socket, delay_ms: int, stress_bytes: int):
        self.sock = sock
        self.delay = delay_ms / 1000.0
        self.stress_bytes = stress_bytes
        self.alive = True
        # Set by the reader thread when the client accepts our COMPRESS2 offer
        # (`IAC DO COMPRESS2`), so the MCCP attack knows whether to proceed.
        self.compress2_accepted = threading.Event()

    def send(self, data: bytes) -> None:
        if not self.alive:
            return
        try:
            self.sock.sendall(data)
        except OSError:
            self.alive = False

    def text(self, s: str) -> None:
        # Deliberately CRLF: real MUDs use it, and clients must cope with both.
        self.send(s.replace("\n", "\r\n").encode("utf-8", "surrogatepass"))

    def line(self, s: str) -> None:
        self.text(s + "\r\n")

    def banner(self, index: int, total: int, name: str, desc: str) -> None:
        """Announce the next attack, in-band (bright cyan) and on the console."""
        self.send(
            b"\r\n" + ESC + b"[1;36m" + f"== [{index}/{total}] {name} ==".encode()
            + ESC + b"[0m\r\n"
        )
        self.line(ESC.decode() + f"[36m{desc}" + ESC.decode() + "[0m")
        print(f"  -> [{index}/{total}] {name}", flush=True)

    def sleep(self) -> None:
        time.sleep(self.delay)


# ---- attack registry ---------------------------------------------------------

ATTACKS: list[tuple[str, str, object]] = []


def attack(name: str, desc: str):
    def register(fn):
        ATTACKS.append((name, desc, fn))
        return fn

    return register


# ---- display / SGR -----------------------------------------------------------


@attack("sgr_backgrounds", "ANSI background colors: 16-color, 256, truecolor, bright.")
def sgr_backgrounds(p: Peer) -> None:
    e = ESC.decode()
    p.line(f"{e}[41m red background {e}[0m plain after reset")
    p.line(f"{e}[42;30m green bg, black fg {e}[0m")
    p.line(f"{e}[48;5;27m 256-color blue bg {e}[0m{e}[103m bright yellow bg {e}[0m")
    p.line(f"{e}[48;2;128;0;255m truecolor purple bg {e}[0m")


@attack("sgr_poison", "One unsupported SGR code must not discard the whole sequence's colors.")
def sgr_poison(p: Peer) -> None:
    e = ESC.decode()
    # 4 (underline) is unsupported by some clients; the 31 (red) must survive.
    p.line(f"{e}[1;4;31m bright red despite the underline code {e}[0m")
    # Empty parameter == implicit 0 == reset.
    p.line(f"{e}[31mred{e}[m plain again (bare ESC[m must reset)")
    # A garbage-high code between two valid colors.
    p.line(f"{e}[32;9999;44m green fg on blue bg, unknown 9999 skipped {e}[0m")
    # Colon-form extended color (ITU T.416).
    p.line(f"{e}[38:2::255:128:0m colon-form orange {e}[0m")


@attack("sgr_colon_slant", "Colon-form italic 3:2 - a real-world parser bug corrupts underline state.")
def sgr_colon_slant(p: Peer) -> None:
    e = ESC.decode()
    # Some parsers route the 3:x sub-parameter into the underline flag instead
    # of italics; a client that mishandles it may show the following text
    # underlined, not italic.
    p.line(f"{e}[3:2m slanted? (watch for stray underline) {e}[0m normal")


# ---- line handling -----------------------------------------------------------


@attack("cr_overprint", "Bare carriage return should overwrite the line (progress bar), not stack it.")
def cr_overprint(p: Peer) -> None:
    for pct in ("10", "35", "70", "100"):
        p.send(f"progress: {pct}% ".encode())
        p.sleep()
        p.send(b"\r")
    p.line("progress: done")


@attack("cr_flood", "Many CR frames plus a trailing CR with no LF (dangling overprint).")
def cr_flood(p: Peer) -> None:
    spinner = "|/-\\"
    for i in range(12):
        p.send(f"working {spinner[i % 4]}".encode())
        p.sleep()
        p.send(b"\r")
    # End on a bare CR + no newline: the frame is left open.
    p.send(b"final frame, no newline\r")


@attack("naked_controls", "C0 control bytes embedded mid-line: NUL BEL TAB BS VT FF.")
def naked_controls(p: Peer) -> None:
    p.send(b"tabs\ther\te, ")
    p.send(b"nul[\x00], bel[\x07], backspace[\x08], vt[\x0b], ff[\x0c] end\r\n")


@attack("long_line_no_newline", "A very long line with no newline - unbounded buffer growth probe.")
def long_line_no_newline(p: Peer) -> None:
    p.text("no newline for a long time: ")
    chunk = b"x" * 4096
    sent = 0
    while sent < p.stress_bytes and p.alive:
        p.send(chunk)
        sent += len(chunk)
    p.line(f" [{sent} bytes with no LF]")


# ---- escape / CSI robustness -------------------------------------------------


@attack("unterminated_csi", "ESC[ + a huge run of parameter bytes and no final byte (unbounded-buffer probe).")
def unterminated_csi(p: Peer) -> None:
    p.text("about to open a CSI that never closes...\r\n")
    p.send(ESC + b"[")
    chunk = b"0;1;2;3;4;5;6;7;8;9;"
    sent = 0
    while sent < p.stress_bytes and p.alive:
        p.send(chunk)
        sent += len(chunk)
    # Finally terminate it so the connection can continue for later attacks.
    p.send(b"m")
    p.line("...CSI finally terminated with 'm'")


@attack("esc_latch", "ESC-Fe / charset designator, then text with [ and ] (ESC-state latch probe).")
def esc_latch(p: Peer) -> None:
    # ESC c (RIS), ESC 7 (save cursor), ESC(B (designate G0 = ASCII): none is
    # CSI/OSC. A client that latches "saw ESC" may misparse the next literal
    # '[' or ']' as a sequence introducer and eat the following text.
    p.send(ESC + b"c")
    p.line("after ESC c - this [bracketed] text must display in full")
    p.send(ESC + b"(B")
    p.line("after ESC(B - these ]brackets[ must not be swallowed")


@attack("csi_cursor_ops", "Cursor moves / erase / DEC private modes - must not corrupt or leak into text.")
def csi_cursor_ops(p: Peer) -> None:
    e = ESC.decode()
    p.line(f"cursor ops: {e}[2J{e}[H{e}[10;5H{e}[K{e}[?25l{e}[?25h none should print as text")


# ---- encoding ----------------------------------------------------------------


@attack("invalid_utf8", "Invalid UTF-8: lone high bytes, overlong, truncated multibyte, lone surrogate.")
def invalid_utf8(p: Peer) -> None:
    p.text("valid first: café - 日本語 - 😀 - combining: é\r\n")
    p.send(b"lone high bytes: \xff\xfe\x80\x81 | ")
    p.send(b"overlong slash: \xc0\xaf | ")
    p.send(b"truncated 3-byte: \xe2\x82 | ")
    p.send(b"lone surrogate: \xed\xa0\x80 end\r\n")


@attack("wide_unicode", "Wide/zero-width/combining glyphs - column math and wrapping.")
def wide_unicode(p: Peer) -> None:
    p.line("wide CJK: 你好世界 (each cell is 2 wide)")
    p.line("zero-width joiner emoji: 👨‍👩‍👧‍👦 family")
    p.line("stacked combining: à́̂̃̄ then normal")


# ---- telnet protocol ---------------------------------------------------------


@attack("unterminated_subneg", "IAC SB + huge payload, no IAC SE (subnegotiation buffer-cap probe).")
def unterminated_subneg(p: Peer) -> None:
    p.line("opening a GMCP subnegotiation that never sends IAC SE...")
    p.send(bytes([IAC, SB, OPT_GMCP]))
    chunk = b"x" * 4096
    sent = 0
    while sent < p.stress_bytes and p.alive:
        p.send(chunk)
        sent += len(chunk)
    # Close it so the stream can resync for the next attack.
    p.send(bytes([IAC, SE]))
    p.line(f"...subnegotiation closed after {sent} unterminated bytes")


@attack("iac_edge", "Telnet edge cases: lone commands, IAC SE without SB, doubled IAC, bad negotiation.")
def iac_edge(p: Peer) -> None:
    p.send(b"before ")
    p.send(bytes([IAC, 241]))            # NOP - no option argument
    p.send(bytes([IAC, SE]))             # stray SE with no open subnegotiation
    p.send(bytes([IAC, IAC]))            # doubled IAC == literal 0xFF byte
    p.send(bytes([IAC, WILL, 200]))      # WILL for an unknown/unused option
    p.line(" after (a literal 0xFF should appear between 'before ' and ' after')")


@attack("mccp_garbage", "Offer MCCP2, then send invalid deflate if accepted (inflate-error handling probe).")
def mccp_garbage(p: Peer) -> None:
    p.line("offering MCCP2 (COMPRESS2)...")
    p.send(bytes([IAC, WILL, OPT_COMPRESS2]))
    if not p.compress2_accepted.wait(timeout=1.5):
        p.line("client declined MCCP2 (or didn't answer) - skipping the garbage payload")
        return
    # The MCCP2 start marker, then bytes that are NOT a valid zlib stream.
    p.send(bytes([IAC, SB, OPT_COMPRESS2, IAC, SE]))
    p.send(b"\x78\x9c" + b"\x00\xde\xad\xbe\xef garbage not-deflate \xff\xff")
    print("     (sent invalid MCCP2 deflate; a client with no inflate-error "
          "handling may wedge here)", flush=True)


# ---- links / social engineering ----------------------------------------------


@attack("osc8_links", "OSC 8 hyperlinks: a normal https link and a MUD 'send:' command link.")
def osc8_links(p: Peer) -> None:
    p.send(b"Visit " + ESC + b"]8;;https://example.org/wiki" + ST
           + b"the wiki" + ESC + b"]8;;" + ST + b" for help.\r\n")
    p.send(b"Action: " + ESC + b"]8;;send:look" + ST
           + b"[look around]" + ESC + b"]8;;" + ST + b"\r\n")


@attack("osc8_spoof", "OSC 8 link whose visible text lies about its destination - does the client reveal the real URL?")
def osc8_spoof(p: Peer) -> None:
    # The text says one host; the URI points somewhere else. A safe client
    # surfaces the REAL destination (example.evil), unmaskable by the server.
    p.send(b"Totally safe: " + ESC + b"]8;;https://example.evil/phish" + ST
           + b"https://your-bank.example" + ESC + b"]8;;" + ST + b"\r\n")


@attack("osc52_clipboard", "OSC 52 clipboard write - a server must NOT be able to hijack your clipboard.")
def osc52_clipboard(p: Peer) -> None:
    # base64("smudgeon owned your clipboard") - if the client honors this, the
    # server just wrote the user's system clipboard. It must not.
    payload = b"c3medWRnZW9uIG93bmVkIHlvdXIgY2xpcGJvYXJk"
    p.send(ESC + b"]52;c;" + payload + ST)
    p.line("sent an OSC 52 clipboard-write; check whether your clipboard changed")


# ---- MXP ---------------------------------------------------------------------


@attack("mxp_malformed", "MXP mode + unterminated/malformed tags and a custom entity (tag-parser robustness).")
def mxp_malformed(p: Peer) -> None:
    e = ESC.decode()
    # Enter MXP line mode, then feed it degenerate tags.
    p.line(f"{e}[6z<b>bold never closed, then <unknown-tag attr='x'> and a")
    p.line("dangling entity &notreal; plus a never-terminated <send href='")
    p.line(f"{e}[0z back to plain - did the malformed MXP corrupt anything above?")


# ---- server plumbing ---------------------------------------------------------


def reader_thread(p: Peer) -> None:
    """Drain and log whatever the client sends, so the socket never backs up
    and we can report negotiation attempts. Also detects COMPRESS2 acceptance."""
    buf = bytearray()
    sock = p.sock
    while p.alive:
        try:
            data = sock.recv(4096)
        except OSError:
            break
        if not data:
            break
        buf.extend(data)
        # Cheap scan for `IAC DO COMPRESS2` (the MCCP attack waits on this).
        for i in range(len(data) - 2):
            if data[i] == IAC and data[i + 1] == DO and data[i + 2] == OPT_COMPRESS2:
                p.compress2_accepted.set()
        # Log any GMCP the client volunteers (its Core.Hello, etc.).
        if IAC in data and OPT_GMCP in data:
            print("     (client sent GMCP / telnet negotiation)", flush=True)
    p.alive = False


def handshake(p: Peer) -> None:
    """A minimal, well-formed greeting so clients connect cleanly: offer GMCP
    and EOR, print a banner. We don't require the client to answer."""
    p.send(bytes([IAC, WILL, OPT_GMCP]))
    p.send(bytes([IAC, WILL, OPT_EOR]))
    e = ESC.decode()
    p.line(f"{e}[1;35m*** smudgeon ***{e}[0m the server that bludgeons clients")
    p.line("Every line below is a deliberate attack. Watch your client cope - or not.")


def run_attacks(p: Peer, selected: list[tuple[str, str, object]]) -> None:
    total = len(selected)
    for i, (name, desc, fn) in enumerate(selected, start=1):
        if not p.alive:
            break
        p.banner(i, total, name, desc)
        p.sleep()
        try:
            fn(p)
        except Exception as exc:  # a broken attack must not kill the server
            print(f"     !! attack {name} raised: {exc}", flush=True)
        p.sleep()
    if p.alive:
        p.line("")
        p.line("=== gauntlet complete. smudgeon rests. ===")
        # Mark the final line with a real prompt signal, since we advertised EOR.
        p.send(bytes([IAC, EOR_CMD]))


def select_attacks(only: str | None, exclude: str | None) -> list[tuple[str, str, object]]:
    names = [a[0] for a in ATTACKS]
    if only:
        want = [n.strip() for n in only.split(",") if n.strip()]
        unknown = [n for n in want if n not in names]
        if unknown:
            sys.exit(f"unknown attack(s): {', '.join(unknown)}\nknown: {', '.join(names)}")
        return [a for a in ATTACKS if a[0] in want]
    chosen = ATTACKS
    if exclude:
        drop = {n.strip() for n in exclude.split(",")}
        chosen = [a for a in ATTACKS if a[0] not in drop]
    return chosen


def serve_one(sock: socket.socket, args, selected) -> None:
    conn, addr = sock.accept()
    print(f"client connected from {addr[0]}:{addr[1]}", flush=True)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    p = Peer(conn, args.delay_ms, args.stress_bytes)
    t = threading.Thread(target=reader_thread, args=(p,), daemon=True)
    t.start()
    try:
        handshake(p)
        p.sleep()
        run_attacks(p, selected)
        # Hold the connection briefly so trailing frames flush before we close.
        time.sleep(1.0)
    finally:
        p.alive = False
        try:
            conn.shutdown(socket.SHUT_RDWR)  # clean FIN, not a reset
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass
        print("client disconnected", flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description="smudgeon - an adversarial MUD server.")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=4123, help="bind port (default 4123)")
    parser.add_argument("--loop", action="store_true", help="keep accepting connections")
    parser.add_argument("--delay-ms", type=int, default=500,
                        help="pause between/within attacks (default 500)")
    parser.add_argument("--stress-bytes", type=int, default=256 * 1024,
                        help="size of the unbounded-growth probes (default 262144)")
    parser.add_argument("--only", help="comma-separated attack names to run (in catalog order)")
    parser.add_argument("--exclude", help="comma-separated attack names to skip")
    parser.add_argument("--list", action="store_true", help="print the attack catalog and exit")
    args = parser.parse_args()

    if args.list:
        width = max(len(n) for n, _, _ in ATTACKS)
        for name, desc, _ in ATTACKS:
            print(f"{name.ljust(width)}  {desc}")
        return

    selected = select_attacks(args.only, args.exclude)

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.host, args.port))
    srv.listen(1)
    print(f"smudgeon listening on {args.host}:{args.port} "
          f"({len(selected)} attacks; {'looping' if args.loop else 'single connection'})",
          flush=True)
    print("point a MUD client here and connect.", flush=True)

    try:
        while True:
            serve_one(srv, args, selected)
            if not args.loop:
                break
    except KeyboardInterrupt:
        print("\nsmudgeon stopped.", flush=True)
    finally:
        srv.close()


if __name__ == "__main__":
    main()
