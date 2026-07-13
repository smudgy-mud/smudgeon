# smudgeon

An adversarial MUD server that bludgeons clients.

`smudgeon` is a deliberately hostile MUD server. It speaks just enough of the
telnet/ANSI wire to get a client to connect, then feeds it a gauntlet of
malformed, degenerate, and abusive input. A client's goal should be to avoid
corrupting the screen or exhausting memory.

It is a **test instrument, not an exploit.** Every attack is bounded (no
genuine out-of-memory), binds to localhost by default, and is labeled in-band
so you can read a client's behavior section by section.

## Running it

Requires Python 3.9+ (standard library only — no dependencies).

```
python smudgeon.py                     # all attacks, once, on 127.0.0.1:4123
python smudgeon.py --loop              # keep accepting connections (test many clients)
python smudgeon.py --list              # print the attack catalog and exit
python smudgeon.py --only sgr_poison,osc8_spoof
python smudgeon.py --exclude mccp_garbage
python smudgeon.py --port 5000 --delay-ms 800 --stress-bytes 1048576
```

Then, in the client under test, connect to `localhost 4123` (or whatever
`--port` you chose). Each attack prints a bright-cyan `== [n/N] name ==` banner
into the stream before its payload, and the server logs the same to its
console, so you can line up what you see against what was sent.

`--stress-bytes` (default 256 KiB) sizes the three unbounded-growth probes.
Raise it to lean harder on a client's buffer caps.

## What to look for

A robust client should get through the whole gauntlet with the connection
intact, no crash, no hang, no corrupted scrollback, and no server-driven side
effects (clipboard, arbitrary commands). Specific expectations per attack:

| Attack | Robust behavior | Failure smell |
|---|---|---|
| `sgr_backgrounds` | Background colors render (16/256/truecolor/bright) | Backgrounds missing or wrong |
| `sgr_poison` | `ESC[1;4;31m` still shows **red**; `ESC[m` resets | One unknown code blanks the whole sequence's color |
| `sgr_colon_slant` | Italic or ignored | Text goes **underlined** (a `3:2`→underline parser bug seen in the wild) |
| `cr_overprint` | One line that updates in place | A stack of `progress: 10% / 35% / …` lines |
| `cr_flood` | Spinner animates on one line | Runaway concatenation; dangling final frame lost or duplicated |
| `naked_controls` | Controls dropped/handled; text intact; no BEL spam | Stray glyphs, misalignment, or an audible bell per line |
| `long_line_no_newline` | Bounded memory, still responsive | Memory climbs; UI stalls waiting for a newline |
| `unterminated_csi` | Bounded memory; later text unaffected | Unbounded buffer growth |
| `esc_latch` | The `[bracketed]` / `]bracket[` text displays **in full** | Following text swallowed (a stuck ESC-state latch) |
| `csi_cursor_ops` | Sequences consumed, nothing leaks as text | `2J`, `?25l`, etc. printed literally |
| `invalid_utf8` | Replacement glyphs; valid text around them intact | Crash, mojibake cascade, or dropped bytes |
| `wide_unicode` | Correct cell widths / wrapping | Cursor drift, overlap, or a crash on ZWJ/combining |
| `unterminated_subneg` | Bounded; stream resyncs after | Unbounded subnegotiation buffer |
| `iac_edge` | A literal `0xFF` appears; commands swallowed cleanly | Desync, dropped following text, or a crash |
| `mccp_garbage` | Inflate error → disconnect or clean recovery | Silent permanent wedge; needs the client to accept MCCP2 |
| `osc8_links` | Clickable link; a MUD `send:` link is gated/visible | Link sends silently, or isn't recognized |
| `osc8_spoof` | The **real** destination (`example.evil`) is shown | The visible lie (`your-bank.example`) is all the user sees |
| `osc52_clipboard` | Clipboard **unchanged** | The server just wrote your system clipboard |
| `mxp_malformed` | Malformed MXP contained; text above intact | Tag parser corrupts or swallows surrounding lines |

## Adding an attack

Attacks are self-contained functions registered with a decorator:

```python
@attack("my_probe", "One-line description shown in --list and in-band.")
def my_probe(p: Peer) -> None:
    p.line("some setup text")
    p.send(b"\x1b[raw bytes]")   # p.send for raw, p.text/p.line for UTF-8
```

`p.stress_bytes` and `p.sleep()` are available for bounded-growth and paced
probes. A function that raises is caught and logged; it won't take the server
down mid-gauntlet.

## Scope and safety

- Binds to `127.0.0.1` by default. Only pass `--host 0.0.0.0` on a network you
  control and understand — this server is hostile by design.
- Every payload is bounded; the "unbounded" probes are capped by
  `--stress-bytes`.
- It does not attempt to exploit anything beyond the display/ingest surface —
  no code execution, no filesystem access, no network calls out.

## Prior art

- **vttest** (Thomas E. Dickey) — the classic interactive VT100/VT220 torture
  test for terminal emulators.
- **esctest / esctest2** (from iTerm2) — an automated escape-sequence
  conformance suite.
- **libvterm / vte / alacritty / wezterm** and other emulators ship their own
  VT-parser unit tests and fuzz targets

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).

## Status

Early but functional: 19 bounded attacks, a stable server loop, and a README
mapping each probe to its robust-vs-failure tell. Intended to grow into a
portable adversarial test any MUD client can be run through.
