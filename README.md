# rspamd-kam-rules

**Transpile SpamAssassin's KAM.cf ruleset into a single native Rspamd Lua plugin.**

> 📖 **Full write-up:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/) — why the naive `spamassassin` module approach bites, and how this converter avoids it.

## Two spam fighters, one ruleset

**SpamAssassin** is the elder. Its KAM.cf ruleset (Kevin A. McGrail's collection of
3,000+ patterns) has caught phishing, malware droppers, and lottery scams for years.
It's genuinely good — and written in SpamAssassin's dialect, which expects
SpamAssassin to run it.

**Rspamd** is the faster animal: event-driven C core, Lua logic, and a regexp engine
that compiles every pattern once at startup and scans each message in a single
Hyperscan pass. Running KAM.cf on Rspamd instead of the Perl daemon is a large win.

You *can* feed the raw `.cf` to Rspamd's built-in `spamassassin` module. But that
parses all ~6,500 lines on every config load, carries hundreds of rules it can't run,
and never remaps SpamAssassin symbol names like `SPF_PASS` to Rspamd's `R_SPF_ALLOW`.
Meta rules that reference unmapped symbols compile fine and then silently never fire.

## What this does instead

This converter reads KAM.cf with a real parser and emits one self-contained `kam.lua`:

- **Maps symbols** — `SPF_PASS` → `R_SPF_ALLOW`, `DKIM_VALID` → `R_DKIM_ALLOW`, the
  `URIBL_*` family → Rspamd's SURBL/DBL symbols, so metas actually resolve and fire.
- **Prunes dead metas** — fixpoint dependency resolution drops any meta whose
  transitive dependencies aren't reachable on *your* Rspamd (179 in the current run),
  recording the missing symbols in the report.
- **Preserves semantics** — regex flags, header modes (`addr`/`name`/`raw`/`case`),
  `replace_tag`/`replace_rules` expansion, and `tflags multiple maxhits=N` per-hit
  scoring all survive.
- **Registers properly** — every pattern goes into Rspamd's regexp cache by type
  (`sabody`, `sarawbody`, `message`, `url`, `mimeheader`, header variants) for
  single-pass Hyperscan scanning. Metas compile via `rspamd_expression.create`.
- **Skips the unsupported** — `askdns`, `eval:` plugin functions, and friends go to
  the report, not the output.
- **Pins the source** — each generated `kam.lua` carries the SHA-256 of the exact
  KAM.cf it was built from.

The result is one `kam.lua` that drops into Rspamd's plugin directory.

## What gets converted

Out of KAM.cf's ~6,500 lines, the current run converts **3,248 rules**:

| Type | Count | Catches |
|---|---|---|
| body | 1,179 | message-text patterns |
| header | 1,116 | Subject / From / Message-ID etc. |
| meta | 690 | combined-signal verdicts |
| uri | 156 | malicious redirectors, phishing domains |
| rawbody | 67 | base64-obfuscated payloads pre-decode |
| mimeheader | 38 | forged attachments |
| full | 2 | whole RFC 822 message |

179 meta rules are deliberately dropped because they depend on symbols the target
Rspamd doesn't provide (SA-plugin symbols, DNS lists, `eval:` functions).

## Install

```bash
# Download the pre-compiled plugin into your Rspamd plugins directory
sudo wget -O /etc/rspamd/plugins.d/kam.lua \
  https://raw.githubusercontent.com/eilandert/rspamd-kam-rules/main/dist/kam.lua

# Validate BEFORE you reload a production mail filter
rspamadm configtest && systemctl restart rspamd
```

The plugin is regenerated **daily at 3am UTC** via GitHub Actions, but only commits a
new `dist/kam.lua` when KAM.cf upstream actually changes (it compares the
`Last-Modified` header against a stored timestamp).

## Build it yourself

```bash
# Uses your production symbol set so the output adapts to your stack
python3 kam_rspamd.py                       # downloads KAM.cf, writes dist/kam.lua + dist/report.json
python3 kam_rspamd.py --input KAM.cf        # convert a local file instead
python3 -m unittest discover -s tests       # run the test suite
```

Two config files describe the target Rspamd:

- `config/external-symbols.txt` — dump of your production Rspamd `/symbols` endpoint
  (everything your instance can raise). KAM-defined symbols are excluded.
- `config/unavailable-symbols.txt` — KAM symbols you know aren't registered on your
  stack, listed explicitly so dependent metas get pruned.

Regenerate the symbol dump whenever you change stacks, then rebuild.

## Performance note (read this)

Running KAM.cf inside Rspamd is far faster than SpamAssassin's Perl daemon — often
~40 ms/message versus several hundred, without pinning 2–4 cores. That gap is
**Rspamd vs SpamAssassin**, not this converter vs Rspamd's SA module: both run inside
the same regexp cache, so they're in the same ballpark on raw scan speed.

What this converter buys you over the SA module is **correctness and hygiene**:
symbols that resolve, dead metas pruned, a single auditable file pinned to a known
KAM.cf hash, and no 6,500-line parse on every reload. Don't trust anyone quoting a
"20× speedup" from the converter specifically.

## License

**This project** (the converter) is MIT-licensed.

**KAM.cf** remains under Apache-2.0 with its original authorship (Kevin A. McGrail,
with Joe Quinn, Karsten Bräckelmann, Bill Cole, and Giovanni Bechis). The generated
`dist/kam.lua` is a derivative work of KAM.cf and inherits its Apache-2.0 license.

## See also

- **Article:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/)
- **Background:** [Rspamd Explained: How Modern Spam Filtering Actually Works](https://deb.myguard.nl/2026/05/rspamd-explained-modern-spam-filtering-bayes-neural-rbl/)
- **KAM.cf upstream:** [mcgrail.com/downloads/KAM.cf](https://mcgrail.com/downloads/KAM.cf)
- **Rspamd:** [rspamd.com](https://rspamd.com)
