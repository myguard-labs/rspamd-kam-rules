# rspamd-kam-rules

**Turn SpamAssassin's KAM.cf ruleset into a single native Rspamd Lua plugin.**

> 📖 **Full write-up:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/) — why the naive `spamassassin` module approach bites, and how this converter avoids it.

## The problem

[KAM.cf](https://mcgrail.com/downloads/KAM.cf) is Kevin A. McGrail's SpamAssassin
ruleset — 3,000+ patterns that have caught phishing, malware droppers, and lottery
scams for years. It's good. But it's written in SpamAssassin's dialect and assumes
SpamAssassin is running it.

Rspamd *can* load raw `.cf` files through its built-in `spamassassin` module, but that
path:

- **re-parses all ~10,600 lines on every config load**,
- **carries hundreds of rules it can't actually run**, and
- **never remaps symbol names** — `SPF_PASS` stays `SPF_PASS` instead of Rspamd's
  `R_SPF_ALLOW`, so metas that reference it compile fine and then silently never fire.

## What this converter does instead

It parses KAM.cf properly and emits two files:

- **`dist/kam.lua`** — a thin (~13 KB) static plugin: the runtime, no rule data.
- **`dist/kam_rules.map`** — the rules themselves (jsonl: one regex/meta/score per line).

At config load the plugin reads the map, registers each symbol, and compiles every
simple regex into Rspamd's **combined Hyperscan database** — so the ruleset is scanned
in one pass per message instead of running ~2,500 regexes one at a time. Along the way
it:

- **Remaps symbols** to Rspamd equivalents — `SPF_PASS` → `R_SPF_ALLOW`, `DKIM_VALID` →
  `R_DKIM_ALLOW`, the `URIBL_*` family → SURBL/DBL — so metas resolve and fire.
- **Prunes dead metas** — any meta whose dependencies your Rspamd can't provide is
  dropped (70 in the current run) and its missing symbols recorded in the report.
- **Preserves semantics** — regex flags, header modes (`addr`/`name`/`raw`/`case`),
  `replace_tag`/`replace_rules` expansion, and `tflags multiple maxhits=N` scoring.
- **Skips the unsupported** — `askdns`, `eval:` plugin functions and friends go to the
  report, not the output.
- **Pins the source** — `report.json` records the SHA-256 of KAM.cf, the plugin, and the
  map, so every build is traceable to one exact upstream file.

Because the plugin holds no rule data, a KAM.cf update only regenerates the map — the
daily CI commits `dist/kam_rules.map` + `dist/report.json`, never `kam.lua`. The map is
re-validated when loaded, so a tampered map can introduce no symbol outside the
SpamAssassin name charset and no Lua code.

## What gets converted

Of KAM.cf's ~10,600 lines, the current run converts **3,572 rules**:

| Type | Count | Catches |
|---|---|---|
| body | 1,264 | message-text patterns |
| header | 1,173 | Subject / From / Message-ID etc. |
| meta | 843 | combined-signal verdicts |
| uri | 162 | malicious redirectors, phishing domains |
| rawbody | 75 | base64-obfuscated payloads pre-decode |
| mimeheader | 53 | forged attachments |
| full | 2 | whole RFC 822 message |

A further **70 meta rules are dropped** because they depend on symbols the target
Rspamd doesn't provide (SA-plugin symbols, DNS lists, `eval:` functions).

## Install

Both files must be in place before Rspamd starts — the plugin reads the map at config
load to register symbols and build the Hyperscan DB.

```bash
# The plugin (static runtime) goes in plugins.d …
sudo wget -O /etc/rspamd/plugins.d/kam.lua \
  https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam.lua
# … and the rule map at the path the plugin reads at startup.
sudo wget -O /etc/rspamd/kam_rules.map \
  https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam_rules.map
sudo chmod 0644 /etc/rspamd/plugins.d/kam.lua /etc/rspamd/kam_rules.map
```

A file in `plugins.d` stays disabled until its module is configured. Add this block to
`/etc/rspamd/rspamd.conf.local` once (full options in `examples/kam.conf`):

```ucl
kam {
    enabled = true;
    # Every path and the self-update URL have baked-in defaults — this is all
    # you need. Self-update is ON by default (rspamd polls GitHub and stages a
    # fresh map; a `systemctl reload rspamd` applies it — see Staying up to
    # date). Set map_url = "" to disable it. Full options in examples/kam.conf.
}
```

Both example config files ship in `examples/`: `examples/kam.conf` is the block
above with every option documented, and `examples/groups.conf` carries the `KAM`
symbol-group metadata. To cap how much the whole ruleset can contribute, drop it in
and uncomment `max_score` (see [Capping the score](#capping-the-score)):

```bash
sudo wget -O /etc/rspamd/local.d/groups.conf \
  https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/examples/groups.conf
```

Then validate and reload:

```bash
sudo rspamadm configtest
sudo systemctl reload rspamd   # full reconfigure — re-runs plugin init
sudo journalctl -u rspamd --since "5 minutes ago" | grep "generated KAM Lua rules"
```

### Staying up to date

`dist/kam_rules.map` is rebuilt **daily at 03:00 UTC** by GitHub Actions, but only
committed when KAM.cf's content actually changes (the workflow compares its SHA-256
against `dist/report.json`). `dist/kam.lua` is static — it changes only when the runtime
code does, not on a rule update.

**The plugin updates itself.** Rspamd polls `map_url` (the published map on GitHub by
default) every `map_watch_interval` (default 5 minutes) and, when it changes, atomically
writes the new map to `cache_path` (`/var/lib/rspamd/kam_rules.map` — under DBDIR, the
only map dir the dropped-privilege rspamd user can write; `/etc/rspamd` is root-owned).
No host cron, no `curl`, no SHA-compare script: the download is rspamd's own job.

The catch: rspamd registers native regexps and symbols **only at config load**, so a
freshly downloaded map does **not** go live on download — the poll just stages it in the
cache. A plain `systemctl reload rspamd` (full reconfigure) applies it; the runtime
prefers the cache copy over the shipped seed at load. So the whole update path is:

```bash
# A dumb daily timer — no fetch logic, rspamd already downloaded the map:
sudo systemctl reload rspamd
```

Use `systemctl reload rspamd` (SIGHUP / full reconfigure), **not** `rspamadm control
reload`: the lighter `control reload` (maps + stats only) never re-runs plugin init, so
it would silently keep the old rules. The reload is graceful — workers drain in place,
Bayes and greylist state live in Redis — so it's safe to run on a timer; at worst it's a
no-op when nothing changed.

Set `map_url = ""` in the `kam {}` block to disable the poll (e.g. on a host that can't
resolve `raw.githubusercontent.com` — point it at an internal mirror instead) and fall
back to pulling the map yourself:

```bash
sudo wget -O /etc/rspamd/kam_rules.map \
  https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam_rules.map
sudo rspamadm configtest && sudo systemctl reload rspamd
```

`update-if-changed.sh` automates that manual fetch-compare-reload cycle for the
poll-disabled case.

### Checking for a newer upstream

KAM.cf carries **no version number** — upstream is tracked purely by the SHA-256 of the
file. To answer "is there a newer version upstream?", compare the SHA recorded in the
last build against the live file:

```bash
# SHA of the KAM.cf this build was pinned to
python3 -c 'import json; print(json.load(open("dist/report.json"))["source_sha256"])'

# SHA of the current upstream file
curl -fsSL https://mcgrail.com/downloads/KAM.cf | sha256sum
```

Hashes **match** → up to date, nothing to do. Hashes **differ** → upstream changed; run
`bash update-if-changed.sh` (or `python3 kam_rspamd.py`) to fetch, reconvert, and refresh
`dist/`. The script does this comparison itself and no-ops when the SHAs already match, so
running it on a cron is the hands-off way to stay current.

### Capping the score

Every KAM symbol joins the `KAM` group, which is **uncapped** — symbols score additively.
To cap the ruleset's total contribution, drop `examples/groups.conf` in as
`/etc/rspamd/local.d/groups.conf` and set `max_score`:

```
group "KAM" {
    max_score = 100;   # ceiling for the whole ruleset's contribution
}
```

## Build it yourself

```bash
python3 kam_rspamd.py                  # download KAM.cf, write dist/kam_rules.map + dist/report.json
python3 kam_rspamd.py --input KAM.cf   # convert a local file instead
python3 kam_rspamd.py --emit-lua       # also re-emit dist/kam.lua (only after a runtime-code change)
python3 -m unittest discover -s tests  # Python conversion tests
bash tests/test_runtime.sh             # Docker + Rspamd integration tests
```

The converter builds against **your** production symbol set, so the output adapts to your
stack. Three optional config files describe the target Rspamd:

- `config/external-symbols.txt` — a dump of your production Rspamd `/symbols` endpoint
  (everything your instance can raise; KAM-defined symbols are excluded).
- `config/unavailable-symbols.txt` — KAM symbols you *know* aren't registered on your
  stack, so dependent metas get pruned.
- `config/local-rules.cf` — optional site-local rules in SpamAssassin syntax, appended
  after upstream KAM.cf and compiled into the same output. Override the path with
  `--local-rules <file>`. The SHA gate ignores this file, so editing it alone won't trip
  `update-if-changed.sh` — rerun `python3 kam_rspamd.py` to regenerate.

Regenerate the symbol dump whenever you change stacks, then rebuild. For a pinned local
source, add `--expected-sha256 <hash>` — conversion fails if the bytes don't match.

## How matching works

Simple `body`/`rawbody`/`full`/`uri`/`header`/`mimeheader` rules register into the
**combined re-cache**, so Rspamd compiles them into one Hyperscan database per scan
category and matches the whole batch in a single pass per message (`task:process_regexp`).
Metas are then evaluated lazily over those cached results (`rspamd_expression`).

The exception is header rules with an `addr`/`name` transform or an
`ALL`/`ToCc`/`MESSAGEID` pseudo-header: those need per-value Lua post-processing, so they
keep an individual regex and scan in Lua. In the current run that's a small minority of
header rules; everything else rides the fast path.

Real throughput still depends on your corpus, enabled rules, Rspamd build (Hyperscan vs
PCRE fallback), and hardware — benchmark on your own traffic. The other point of the
converter is **correctness and hygiene**: mapped external symbols, explicit scheduler
dependencies, dead metas pruned, and one auditable artifact pinned to a known KAM.cf hash.

## License

- **This project** (the converter) — MIT.
- **KAM.cf** — Apache-2.0, original authorship preserved (Kevin A. McGrail, with Joe
  Quinn, Karsten Bräckelmann, Bill Cole, and Giovanni Bechis). The generated rules are a
  derivative work of KAM.cf and inherit its Apache-2.0 license. The full credits + Apache
  notice travel **with the rules**, in the `kam_rules.map` header (`_kam_credits` /
  `_kam_license` keys); `dist/kam.lua` carries only a short pointer to them.

## See also

- **Article:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/)
- **Background:** [Rspamd Explained: How Modern Spam Filtering Actually Works](https://deb.myguard.nl/2026/05/rspamd-explained-modern-spam-filtering-bayes-neural-rbl/)
- **KAM.cf upstream:** [mcgrail.com/downloads/KAM.cf](https://mcgrail.com/downloads/KAM.cf)
- **Our other Rspamd modules** (olefy, yarad, gyzor, mailstrix, …): [github.com/eilandert](https://github.com/eilandert)
- **Rspamd:** [rspamd.com](https://rspamd.com)
