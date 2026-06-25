# rspamd-kam-rules

**Transpile SpamAssassin's KAM.cf ruleset into a single native Rspamd Lua plugin.**

> 📖 **Full write-up:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/) — why the naive `spamassassin` module approach bites, and how this converter avoids it.

## The problem

[KAM.cf](https://mcgrail.com/downloads/KAM.cf) is Kevin A. McGrail's SpamAssassin
ruleset — 3,000+ patterns that have caught phishing, malware droppers, and lottery
scams for years. It's good. It's also written in SpamAssassin's dialect and expects
SpamAssassin to run it.

Rspamd can load raw `.cf` files through its built-in `spamassassin` module, but that
path has three problems:

- It **re-parses all ~6,500 lines on every config load.**
- It **carries hundreds of rules it can't run.**
- It **never remaps symbol names** — `SPF_PASS` stays `SPF_PASS` instead of becoming
  Rspamd's `R_SPF_ALLOW`. Meta rules referencing unmapped symbols compile fine, then
  silently never fire.

## What this converter does instead

It parses KAM.cf properly and emits one self-contained `dist/kam.lua`:

- **Maps symbols** to Rspamd equivalents — `SPF_PASS` → `R_SPF_ALLOW`, `DKIM_VALID` →
  `R_DKIM_ALLOW`, the `URIBL_*` family → SURBL/DBL — so metas resolve and fire.
- **Prunes dead metas** via fixpoint dependency resolution: any meta whose transitive
  dependencies aren't reachable on *your* Rspamd is dropped (180 in the current run)
  and its missing symbols recorded in the report.
- **Preserves semantics** — regex flags, header modes (`addr`/`name`/`raw`/`case`),
  `replace_tag`/`replace_rules` expansion, body-vs-Subject matching (unless
  `nosubject`), and message-global `tflags multiple maxhits=N` scoring.
- **Registers properly** — every scored rule is a virtual child of the
  `KAM_RULES_MODULE` callback and joins the `KAM` symbol group, so the ruleset is one
  unit in the UI/history. External symbols used by metas become scheduler dependencies.
  Regexps compile via `rspamd_regexp.create`, metas via `rspamd_expression.create`.
- **Skips the unsupported** — `askdns`, `eval:` plugin functions, and friends go to the
  report, not the output.
- **Pins the source** — each `kam.lua` carries the SHA-256 of the exact KAM.cf it was
  built from.

## What gets converted

Of KAM.cf's ~6,500 lines, the current run converts **3,249 rules**:

| Type | Count | Catches |
|---|---|---|
| body | 1,179 | message-text patterns |
| header | 1,117 | Subject / From / Message-ID etc. |
| meta | 690 | combined-signal verdicts |
| uri | 156 | malicious redirectors, phishing domains |
| rawbody | 67 | base64-obfuscated payloads pre-decode |
| mimeheader | 38 | forged attachments |
| full | 2 | whole RFC 822 message |

A further **180 meta rules are dropped** because they depend on symbols the target
Rspamd doesn't provide (SA-plugin symbols, DNS lists, `eval:` functions).

## Install

```bash
# Download the pre-compiled plugin into your Rspamd plugins directory
sudo wget -O /etc/rspamd/plugins.d/kam.lua \
  https://raw.githubusercontent.com/eilandert/rspamd-kam-rules/main/dist/kam.lua
sudo chmod 0644 /etc/rspamd/plugins.d/kam.lua
```

A file in `plugins.d` stays disabled until its top-level module is configured. Add this
block to `/etc/rspamd/rspamd.conf.local` once:

```ucl
kam {
    enabled = true;
}
```

Then validate and restart:

```bash
sudo rspamadm configtest
sudo systemctl restart rspamd
sudo journalctl -u rspamd --since "5 minutes ago" | grep "generated KAM Lua rules"
```

### Staying up to date

The published `dist/kam.lua` is rebuilt **daily at 03:00 UTC** by GitHub Actions, but a
new file is only committed when KAM.cf's content actually changes. The workflow
downloads KAM.cf once, compares its SHA-256 against `dist/report.json`, and — if it
differs — passes that same hash to the converter so the bytes are verified before
conversion.

To pull updates automatically, re-run the `wget` above on a schedule (e.g. a daily
cron), or watch the repo.

### Capping the score

Every KAM symbol joins the `KAM` group (child of the `KAM_RULES_MODULE` callback). The
group is **uncapped** — symbols score additively. To cap the ruleset's total positive
contribution, drop `config/groups.conf` in as `/etc/rspamd/local.d/groups.conf` and set
`max_score`:

```
group "KAM" {
    max_score = 100;   # ceiling for the whole ruleset's contribution
}
```

## Build it yourself

```bash
python3 kam_rspamd.py                  # download KAM.cf, write dist/kam.lua + dist/report.json
python3 kam_rspamd.py --input KAM.cf   # convert a local file instead
python3 -m unittest discover -s tests  # Python conversion tests
bash tests/test_runtime.sh             # Docker + Rspamd integration tests
```

The converter uses **your** production symbol set, so the output adapts to your stack.
Two config files describe the target Rspamd:

- `config/external-symbols.txt` — a dump of your production Rspamd `/symbols` endpoint
  (everything your instance can raise). KAM-defined symbols are excluded.
- `config/unavailable-symbols.txt` — KAM symbols you *know* aren't registered on your
  stack, listed so dependent metas get pruned.
- `config/local-rules.cf` — optional supplement in SpamAssassin syntax, appended after
  upstream KAM.cf and compiled into the same `kam.lua`. Use it to define site-local
  rules or to supply a missing symbol that upstream metas depend on. Override the path
  with `--local-rules <file>`. The upstream-change SHA gate ignores this file, so editing
  it alone won't trip `update-if-changed.sh` — rerun `python3 kam_rspamd.py` to regenerate.

Regenerate the symbol dump whenever you change stacks, then rebuild.

For a pinned local source, add `--expected-sha256 <hash>`; conversion fails if the bytes
don't match.

## Performance note

The generated plugin compiles its regexps at Rspamd startup and evaluates scored rules
(and their dependencies) lazily during the callback. It does **not** promise a single
Hyperscan pass, and throughput depends on your corpus, enabled rules, Rspamd build, and
hardware.

The point of this converter is **correctness and hygiene**, not a speed claim: mapped
external symbols, explicit scheduler dependencies, dead metas pruned, and one auditable
artifact pinned to a known KAM.cf hash. Benchmark both approaches on your own traffic
before making performance claims.

## License

- **This project** (the converter) — MIT.
- **KAM.cf** — Apache-2.0, original authorship preserved (Kevin A. McGrail, with Joe
  Quinn, Karsten Bräckelmann, Bill Cole, and Giovanni Bechis). The generated
  `dist/kam.lua` is a derivative work of KAM.cf and inherits its Apache-2.0 license.

## See also

- **Article:** [KAM.cf in Rspamd: 3,200 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/2026/06/kam-cf-rspamd-lua-converter/)
- **Background:** [Rspamd Explained: How Modern Spam Filtering Actually Works](https://deb.myguard.nl/2026/05/rspamd-explained-modern-spam-filtering-bayes-neural-rbl/)
- **KAM.cf upstream:** [mcgrail.com/downloads/KAM.cf](https://mcgrail.com/downloads/KAM.cf)
- **Rspamd:** [rspamd.com](https://rspamd.com)
