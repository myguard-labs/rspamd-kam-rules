# rspamd-kam-rules

**Turn SpamAssassin's KAM.cf ruleset into a single native Rspamd Lua plugin — with a rule map the plugin keeps up to date by itself.**

> 📖 **Full write-up:** [KAM.cf in Rspamd: 3,668 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/articles/kam-cf-rspamd-lua-converter/) — why the naive `spamassassin` module approach bites, and how this converter avoids it.

## The problem

[KAM.cf](https://mcgrail.com/downloads/KAM.cf) is Kevin A. McGrail's SpamAssassin
ruleset — thousands of patterns that have caught phishing, malware droppers, and
lottery scams for years. It's good. But it's written in SpamAssassin's dialect and
assumes SpamAssassin is running it.

Rspamd *can* load raw `.cf` files through its built-in `spamassassin` module, but that
path re-parses all ~10,600 lines on every config load, carries hundreds of rules it
can't actually run, and never remaps symbol names — `SPF_PASS` stays `SPF_PASS`
instead of Rspamd's `R_SPF_ALLOW`, so metas that reference it compile fine and then
silently never fire.

## What this converter does instead

It parses the KAM channel properly and emits two files:

- **`dist/kam.lua`** — a thin (~18 KB) static plugin: the runtime, no rule data.
- **`dist/kam_rules.map`** — the rules themselves (jsonl: one regex/meta/score per line).
  **Rspamd downloads updates to this file itself** — see
  [Staying up to date](#staying-up-to-date).

At config load the plugin reads the map, registers each symbol, and compiles every
simple regex into Rspamd's **combined Hyperscan database** — the ruleset is scanned in
one pass per message instead of running ~2,800 regexes one at a time. Along the way it:

- **Remaps symbols** to Rspamd equivalents — `SPF_PASS` → `R_SPF_ALLOW`, `DKIM_VALID` →
  `R_DKIM_ALLOW`, the `URIBL_*` family → SURBL/DBL — so metas resolve and fire.
- **Prunes dead metas** — any meta whose dependencies your Rspamd can't provide is
  dropped (67 in the current run) and its missing symbols recorded in the report.
- **Preserves semantics** — regex flags, header modes (`addr`/`name`/`raw`/`case`),
  `replace_tag`/`replace_rules` expansion, `tflags multiple maxhits=N` scoring.
- **Pins the source** — `report.json` records the SHA-256 of KAM.cf, the plugin, and the
  map, so every build is traceable to one exact upstream file. The map is re-validated
  on load, so a tampered map can inject no Lua and no rogue symbol.

The plugin holds no rule data, so a KAM.cf update only regenerates the map — CI commits
`dist/kam_rules.map` + `dist/report.json`, never `kam.lua`.

## What gets converted

Of the KAM channel's ~11,400 lines (KAM.cf + KAM_redirectors.cf +
nonKAMrules.cf snapshots in `config/`), the current run converts **3,668 rules**:

| Type | Count | Catches |
|---|---|---|
| body | 1,269 | message-text patterns |
| header | 1,186 | Subject / From / Message-ID etc. |
| meta | 862 | combined-signal verdicts |
| uri | 211 | malicious redirectors, phishing domains |
| rawbody | 82 | base64-obfuscated payloads pre-decode |
| mimeheader | 54 | forged attachments |
| full | 4 | whole RFC 822 message |

A further **67 meta rules are dropped** because they depend on symbols the target
Rspamd doesn't provide (SA-plugin symbols, DNS lists, `eval:` functions).

## Install

Both files must be in place before Rspamd starts — the plugin reads the map at config
load to register symbols and build the Hyperscan DB. The map download is a **one-time
seed**: after this, rspamd fetches map updates on its own.

```bash
sudo wget -O /etc/rspamd/plugins.d/kam.lua \
  https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam.lua
sudo wget -O /etc/rspamd/kam_rules.map \
  https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam_rules.map
sudo chmod 0644 /etc/rspamd/plugins.d/kam.lua /etc/rspamd/kam_rules.map
```

Enable the module once in `/etc/rspamd/rspamd.conf.local` (all options and defaults
documented in `examples/kam.conf`):

```ucl
kam {
    enabled = true;
}
```

Then validate and reload:

```bash
sudo rspamadm configtest
sudo systemctl reload rspamd   # full reconfigure — re-runs plugin init
sudo journalctl -u rspamd --since "5 minutes ago" | grep "generated KAM Lua rules"
```

## Staying up to date

**The rule map updates itself; the plugin (`kam.lua`) doesn't and shouldn't change
much.** Rspamd polls `map_url` (the published map on GitHub by default) every
`map_watch_interval` (default 5 minutes) and, when it changes, atomically stages the new
map at `cache_path` (`/var/lib/rspamd/kam_rules.map` — the one map dir the
dropped-privilege rspamd user can write). No host cron, no `curl`, no SHA-compare
script: the download is rspamd's own job.

One catch: rspamd registers symbols and regexps **only at config load**, so a staged
map goes live on the next reload, not on download. The whole update path is therefore
a dumb daily timer:

```bash
sudo systemctl reload rspamd   # applies whatever rspamd already downloaded
```

Use `systemctl reload rspamd` (full reconfigure), **not** `rspamadm control reload` —
the lighter one never re-runs plugin init and would silently keep the old rules. The
reload is graceful (workers drain, Bayes/greylist state lives in Redis), so at worst
it's a no-op.

If your mail host can't resolve `raw.githubusercontent.com`, set `map_url = ""` in the
`kam {}` block (or point it at an internal mirror) and pull the map yourself —
`update-if-changed.sh` automates that fetch-compare-reload cycle.

### How the map itself stays fresh

`dist/kam_rules.map` is rebuilt daily at 03:00 UTC by GitHub Actions, but only when the
KAM ruleset actually changed. The change signal is the KAM sa-update **channel serial
published in DNS** (SpamAssassin version reversed, same scheme as
`updates.spamassassin.org`):

```sh
dig +short TXT 0.0.4.kam.sa-channels.mcgrail.com   # current channel serial
cat dist/kam.serial                                 # serial this build was made against
```

Only when the DNS serial is strictly newer than `dist/kam.serial` does CI fetch KAM.cf;
a SHA-256 check then decides whether a rebuild is really needed (an upstream re-touch
with identical bytes just records the new serial). An empty/unresolvable TXT answer is
treated as "no change", so a DNS blip never forces a rebuild.

## Capping the score

Every KAM symbol joins the `KAM` group, which is **uncapped** — symbols score
additively. To cap the ruleset's total contribution, drop `examples/groups.conf` in as
`/etc/rspamd/local.d/groups.conf` and set `max_score`:

```
group "KAM" {
    max_score = 100;   # ceiling for the whole ruleset's contribution
}
```

## How matching works

Simple `body`/`rawbody`/`full`/`uri`/`header`/`mimeheader` rules register into the
combined re-cache: one Hyperscan database per scan category, matched in a single pass
per message (`task:process_regexp`). Metas evaluate lazily over those cached results
(`rspamd_expression`). Header rules needing `addr`/`name` transforms or
`ALL`/`ToCc`/`MESSAGEID` pseudo-headers keep an individual Lua scan — a small minority;
everything else rides the fast path.

Real throughput depends on your corpus, Rspamd build (Hyperscan vs PCRE fallback), and
hardware — benchmark on your own traffic. The other point of the converter is
**correctness and hygiene**: mapped symbols, dead metas pruned, one auditable artifact
pinned to a known KAM.cf hash.

## License

- **This project** (the converter) — MIT.
- **KAM.cf** — Apache-2.0, original authorship preserved (Kevin A. McGrail, with Joe
  Quinn, Karsten Bräckelmann, Bill Cole, and Giovanni Bechis). The generated rules are a
  derivative work of KAM.cf and inherit its Apache-2.0 license. The full credits +
  Apache notice travel **with the rules**, in the `kam_rules.map` header
  (`_kam_credits` / `_kam_license` keys).

## See also

- **Article:** [KAM.cf in Rspamd: 3,668 SpamAssassin Rules, Native Lua, No Perl](https://deb.myguard.nl/articles/kam-cf-rspamd-lua-converter/)
- **Background:** [Rspamd Explained: How Modern Spam Filtering Actually Works](https://deb.myguard.nl/articles/rspamd-explained-spam-filtering/)
- **KAM.cf upstream:** [mcgrail.com/downloads/KAM.cf](https://mcgrail.com/downloads/KAM.cf)
- **Our other Rspamd modules** (olefy, yarad, gyzor, mailstrix, …): [github.com/eilandert](https://github.com/eilandert)
- **Rspamd:** [rspamd.com](https://rspamd.com)
