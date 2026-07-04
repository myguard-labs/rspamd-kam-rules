# TODO

- [ ] Drop or retarget dormant `URIBL_WS_SURBL → WS_SURBL_MULTI` remap: target absent
      from the pristine rspamd 4.1.0 symbol set (WS SURBL zone retired upstream);
      currently self-correcting (metas depending on it drop) but stale.
- [ ] Re-sort `SYMBOL_REPLACEMENTS` fully alphabetically (pre-existing tail entries
      out of order relative to the 2026-07-04 remap block).
- [ ] README top link uses /2026/06/kam-cf-rspamd-lua-converter/ — canonical is /articles/kam-cf-rspamd-lua-converter/ (redirect works, cosmetic)
- [ ] Collision guard: local-rules/SA-lift names silently shadow same-named KAM.cf
      rules (last-write-wins in parse_rules) — surface an overridden_rules report
      field if a future KAM.cf adds a name the supplement already defines.
