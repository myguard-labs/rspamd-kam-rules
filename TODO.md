# TODO

- [ ] Drop or retarget dormant `URIBL_WS_SURBL → WS_SURBL_MULTI` remap: target absent
      from the pristine rspamd 4.1.0 symbol set (WS SURBL zone retired upstream);
      currently self-correcting (metas depending on it drop) but stale.
- [ ] Re-sort `SYMBOL_REPLACEMENTS` fully alphabetically (pre-existing tail entries
      out of order relative to the 2026-07-04 remap block).
