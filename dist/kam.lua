-- ===========================================================================
-- rspamd-kam-rules — KAM.cf compiled to a native Rspamd Lua plugin.
-- Copyright (c) 2026 eilandert / myguard.nl
-- License: MIT (converter) — generated rules are Apache-2.0, see below
-- Home:    https://github.com/myguard-labs/rspamd-kam-rules
-- More Rspamd modules (olefy, yarad, gyzor, mailstrix, …): https://github.com/eilandert
--
-- Quick start:
--   1. wget kam.lua       -> /etc/rspamd/plugins.d/kam.lua
--   2. wget kam_rules.map -> /etc/rspamd/kam_rules.map
--   3. add to rspamd.conf.local:  kam { enabled = true; }   (see examples/kam.conf)
--   4. (optional) cap scoring: examples/groups.conf -> /etc/rspamd/local.d/groups.conf
--   5. rspamadm configtest && systemctl reload rspamd
-- Self-update: rspamd polls map_url (github by default) every map_watch_interval
-- and writes a fresh map to cache_path (/var/lib/rspamd, rspamd-writable). A
-- 'systemctl reload rspamd' timer then re-registers it (native regexps register
-- at config load only). Set map_url="" to disable polling.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- This plugin is generated from KAM.cf (Apache-2.0) and is a derivative work
-- of it. The full KAM.cf credits and Apache-2.0 notice travel WITH the rules,
-- in the kam_rules.map header (`_kam_credits` / `_kam_license` keys).
-- KAM.cf home: https://mcgrail.com/template/projects#KAM1
-- The converter itself (rspamd-kam-rules) is MIT-licensed.
-- ---------------------------------------------------------------------------

local rspamd_expression = require "rspamd_expression"
local rspamd_logger = require "rspamd_logger"
local rspamd_regexp = require "rspamd_regexp"
local rspamd_util = require "rspamd_util"

-- Map locations + self-update URL, overridable via the kam {} config block.
--   map_path   = shipped seed (read-only /etc/rspamd) — fallback only.
--   cache_path = rspamd-writable copy (/var/lib/rspamd) the poll writes
--                and the runtime PREFERS at load.
--   map_url    = remote map polled on map_watch_interval; "" disables.
local opts = rspamd_config:get_all_opt('kam') or {}
local kam_map_path = opts.map_path or [=[/etc/rspamd/kam_rules.map]=]
local kam_cache_path = opts.cache_path or [=[/var/lib/rspamd/kam_rules.map]=]
local kam_map_url = opts.map_url or [=[https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam_rules.map]=]

local rules = {}
local replacements = {}
local external_dependencies = {}
local expressions = {}
local rule_count = 0
local disabled_rule_count = 0

-- Symbol names are interpolated nowhere as code — they are only ever table keys
-- and insert_result() arguments — but the map is read from disk and could be
-- tampered with, so re-validate every name against the SA symbol charset (same
-- gate the Python emitter applies) before trusting a map entry.
local valid_name = rspamd_regexp.create('/^[A-Za-z0-9_]+$/')

-- Atom extractor for meta expressions; defined before compile_rule because
-- rspamd_expression.create captures it as the parse callback.
local function parse_atom(str)
  return str:match('^([^, %s%(%)><+!|&]+)') or ''
end

-- KAM rule.kind -> rspamd re-cache scan type passed to task:process_regexp.
-- These are the categories rspamd compiles into ONE combined Hyperscan DB and
-- scans in a single pass per category — the whole point of the native path.
--   body    -> sabody    (normalised, de-HTMLised text parts; SA `body` semantics)
--   rawbody -> sarawbody  (raw decoded text parts)
--   full    -> rawmime    (entire raw message)
--   uri     -> url
--   header  -> header / rawheader (+ header-name + strong/case flags)
--   mimeheader -> mimeheader
-- header rules with an addr/name transform, or the ALL pseudo-header, cannot go
-- through the combined DB (they need per-address Lua post-processing or the
-- allheader blob), so they keep an individually-compiled re + Lua scan path.
local SCAN_TYPE = {
  body = 'sabody', rawbody = 'sarawbody', full = 'rawmime', uri = 'url',
}

-- A header rule is "native" (combined-DB) only when it is a single concrete
-- header with no addr/name transform. ALL / ToCc / MESSAGEID multi-header and
-- addr/name modes drop to the slow per-value Lua path.
local function header_is_native(rule)
  if rule.header_mode == 'addr' or rule.header_mode == 'name' then return false end
  if rule.header == 'ALL' or rule.header == 'ToCc' or rule.header == 'MESSAGEID' then return false end
  return true
end

-- Compile one parsed rule entry: build its regexp (and register it in the
-- combined re-cache for the native fast path) or its meta expression, flagging
-- it disabled on failure so a broken rule is never scored.
local function compile_rule(name, rule)
  if rule.kind == 'meta' then
    local expr = rspamd_expression.create(rule.expression, parse_atom, rspamd_config:get_mempool())
    if expr then
      expressions[name] = expr
      rule.disabled = nil
    else
      rule.disabled = true
      disabled_rule_count = disabled_rule_count + 1
      rspamd_logger.errx(rspamd_config, 'cannot compile KAM meta %s: %s', name, rule.expression)
    end
    return
  end

  local re = rspamd_regexp.create(rule.expression)
  if not re then
    rule.disabled = true
    disabled_rule_count = disabled_rule_count + 1
    rspamd_logger.errx(rspamd_config, 'cannot compile KAM regexp %s: %s', name, rule.expression)
    return
  end
  -- maxhits caps a `multiple` rule; a non-multiple rule stops at the first hit.
  re:set_max_hits(rule.multiple and (rule.maxhits or 0) or 1)
  rule.re = re
  rule.disabled = nil

  -- Decide the scan type and register the regexp with the re-cache so it joins
  -- the combined Hyperscan DB. body/rawbody/full/uri map straight through;
  -- header/mimeheader register against their concrete header (+ raw flag).
  local scan_type = SCAN_TYPE[rule.kind]
  if scan_type then
    rule.scan_type = scan_type
    rspamd_config:register_regexp({ re = re, type = scan_type })
  elseif rule.kind == 'mimeheader' and header_is_native(rule) then
    rule.scan_type = 'mimeheader'
    rspamd_config:register_regexp({ re = re, type = 'mimeheader', header = rule.header })
  elseif rule.kind == 'header' and header_is_native(rule) then
    rule.scan_type = rule.header_mode == 'raw' and 'rawheader' or 'header'
    rspamd_config:register_regexp({ re = re, type = rule.scan_type, header = rule.header })
  else
    -- Slow path (addr/name transform, ALL/ToCc/MESSAGEID): scanned in Lua.
    rule.scan_type = nil
  end
end

-- Parse the jsonl map body into (rules, replacements, external_dependencies).
-- Line 1 is the header object ({_kam, replacements, external_dependencies});
-- every later non-blank line is one rule object keyed by its `name`. Malformed
-- lines and entries with an invalid name are skipped, not fatal — a single bad
-- line never takes the whole ruleset down.
local function parse_map(data)
  local ucl = require 'ucl'
  local parsed_rules, repl, deps = {}, {}, {}
  local header_seen = false
  for line in data:gmatch('[^\r\n]+') do
    if line:match('%S') then
      local parser = ucl.parser()
      local ok, err = parser:parse_string(line)
      if not ok then
        rspamd_logger.errx(rspamd_config, 'KAM map: bad json line: %s', err)
      else
        local obj = parser:get_object()
        if not header_seen then
          header_seen = true
          repl = obj.replacements or {}
          deps = obj.external_dependencies or {}
        elseif type(obj.name) == 'string' and valid_name:match(obj.name) then
          local name = obj.name
          obj.name = nil
          parsed_rules[name] = obj
        end
      end
    end
  end
  return parsed_rules, repl, deps
end

-- SLOW PATH ONLY: header rules with an addr/name transform, or ALL/ToCc/
-- MESSAGEID multi-header. These cannot ride the combined Hyperscan DB, so they
-- scan their individually-compiled rule.re value-by-value in Lua.
local function match_header_slow(task, rule)
  if rule.header == 'ALL' then
    local data = task:get_raw_headers()
    local hits = 0
    if data then
      if rule.multiple then
        -- matchn returns the hit count (capped by maxhits, 0 = uncapped).
        hits = rule.re:matchn(data, rule.maxhits or 0, true) or 0
      elseif rule.re:match(data, true) then
        hits = 1
      end
    end
    if rule.negate then
      return hits > 0 and 0 or 1
    end
    return rule.multiple and hits or (hits > 0 and 1 or 0)
  end

  local header_names = { rule.header }
  if rule.header == 'ToCc' then header_names = { 'To', 'Cc', 'Bcc' } end
  if rule.header == 'MESSAGEID' then header_names = { 'Message-ID', 'X-Message-ID', 'Resent-Message-ID' } end

  local hits = 0
  for _, header_name in ipairs(header_names) do
    local values = {}
    if rule.kind == 'mimeheader' then
      for _, part in ipairs(task:get_parts() or {}) do
        if part.get_header_full then
          for _, hdr in ipairs(part:get_header_full(header_name, rule.header_mode == 'case') or {}) do table.insert(values, hdr) end
        end
      end
    else
      values = task:get_header_full(header_name, rule.header_mode == 'case') or {}
    end
    for _, hdr in ipairs(values) do
      local value = rule.header_mode == 'raw' and hdr.value or (hdr.decoded or hdr.value)
      local candidates = {}
      if rule.header_mode == 'addr' or rule.header_mode == 'name' then
        for _, address in ipairs(rspamd_util.parse_mail_address(value or '') or {}) do
          local field = rule.header_mode == 'addr' and address.addr or address.name
          if field then table.insert(candidates, field) end
        end
      elseif value then
        table.insert(candidates, value)
      end
      for _, cand in ipairs(candidates) do
        if rule.re:match(cand, rule.header_mode == 'raw') then
          hits = hits + 1
          if not rule.multiple then break end
          if rule.maxhits and hits >= rule.maxhits then break end
        end
      end
      if not rule.multiple and hits > 0 then break end
      if rule.maxhits and hits >= rule.maxhits then break end
    end
    if not rule.multiple and hits > 0 then break end
    if rule.maxhits and hits >= rule.maxhits then break end
  end

  -- negate handled with an early return (mirrors the ALL branch above): a
  -- negated rule fires once when the pattern is ABSENT, weight 1, never a count.
  -- Folding negate into the multiple/hits ternary breaks on hits==0 because 0
  -- is truthy in Lua (`(multiple and 0 or 1)` returns 0, not 1).
  if rule.negate then
    return hits > 0 and 0 or 1
  end
  return rule.multiple and hits or (hits > 0 and 1 or 0)
end

local function eval_atom(name, task)
  local cache = task:cache_get('kam_lua_results')
  if not cache then cache = {}; task:cache_set('kam_lua_results', cache) end
  if cache[name] ~= nil then return cache[name] end
  cache[name] = 0
  local rule = rules[name]
  local result = 0
  if not rule then
    result = task:has_symbol(replacements[name] or name) and 1 or 0
  elseif rule.disabled then
    result = 0
  elseif rule.kind == 'meta' then
    local expression = expressions[name]
    if expression then
      result = expression:process(function(atom) return eval_atom(atom, task) end)
    end
  elseif rule.scan_type then
    -- NATIVE FAST PATH: single combined-Hyperscan-DB lookup. process_regexp
    -- returns the hit count (0 when no match); the DB was already scanned once
    -- for the whole ruleset, so this is just a result fetch.
    if rule.kind == 'header' or rule.kind == 'mimeheader' then
      result = task:process_regexp(rule.re, rule.scan_type, rule.header, rule.header_mode == 'case')
    else
      result = task:process_regexp(rule.re, rule.scan_type)
    end
    result = result or 0
    if rule.negate then result = result > 0 and 0 or 1 end
    if not rule.multiple and result > 1 then result = 1 end
  elseif rule.kind == 'header' or rule.kind == 'mimeheader' then
    result = match_header_slow(task, rule)
  end
  cache[name] = result or 0
  return cache[name]
end

-- Init load (synchronous): read the bundled map beside the plugin so symbols
-- and regexps can be registered at config-load time — registration (and the
-- combined-DB compile) only happens at config load. `replacements`/
-- `external_dependencies` come from the same header (dependency wiring +
-- has_symbol fallback for external atoms).
local function read_file(path)
  local handle = io.open(path, 'r')
  if not handle then return nil end
  local data = handle:read('*a')
  handle:close()
  return data
end

do
  -- Prefer the self-updated cache copy (/var/lib/rspamd, written by the poll
  -- below); fall back to the shipped seed (/etc/rspamd) on first boot or if the
  -- cache is absent. Both feed the same parse_map → native register at load.
  local init_data = read_file(kam_cache_path)
  local source = kam_cache_path
  if not init_data then
    init_data = read_file(kam_map_path)
    source = kam_map_path
  end
  if not init_data then
    rspamd_logger.errx(rspamd_config,
      'KAM: cannot read map (tried %s then %s); no rules loaded',
      kam_cache_path, kam_map_path)
    init_data = ''
  else
    rspamd_logger.infox(rspamd_config, 'KAM: loaded rule map from %s', source)
  end
  rules, replacements, external_dependencies = parse_map(init_data)
end

-- Self-update poll (C1): rspamd fetches kam_map_url on map_watch_interval and
-- hands the full new content to this callback. It does NOT (cannot) register
-- rules here — native register_regexp only runs at config load. It only writes
-- the bytes to the rspamd-writable cache path (atomic tmp+rename, lock-guarded
-- so concurrent workers can't tear the file); a 'systemctl reload rspamd' timer
-- then re-reads the cache and re-registers. Set map_url = "" to disable.
if kam_map_url and kam_map_url ~= '' then
  rspamd_config:add_map({
    type = 'callback',
    url = kam_map_url,
    description = 'KAM rule map self-update (downloads to cache; reload applies)',
    callback = function(content)
      if not content or #content == 0 then return end
      -- Skip the write if the cache already holds these exact bytes — avoids
      -- needless churn and log noise when the poll returns an unchanged map.
      local current = read_file(kam_cache_path)
      if current == content then return end
      local tmp = kam_cache_path .. '.tmp'
      local lock = rspamd_util.lock_file(kam_cache_path .. '.lock')
      local fh = io.open(tmp, 'w')
      if not fh then
        if lock then rspamd_util.unlock_file(lock) end
        rspamd_logger.errx(rspamd_config,
          'KAM: cannot write map cache %s (check perms; rspamd user owns /var/lib/rspamd)',
          tmp)
        return
      end
      fh:write(content)
      fh:close()
      local ok = os.rename(tmp, kam_cache_path)
      if lock then rspamd_util.unlock_file(lock) end
      if ok then
        rspamd_logger.infox(rspamd_config,
          'KAM: downloaded updated rule map to %s (%s bytes); '
          .. 'reload rspamd to apply', kam_cache_path, tostring(#content))
      else
        os.remove(tmp)
        rspamd_logger.errx(rspamd_config, 'KAM: failed to rename %s -> %s',
          tmp, kam_cache_path)
      end
    end,
  })
end

for name, rule in pairs(rules) do
  rule_count = rule_count + 1
  compile_rule(name, rule)
end

local function kam_callback(task)
  for name, rule in pairs(rules) do
    if rule.score ~= 0 then
      local result = eval_atom(name, task)
      if result and result > 0 then
        task:insert_result(name, rule.kind == 'meta' and 1 or result)
      end
    end
  end
end

local parent_id = rspamd_config:register_symbol({
  name = 'KAM_RULES_MODULE', type = 'normal', callback = kam_callback,
  score = 0.01, priority = 5, group = 'KAM'
})

for _, dependency in ipairs(external_dependencies) do
  rspamd_config:register_dependency('KAM_RULES_MODULE', dependency)
end

-- Every scored rule is a virtual child of KAM_RULES_MODULE and belongs to the
-- 'KAM' group. The group is uncapped (no max_score) — purely organisational, so
-- the symbols sum additively. Add a max_score in groups.conf to cap the total.
for name, rule in pairs(rules) do
  if rule.score ~= 0 then
    rspamd_config:register_symbol({
      name = name, type = 'virtual', parent = parent_id, score = rule.score,
      description = rule.description, group = 'KAM'
    })
  end
end

rspamd_logger.infox(
  rspamd_config,
  'loaded %s generated KAM Lua rules (%s disabled after compile errors)',
  tostring(rule_count),
  tostring(disabled_rule_count)
)
