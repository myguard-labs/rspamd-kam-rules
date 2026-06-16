#!/usr/bin/env python3
"""Download KAM.cf and compile supported rules to a standalone Rspamd Lua plugin."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tempfile
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_URL = "https://mcgrail.com/downloads/KAM.cf"
REGEX_TYPES = {"body", "full", "header", "mimeheader", "rawbody", "uri"}

# Reproduced from the KAM.cf source header so the generated plugin — a derivative
# work of KAM.cf — carries its credits and Apache-2.0 notice. Verbatim wording from
# the upstream file; emitted as Lua comments at the top of kam.lua.
KAM_LICENSE_HEADER = """\
-- ---------------------------------------------------------------------------
-- This plugin is generated from KAM.cf and is a derivative work of it.
-- KAM.cf — the KAM ruleset for Apache SpamAssassin.
--
-- Authors: Kevin A. McGrail, with key contributions from Joe Quinn,
--          Karsten Bräckelmann, Bill Cole & Giovanni Bechis.
-- Thanks to Wolfgang Breyha for his help fixing a few rules.
-- Maintained by The McGrail Foundation, a 501(c)(3) charity.
-- Home: https://mcgrail.com/template/projects#KAM1
--
-- Copyright (c) 2022 Kevin A. McGrail and The McGrail Foundation
--
--   Licensed under the Apache License, Version 2.0 (the "License");
--   you may not use this file except in compliance with the License.
--   You may obtain a copy of the License at
--
--       http://www.apache.org/licenses/LICENSE-2.0
--
--   Unless required by applicable law or agreed to in writing, software
--   distributed under the License is distributed on an "AS IS" BASIS,
--   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
--   See the License for the specific language governing permissions and
--   limitations under the License.
--
-- The converter itself (rspamd-kam-rules) is MIT-licensed.
-- ---------------------------------------------------------------------------"""
# Rule/symbol names are interpolated into the generated Lua as table keys, so
# they must be restricted to the SpamAssassin symbol charset. Anything else is a
# malformed (or hostile) source line and is dropped to prevent Lua injection.
VALID_NAME = re.compile(r"[A-Za-z0-9_]+\Z")
KNOWN_PLUGINS = {
    "Mail::SpamAssassin::Plugin::BodyEval",
    "Mail::SpamAssassin::Plugin::FreeMail",
    "Mail::SpamAssassin::Plugin::HeaderEval",
    "Mail::SpamAssassin::Plugin::HTMLEval",
    "Mail::SpamAssassin::Plugin::MIMEEval",
    "Mail::SpamAssassin::Plugin::MIMEHeader",
    "Mail::SpamAssassin::Plugin::RelayEval",
    "Mail::SpamAssassin::Plugin::ReplaceTags",
    "Mail::SpamAssassin::Plugin::WLBLEval",
}
SYMBOL_REPLACEMENTS = {
    "BODY_URI_ONLY": "R_EMPTY_IMAGE",
    "DKIM_VALID": "R_DKIM_ALLOW",
    "SPF_FAIL": "R_SPF_FAIL",
    "SPF_HELO_FAIL": "R_SPF_FAIL",
    "SPF_HELO_PASS": "R_SPF_ALLOW",
    "SPF_HELO_SOFTFAIL": "R_SPF_SOFTFAIL",
    "SPF_PASS": "R_SPF_ALLOW",
    "SPF_SOFTFAIL": "R_SPF_SOFTFAIL",
    "URIBL_ABUSE_SURBL": "ABUSE_SURBL",
    "URIBL_CR_SURBL": "CRACKED_SURBL",
    "URIBL_DBL_ABUSE_BOTCC": "DBL_ABUSE_BOTNET",
    "URIBL_DBL_ABUSE_MALW": "DBL_ABUSE_MALWARE",
    "URIBL_DBL_ABUSE_REDIR": "DBL_ABUSE_REDIR",
    "URIBL_DBL_ABUSE_SPAM": "DBL_ABUSE",
    "URIBL_DBL_BOTNETCC": "DBL_BOTNET",
    "URIBL_DBL_MALWARE": "DBL_MALWARE",
    "URIBL_DBL_PHISH": "DBL_PHISH",
    "URIBL_DBL_SPAM": "DBL_SPAM",
    "URIBL_MW_SURBL": "MW_SURBL_MULTI",
    "URIBL_PH_SURBL": "PH_SURBL_MULTI",
    "URIBL_SBL_A": "URIBL_SBL",
    "URIBL_WS_SURBL": "WS_SURBL_MULTI",
}
for suffix, target in {
    "04": "HTML_SHORT_LINK_IMG_1",
    "08": "HTML_SHORT_LINK_IMG_1",
    "12": "HTML_SHORT_LINK_IMG_1",
    "16": "HTML_SHORT_LINK_IMG_2",
    "20": "HTML_SHORT_LINK_IMG_2",
    "24": "HTML_SHORT_LINK_IMG_3",
    "28": "HTML_SHORT_LINK_IMG_3",
    "32": "HTML_SHORT_LINK_IMG_3",
}.items():
    SYMBOL_REPLACEMENTS[f"HTML_IMAGE_ONLY_{suffix}"] = target


class ConversionError(RuntimeError):
    pass


@dataclass
class Rule:
    name: str
    kind: str
    expression: str
    header: str | None = None
    header_mode: str | None = None
    negate: bool = False
    description: str = ""
    score: float = 0.0
    tflags: set[str] = field(default_factory=set)
    maxhits: int | None = None


def download(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "rspamd-kam-rules/2.0 (+https://github.com/eilandert/rspamd-kam-rules)"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def read_symbol_file(path: Path) -> set[str]:
    if not path.is_file():
        return set()
    return {
        line.strip()
        for line in path.read_text().splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }


def active_lines(text: str) -> list[tuple[int, str]]:
    output: list[tuple[int, str]] = []
    stack: list[tuple[bool, bool]] = []
    active = True

    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("ifplugin "):
            condition = stripped.split(None, 1)[1] in KNOWN_PLUGINS
            stack.append((active, condition))
            active = active and condition
            continue
        if stripped.startswith("if "):
            plugin = re.match(r"if\s+(!?)plugin\(([^)]+)\)", stripped)
            if plugin:
                # `if plugin(X)` is true when X is loaded; `if !plugin(X)` is the
                # inverse. Capability (`if can(...)`) and `if version` guards are
                # not modelled, so their blocks stay inactive (conservative drop).
                known = plugin.group(2) in KNOWN_PLUGINS
                condition = (not known) if plugin.group(1) else known
            else:
                condition = False
            stack.append((active, condition))
            active = active and condition
            continue
        if stripped == "else":
            if not stack:
                raise ConversionError(f"unbalanced else at line {number}")
            parent, condition = stack[-1]
            active = parent and not condition
            stack[-1] = (parent, not condition)
            continue
        if stripped == "endif":
            if not stack:
                raise ConversionError(f"unbalanced endif at line {number}")
            parent, _ = stack.pop()
            active = parent
            continue
        if active:
            output.append((number, stripped))

    if stack:
        raise ConversionError("unbalanced conditional block")
    return output


def extract_regex(value: str) -> str | None:
    value = value.strip()
    if not value:
        return None
    if value.startswith("/"):
        delimiter, start = "/", 1
    elif value.startswith("m") and len(value) > 2 and not value[1].isalnum():
        delimiter, start = value[1], 2
    else:
        return None

    escaped = False
    for index in range(start, len(value)):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == delimiter:
            end = index + 1
            while end < len(value) and value[end] in "imsx":
                end += 1
            return value[:end]
    return None


def meta_dependencies(expression: str) -> set[str]:
    return set(re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expression))


def external_meta_dependencies(rules: dict[str, Rule], external_symbols: set[str]) -> set[str]:
    dependencies: set[str] = set()
    for rule in rules.values():
        if rule.kind != "meta":
            continue
        for dependency in meta_dependencies(rule.expression):
            target = SYMBOL_REPLACEMENTS.get(dependency, dependency)
            if dependency not in rules and target in external_symbols:
                dependencies.add(target)
    return dependencies


def parse_rules(
    source: bytes,
    external_symbols: set[str],
    unavailable_symbols: set[str],
) -> tuple[dict[str, Rule], Counter, list[dict[str, object]], dict[str, list[str]]]:
    text = source.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    lines = active_lines(text)
    rules: dict[str, Rule] = {}
    descriptions: dict[str, str] = {}
    scores: dict[str, float] = {}
    tflags: dict[str, set[str]] = {}
    maxhits: dict[str, int] = {}
    replace_tags: dict[str, str] = {}
    replace_rules: set[str] = set()
    omitted = Counter()
    examples: list[dict[str, object]] = []

    def omit(number: int, directive: str, line: str) -> None:
        omitted[directive] += 1
        if len(examples) < 50:
            examples.append({"line": number, "directive": directive, "text": line[:240]})

    for number, line in lines:
        parts = line.split(None, 2)
        directive = parts[0].lower()
        if directive == "describe" and len(parts) == 3:
            descriptions[parts[1]] = parts[2]
        elif directive == "score" and len(parts) == 3:
            try:
                values = parts[2].split("#", 1)[0].split()
                scores[parts[1]] = float(values[-1])
            except (ValueError, IndexError):
                omit(number, "invalid_score", line)
        elif directive == "tflags" and len(parts) == 3:
            flags = set(parts[2].split())
            tflags.setdefault(parts[1], set()).update(flags)
            for flag in flags:
                if flag.startswith("maxhits="):
                    try:
                        maxhits[parts[1]] = int(flag.split("=", 1)[1])
                    except ValueError:
                        pass
        elif directive == "replace_tag" and len(parts) == 3:
            replace_tags[parts[1]] = parts[2]
        elif directive == "replace_rules" and len(parts) >= 2:
            replace_rules.update(" ".join(parts[1:]).split())
        elif directive == "meta" and len(parts) == 3:
            if not VALID_NAME.match(parts[1]):
                omit(number, "invalid_name", line)
            elif parts[2].strip() != "0":
                rules[parts[1]] = Rule(parts[1], "meta", parts[2])
        elif directive in REGEX_TYPES and len(parts) == 3:
            name, value = parts[1], parts[2]
            if not VALID_NAME.match(name):
                omit(number, "invalid_name", line)
                continue
            header = header_mode = None
            negate = False
            if directive in {"header", "mimeheader"}:
                match = re.match(r"(\S+)\s*([=!])~\s*(.+)", value)
                if not match:
                    omit(number, "unsupported_header", line)
                    continue
                header_spec, operator, value = match.groups()
                negate = operator == "!"
                header_parts = header_spec.split(":")
                header = header_parts[0]
                header_mode = header_parts[1] if len(header_parts) > 1 else None
            expression = extract_regex(value)
            if not expression:
                omit(number, f"unsupported_{directive}", line)
                continue
            expression = re.sub(r"(?<!\\)\$\?", r"\\$?", expression)
            rules[name] = Rule(
                name=name,
                kind=directive,
                expression=expression,
                header=header,
                header_mode=header_mode,
                negate=negate,
            )
        elif directive not in {
            "priority",
            "replace_inter",
            "replace_post",
            "replace_pre",
            "reuse",
        }:
            omit(number, directive, line)

    for name, rule in rules.items():
        rule.description = descriptions.get(name, "")
        rule.score = scores.get(name, 0.0)
        rule.tflags = tflags.get(name, set())
        rule.maxhits = maxhits.get(name)

    resolved_tags = dict(replace_tags)
    for _ in range(len(resolved_tags) + 1):
        changed = False
        for name, value in tuple(resolved_tags.items()):
            replaced = re.sub(
                r"<([A-Za-z0-9_]+)>",
                lambda match: resolved_tags.get(match.group(1), match.group(0)),
                value,
            )
            if replaced != value:
                resolved_tags[name] = replaced
                changed = True
        if not changed:
            break

    for name in replace_rules:
        if name in rules and rules[name].kind != "meta":
            rules[name].expression = re.sub(
                r"<([A-Za-z0-9_]+)>",
                lambda match: resolved_tags.get(match.group(1), match.group(0)),
                rules[name].expression,
            )

    regex_symbols = {name for name, rule in rules.items() if rule.kind != "meta"}
    meta_rules = {name: rule for name, rule in rules.items() if rule.kind == "meta"}
    valid_metas: set[str] = set()
    unavailable = set(unavailable_symbols)
    external = set(external_symbols) - unavailable

    changed = True
    while changed:
        changed = False
        available = regex_symbols | valid_metas | external
        for name, rule in meta_rules.items():
            if name in valid_metas or name in unavailable:
                continue
            if all(
                dep in available or SYMBOL_REPLACEMENTS.get(dep) in external
                for dep in meta_dependencies(rule.expression)
            ):
                valid_metas.add(name)
                changed = True

    available = regex_symbols | valid_metas | external
    dropped = {
        name: sorted(
            dep
            for dep in meta_dependencies(rule.expression)
            if dep not in available and SYMBOL_REPLACEMENTS.get(dep) not in external
        )
        for name, rule in meta_rules.items()
        if name not in valid_metas
    }
    for name in dropped:
        rules.pop(name, None)
    return rules, omitted, examples, dropped


def lua_string(value: str) -> str:
    level = "="
    while f"]{level}]" in value:
        level += "="
    return f"[{level}[{value}]{level}]"


LUA_RUNTIME = """local expressions = {}
local rule_count = 0
local disabled_rule_count = 0

local function parse_atom(str)
  return str:match('^([^, %s%(%)><+!|&]+)') or ''
end

local function match_data(rule, data, raw, max_matches)
  if not data or not rule.re or rule.disabled then return 0 end
  if rule.multiple then return rule.re:matchn(data, max_matches or -1, raw) end
  return rule.re:match(data, raw) and 1 or 0
end

local function add_matches(rule, total, data, raw)
  if rule.maxhits and total >= rule.maxhits then return rule.maxhits, true end
  local remaining = rule.maxhits and (rule.maxhits - total) or -1
  total = total + match_data(rule, data, raw, remaining)
  if rule.maxhits and total >= rule.maxhits then return rule.maxhits, true end
  return total, total > 0 and not rule.multiple
end

local function match_header(task, rule)
  local header_names = { rule.header }
  if rule.header == 'ToCc' then header_names = { 'To', 'Cc', 'Bcc' } end
  if rule.header == 'MESSAGEID' then header_names = { 'Message-ID', 'X-Message-ID', 'Resent-Message-ID' } end
  if rule.header == 'ALL' then
    local result = add_matches(rule, 0, task:get_raw_headers(), true)
    if rule.negate then return result > 0 and 0 or 1 end
    return result
  end
  local matched = false
  local hits = 0
  local done = false
  for _, header_name in ipairs(header_names) do
    local values = {}
    if rule.kind == 'mimeheader' then
      for _, part in ipairs(task:get_parts() or {}) do
        -- get_header_full may be absent on older rspamd mime-part bindings;
        -- guard so a missing method degrades to no match instead of erroring.
        if part.get_header_full then
          for _, hdr in ipairs(part:get_header_full(header_name, false) or {}) do table.insert(values, hdr) end
        end
      end
    else
      values = task:get_header_full(header_name, rule.header_mode == 'case') or {}
    end
    for _, hdr in ipairs(values) do
      local value = rule.header_mode == 'raw' and hdr.value or (hdr.decoded or hdr.value)
      if rule.header_mode == 'addr' then
        local addresses = rspamd_util.parse_mail_address(value or '') or {}
        for _, address in ipairs(addresses) do
          if address.addr then hits, done = add_matches(rule, hits, address.addr, false) end
          if done then break end
        end
      elseif rule.header_mode == 'name' then
        local addresses = rspamd_util.parse_mail_address(value or '') or {}
        for _, address in ipairs(addresses) do
          if address.name then hits, done = add_matches(rule, hits, address.name, false) end
          if done then break end
        end
      elseif value then
        hits, done = add_matches(rule, hits, value, rule.header_mode == 'raw')
      end
      if done then break end
    end
    if done then break end
  end
  matched = hits > 0
  if rule.negate then matched = not matched end
  return matched and (rule.multiple and hits or 1) or 0
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
  elseif rule.kind == 'header' or rule.kind == 'mimeheader' then
    result = match_header(task, rule)
  elseif rule.kind == 'body' then
    local done = false
    if not rule.nosubject then
      result, done = add_matches(rule, result, task:get_subject(), false)
    end
    for _, part in ipairs(task:get_text_parts() or {}) do
      if done then break end
      result, done = add_matches(rule, result, part:get_content(), false)
    end
  elseif rule.kind == 'rawbody' then
    result = add_matches(rule, 0, task:get_rawbody(), true)
  elseif rule.kind == 'full' then
    result = add_matches(rule, 0, task:get_content(), true)
  elseif rule.kind == 'uri' then
    local done = false
    for _, url in ipairs(task:get_urls() or {}) do
      result, done = add_matches(rule, result, url:get_text(), false)
      if done then break end
    end
  end
  cache[name] = result or 0
  return cache[name]
end

for name, rule in pairs(rules) do
  rule_count = rule_count + 1
  if rule.kind == 'meta' then
    expressions[name] = rspamd_expression.create(rule.expression, parse_atom, rspamd_config:get_mempool())
    if not expressions[name] then
      rule.disabled = true
      disabled_rule_count = disabled_rule_count + 1
      rspamd_logger.errx(rspamd_config, 'cannot compile KAM meta %s: %s', name, rule.expression)
    end
  else
    rule.re = rspamd_regexp.create(rule.expression)
    if rule.re then
      rule.re:set_max_hits(rule.multiple and (rule.maxhits or -1) or 1)
    else
      rule.disabled = true
      disabled_rule_count = disabled_rule_count + 1
      rspamd_logger.errx(rspamd_config, 'cannot compile KAM regexp %s: %s', name, rule.expression)
    end
  end
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
"""


def generate_lua(
    rules: dict[str, Rule],
    source_url: str,
    source_sha256: str,
    external_dependencies: set[str],
) -> bytes:
    lines = [
        "-- Generated by rspamd-kam-rules. Do not edit.",
        f"-- Source: {source_url}",
        f"-- Source-SHA256: {source_sha256}",
        "",
        KAM_LICENSE_HEADER,
        "",
        'local rspamd_expression = require "rspamd_expression"',
        'local rspamd_logger = require "rspamd_logger"',
        'local rspamd_regexp = require "rspamd_regexp"',
        'local rspamd_util = require "rspamd_util"',
        "",
        "local rules = {",
    ]
    for name in sorted(rules):
        rule = rules[name]
        fields = [
            f"kind = {lua_string(rule.kind)}",
            f"expression = {lua_string(rule.expression)}",
            f"score = {rule.score:.12g}",
        ]
        if rule.description:
            fields.append(f"description = {lua_string(rule.description)}")
        if rule.header:
            fields.append(f"header = {lua_string(rule.header)}")
        if rule.header_mode:
            fields.append(f"header_mode = {lua_string(rule.header_mode)}")
        if rule.negate:
            fields.append("negate = true")
        if "multiple" in rule.tflags:
            fields.append("multiple = true")
        if "nosubject" in rule.tflags:
            fields.append("nosubject = true")
        if rule.maxhits is not None:
            fields.append(f"maxhits = {rule.maxhits}")
        lines.append(f'  ["{name}"] = {{ {", ".join(fields)} }},')
    lines.append("}")
    lines.append("")
    lines.append("local replacements = {")
    for source, target in sorted(SYMBOL_REPLACEMENTS.items()):
        lines.append(f'  ["{source}"] = {lua_string(target)},')
    lines.append("}")
    lines.append("")
    lines.append("local external_dependencies = {")
    for dependency in sorted(external_dependencies):
        lines.append(f"  {lua_string(dependency)},")
    lines.append("}")
    lines.append("")
    return ("\n".join(lines) + "\n" + LUA_RUNTIME).encode()


def convert(
    source: bytes,
    source_url: str,
    min_bytes: int,
    min_rules: int,
    external_symbols: set[str] | None = None,
    unavailable_symbols: set[str] | None = None,
    expected_sha256: str | None = None,
) -> tuple[bytes, dict]:
    if len(source) < min_bytes:
        raise ConversionError(f"source is unexpectedly small: {len(source)} bytes < {min_bytes}")
    source_sha256 = hashlib.sha256(source).hexdigest()
    if expected_sha256 is not None:
        expected_sha256 = expected_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ConversionError("expected SHA-256 must be exactly 64 hexadecimal characters")
        if source_sha256 != expected_sha256:
            raise ConversionError(
                f"source SHA-256 mismatch: {source_sha256} != {expected_sha256}"
            )
    external = set(external_symbols or ())
    rules, omitted, examples, dropped = parse_rules(
        source,
        external,
        unavailable_symbols or set(),
    )
    if len(rules) < min_rules:
        raise ConversionError(f"too few converted rules: {len(rules)} < {min_rules}")
    dependencies = external_meta_dependencies(rules, external)
    lua = generate_lua(rules, source_url, source_sha256, dependencies)
    report = {
        "source_url": source_url,
        "source_bytes": len(source),
        "source_sha256": source_sha256,
        "output_bytes": len(lua),
        "output_sha256": hashlib.sha256(lua).hexdigest(),
        "converted_rule_count": len(rules),
        "converted_rule_types": dict(sorted(Counter(rule.kind for rule in rules.values()).items())),
        "omitted_directives": dict(sorted(omitted.items())),
        "omitted_examples": examples,
        "dropped_metas": dropped,
        "dropped_meta_count": len(dropped),
        "external_dependencies": sorted(dependencies),
        "external_dependency_count": len(dependencies),
    }
    return lua, report


def atomic_write(path: Path, content: bytes, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def main() -> int:
    root = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--output", type=Path, default=root / "dist" / "kam.lua")
    parser.add_argument("--report", type=Path, default=root / "dist" / "report.json")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--min-bytes", type=int, default=100_000)
    parser.add_argument("--min-rules", type=int, default=1_000)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--external-symbols", type=Path, default=root / "config" / "external-symbols.txt")
    parser.add_argument("--unavailable-symbols", type=Path, default=root / "config" / "unavailable-symbols.txt")
    args = parser.parse_args()

    source = args.input.read_bytes() if args.input else download(args.url, args.timeout)
    lua, report = convert(
        source,
        args.url,
        args.min_bytes,
        args.min_rules,
        read_symbol_file(args.external_symbols),
        read_symbol_file(args.unavailable_symbols),
        args.expected_sha256,
    )
    atomic_write(args.output, lua)
    atomic_write(args.report, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    print(
        f"wrote {args.output} ({report['converted_rule_count']} rules, "
        f"sha256 {report['output_sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
