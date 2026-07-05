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
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_URL = "https://mcgrail.com/downloads/KAM.cf"
REGEX_TYPES = {"body", "full", "header", "mimeheader", "rawbody", "uri"}

# Project identity, reused in both artifact headers (kam.lua + kam_rules.map).
PROJECT_NAME = "rspamd-kam-rules"
PROJECT_COPYRIGHT = "Copyright (c) 2026 eilandert / myguard.nl"
PROJECT_LICENSE = "MIT (converter) — generated rules are Apache-2.0, see below"
PROJECT_HOMEPAGE = "https://github.com/myguard-labs/rspamd-kam-rules"
# Profile overview of our other Rspamd modules (olefy, yarad, gyzor, mailstrix, …).
PROJECT_OVERVIEW = "https://github.com/myguard-labs"
# Terse deploy recipe carried inside both artifacts so a downloaded file is
# self-documenting. Kept in sync with README "Install".
PROJECT_HOWTO = [
    "Quick start:",
    "  1. wget kam.lua       -> /etc/rspamd/plugins.d/kam.lua",
    "  2. add to rspamd.conf.local:  kam { enabled = true; }   (see examples/kam.conf)",
    "  3. (optional) cap scoring: examples/groups.conf -> /etc/rspamd/local.d/groups.conf",
    "  4. rspamadm configtest && systemctl reload rspamd",
    "Self-update: rspamd polls map_url (github by default) every map_watch_interval",
    "and writes a fresh map to cache_path (/var/lib/rspamd, rspamd-writable). A",
    "'systemctl reload rspamd' timer then re-registers it (native regexps register",
    "at config load only). Set map_url=\"\" to disable polling.",
]

# KAM.cf upstream credits + Apache-2.0 notice. The rules are a derivative work of
# KAM.cf, so this attribution must travel WITH the rules — it lives in the map
# header (the data file users download and update), where `_kam_credits` /
# `_kam_license` carry it verbatim. kam.lua only points at it (KAM_LICENSE_POINTER)
# so the runtime stays a thin shell with no baked rule provenance.
KAM_CREDITS = [
    "Generated from KAM.cf — the KAM ruleset for Apache SpamAssassin, a",
    "derivative work of it.",
    "Authors: Kevin A. McGrail, with key contributions from Joe Quinn,",
    "         Karsten Bräckelmann, Bill Cole & Giovanni Bechis.",
    "Thanks to Wolfgang Breyha for his help fixing a few rules.",
    "Maintained by The McGrail Foundation, a 501(c)(3) charity.",
    "Home: https://mcgrail.com/template/projects#KAM1",
    "Copyright (c) 2022 Kevin A. McGrail and The McGrail Foundation",
]
KAM_LICENSE = [
    "Licensed under the Apache License, Version 2.0 (the \"License\"); you may",
    "not use these rules except in compliance with the License. Obtain a copy",
    "at http://www.apache.org/licenses/LICENSE-2.0 . Distributed on an \"AS IS\"",
    "BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, express or implied.",
    "The converter (rspamd-kam-rules) itself is MIT-licensed.",
]
SA_LIFT_PROVENANCE = [
    "Some rule definitions are lifted from Apache SpamAssassin trunk",
    "(rules/ + rulesrc/), Apache-2.0, to satisfy KAM.cf meta dependencies.",
    "See the SA-lift section of config/local-rules.cf for the per-rule source.",
]

# kam.lua is a thin runtime; the full KAM.cf credits + Apache notice live in the
# map header (_kam_credits / _kam_license) so they travel with the rules. This
# short pointer replaces the old in-lua license block.
KAM_LICENSE_POINTER = """\
-- ---------------------------------------------------------------------------
-- This plugin is generated from KAM.cf (Apache-2.0) and is a derivative work
-- of it. The full KAM.cf credits and Apache-2.0 notice travel WITH the rules,
-- in the kam_rules.map header (`_kam_credits` / `_kam_license` keys).
-- KAM.cf home: https://mcgrail.com/template/projects#KAM1
-- The converter itself (rspamd-kam-rules) is MIT-licensed.
-- ---------------------------------------------------------------------------"""
# Rule/symbol names are interpolated into the generated Lua as table keys, so
# they must be restricted to the SpamAssassin symbol charset. Anything else is a
# malformed (or hostile) source line and is dropped to prevent Lua injection.
VALID_NAME = re.compile(r"[A-Za-z0-9_]+\Z")
KNOWN_PLUGINS = {
    "Mail::SpamAssassin::Plugin::BodyEval",
    "Mail::SpamAssassin::Plugin::DKIM",
    "Mail::SpamAssassin::Plugin::Dmarc",
    "Mail::SpamAssassin::Plugin::FreeMail",
    "Mail::SpamAssassin::Plugin::FromNameSpoof",
    "Mail::SpamAssassin::Plugin::HeaderEval",
    "Mail::SpamAssassin::Plugin::HTMLEval",
    "Mail::SpamAssassin::Plugin::MIMEEval",
    "Mail::SpamAssassin::Plugin::MIMEHeader",
    "Mail::SpamAssassin::Plugin::OLEVBMacro",
    "Mail::SpamAssassin::Plugin::RelayEval",
    "Mail::SpamAssassin::Plugin::ReplaceTags",
    "Mail::SpamAssassin::Plugin::SPF",
    "Mail::SpamAssassin::Plugin::URIDNSBL",
    "Mail::SpamAssassin::Plugin::WLBLEval",
}
# `if (version >= X)` gates are evaluated against this SpamAssassin version.
# KAM.cf targets SA4 features behind these gates; rspamd covers the same
# feature surface, so the modern branch is the right one to convert.
SA_VERSION = 4.000000
_VERSION_GATE = re.compile(r"if\s+\(?\s*version\s*(>=|>|<=|<|==|!=)\s*([\d.]+)\s*\)?\s*\Z")
SYMBOL_REPLACEMENTS = {
    # 2026-07-04 pristine remap table (targets verified present in the
    # rspamd/rspamd:4.1.0 image; see memory kam-channel-file-analysis.md).
    # APPROX-flagged mappings conflate a nuance (helo/mfrom, name/addr,
    # alignment) but only widen/narrow a signal that feeds the same metas.
    "ALL_TRUSTED": "RCVD_COUNT_ZERO",  # APPROX: only used in negated guards
    "BODY_URI_ONLY": "R_EMPTY_IMAGE",
    "DKIM_INVALID": "R_DKIM_REJECT",
    "DKIM_VALID": "R_DKIM_ALLOW",
    "DKIM_VALID_AU": "R_DKIM_ALLOW",  # APPROX: alignment lost
    "DKIM_VALID_EF": "R_DKIM_ALLOW",  # APPROX: alignment lost
    "DMARC_PASS": "DMARC_POLICY_ALLOW",
    "EMPTY_MESSAGE": "COMPLETELY_EMPTY",
    "FREEMAIL_ENVFROM_END_DIGIT": "FREEMAIL_ENVFROM",  # APPROX
    "FREEMAIL_FORGED_REPLYTO": "FREEMAIL_REPLYTO_NEQ_FROM",
    "FREEMAIL_REPLYTO_END_DIGIT": "FREEMAIL_REPLYTO",  # APPROX
    "GOOG_REDIR_NOTRDNS": "HAS_GOOGLE_REDIR",  # APPROX: RDNS side lost
    "HEADER_FROM_DIFFERENT_DOMAINS": "FORGED_SENDER",  # APPROX
    "HTML_FONT_LOW_CONTRAST": "R_WHITE_ON_WHITE",  # APPROX
    "MISSING_HEADERS": "MISSING_TO",  # SA def = missing To header
    "NO_RELAYS": "RCVD_COUNT_ZERO",
    "RCVD_IN_PBL": "RBL_SPAMHAUS_PBL",
    "RCVD_IN_XBL": "RBL_SPAMHAUS_XBL",
    "SPF_HELO_NONE": "R_SPF_NA",  # APPROX: helo/mfrom conflated
    "__DKIM_EXISTS": "DKIM_SIGNED",
    "__DOS_DIRECT_TO_MX": "DIRECT_TO_MX",
    "__DOS_HAS_LIST_UNSUB": "HAS_LIST_UNSUB",
    "__DOS_HAS_MAILING_LIST": "MAILLIST",
    "__GB_FROM_ADDR_FREEMAIL": "FREEMAIL_FROM",
    "__GB_FROM_NAME_FREEMAIL": "FREEMAIL_FROM",  # APPROX: name vs addr
    "__GB_TO_ADDR_FREEMAIL": "FREEMAIL_TO",
    "__GB_TO_NAME_FREEMAIL": "FREEMAIL_TO",  # APPROX: name vs addr
    "__HAS_PHP_ORIG_SCRIPT": "HAS_X_PHP_SCRIPT",
    "__KAM_SPF_NONE": "R_SPF_NA",
    "__PLUGIN_FROMNAME_SPOOF": "SPOOF_DISPLAY_NAME",
    "__TO_UNDISCLOSED": "R_UNDISC_RCPT",
    "KAM_DMARC_NONE": "DMARC_NA",
    "KAM_DMARC_QUARANTINE": "DMARC_POLICY_QUARANTINE",
    "KAM_OLEMACRO_ENCRYPTED": "OLETOOLS_ENCRYPTED",
    "KAM_OLEMACRO_RENAME": "MIME_BAD_EXTENSION",
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
# SA eval: atoms the Lua runtime implements natively (builtin_evals table in
# LUA_RUNTIME). They count as available for meta resolution but are NOT
# external dependencies — no symbol is registered for them; eval_atom computes
# them on demand. Keep this set in sync with builtin_evals in the Lua.
PLUGIN_EVAL_SYMBOLS = {
    "HTML_MESSAGE",  # eval:html_test — any HTML text part
    "__KAM_BODY_LENGTH_LT_128",  # eval:check_body_length('128')
    "__KAM_BODY_LENGTH_LT_512",
    "__KAM_BODY_LENGTH_LT_1024",
    "__TAG_EXISTS_HEAD",  # eval:html_tag_exists('head')
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
    if_unset: str | None = None
    description: str = ""
    score: float = 0.0
    tflags: set[str] = field(default_factory=set)
    maxhits: int | None = None


def download(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "rspamd-kam-rules/2.0 (+https://github.com/myguard-labs/rspamd-kam-rules)"},
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
            version = _VERSION_GATE.match(stripped)
            if plugin:
                # `if plugin(X)` is true when X is loaded; `if !plugin(X)` is the
                # inverse. Capability (`if can(...)`) guards are not modelled, so
                # their blocks stay inactive (conservative drop).
                known = plugin.group(2) in KNOWN_PLUGINS
                condition = (not known) if plugin.group(1) else known
            elif version:
                op, wanted = version.group(1), float(version.group(2))
                condition = {
                    ">=": SA_VERSION >= wanted,
                    ">": SA_VERSION > wanted,
                    "<=": SA_VERSION <= wanted,
                    "<": SA_VERSION < wanted,
                    "==": SA_VERSION == wanted,
                    "!=": SA_VERSION != wanted,
                }[op]
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
    # Perl regex delimiters: /re/ or m<delim>re<delim>. Paired brackets
    # ({}, (), [], <>) open/close with different chars and may nest (e.g.
    # m{a{2}b}), so track depth for those; same-char delimiters do not nest.
    paired = {"{": "}", "(": ")", "[": "]", "<": ">"}
    if value.startswith("/"):
        opener, start = "/", 1
    elif value.startswith("m") and len(value) > 2 and not value[1].isalnum():
        opener, start = value[1], 2
    else:
        return None
    closer = paired.get(opener, opener)

    escaped = False
    depth = 0
    for index in range(start, len(value)):
        char = value[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif closer != opener and char == opener:
            depth += 1
        elif char == closer:
            if depth > 0:
                depth -= 1
                continue
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
            if directive == "header":
                exists = re.match(r"exists:(\S+)\Z", value)
                if exists:
                    # SA `header NAME exists:Hdr` is a pure presence test. `^`
                    # matches every value including the empty string, so the
                    # rule fires iff the header is present.
                    rules[name] = Rule(
                        name=name, kind=directive, expression="^", header=exists.group(1)
                    )
                    continue
            if directive in {"header", "mimeheader"}:
                match = re.match(r"(\S+)\s*([=!])~\s*(.+)", value)
                if not match:
                    omit(number, f"unsupported_{directive}", line)
                    continue
                header_spec, operator, value = match.groups()
                negate = operator == "!"
                header_parts = header_spec.split(":")
                header = header_parts[0]
                header_mode = header_parts[1] if len(header_parts) > 1 else None
            # SA `[if-unset: X]` trailing modifier: fallback value used when the
            # header is absent. Strip it off the value and carry it on the rule.
            if_unset = None
            if directive in {"header", "mimeheader"}:
                unset_match = re.search(r"\s*\[if-unset:\s*(.*?)\s*\]\s*\Z", value)
                if unset_match:
                    if_unset = unset_match.group(1)
                    value = value[: unset_match.start()]
            expression = extract_regex(value)
            if not expression:
                omit(number, f"unsupported_{directive}", line)
                continue
            # SA's `$?` (optional end-of-line) is not valid PCRE/rspamd syntax;
            # escape it to a literal `\$?` so the regex compiles. Flags suffix
            # (only imsx) never contains `$?`, so escaping the whole string is safe.
            expression = re.sub(r"(?<!\\)\$\?", r"\\$?", expression)
            rules[name] = Rule(
                name=name,
                kind=directive,
                expression=expression,
                header=header,
                header_mode=header_mode,
                negate=negate,
                if_unset=if_unset,
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

    # Iteratively expand <tag> references. Bounded by tag count + 1 so a cyclic
    # definition (<A>-><B>-><A>) terminates with the unresolved <tag> left as a
    # literal — that produces an invalid regex, caught at rspamd_regexp.create
    # (returns nil -> rule disabled), so a malformed cycle degrades safe.
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


LUA_RUNTIME = """-- Reject a self-update that parses to fewer than this many valid rules — a
-- truncated download or error page must not clobber the good cache. Well below
-- the real count (thousands) but far above anything a broken response yields.
-- Overridable via kam { min_update_rules = N } (tests point it low).
local KAM_MIN_RULES = tonumber(opts.min_update_rules) or 500

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
-- header with no addr/name transform. ALL / ToCc / MESSAGEID multi-header,
-- addr/name modes, the EnvelopeFrom pseudo-header (SMTP envelope sender, not a
-- MIME header) and [if-unset:] rules (must fire on an ABSENT header, which a
-- header-DB scan can never do) drop to the slow per-value Lua path.
local function header_is_native(rule)
  if rule.header_mode == 'addr' or rule.header_mode == 'name' then return false end
  if rule.header == 'ALL' or rule.header == 'ToCc' or rule.header == 'MESSAGEID' then return false end
  if rule.header == 'EnvelopeFrom' then return false end
  if rule.if_unset ~= nil then return false end
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

-- Schema gate per rule object: the map is read from disk (and self-updated over
-- HTTP), so never hand a malformed entry to compile_rule — a nil expression
-- reaching rspamd_regexp.create would abort the whole config load.
local VALID_KINDS = {
  meta = true, body = true, rawbody = true, full = true,
  uri = true, header = true, mimeheader = true,
}
local function valid_rule_object(obj)
  if not VALID_KINDS[obj.kind] then return false end
  if type(obj.expression) ~= 'string' or obj.expression == '' then return false end
  if obj.score ~= nil and type(obj.score) ~= 'number' then return false end
  if (obj.kind == 'header' or obj.kind == 'mimeheader')
      and type(obj.header) ~= 'string' then return false end
  return true
end

local function parse_map(data)
  local ucl = require 'ucl'
  local parsed_rules, repl, deps = {}, {}, {}
  local header_seen = false
  for line in data:gmatch('[^\\r\\n]+') do
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
          if valid_rule_object(obj) then
            local name = obj.name
            obj.name = nil
            obj.score = obj.score or 0
            parsed_rules[name] = obj
          else
            rspamd_logger.errx(rspamd_config,
              'KAM map: invalid rule object %s; skipped', obj.name)
          end
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

  -- EnvelopeFrom is SA's pseudo-header for the SMTP envelope sender (MAIL
  -- FROM), not a MIME header: read it from the task envelope, falling back to
  -- Return-Path. Same source rspamd's own spamassassin.lua uses.
  if rule.header == 'EnvelopeFrom' then
    local candidates = {}
    local from = task:get_from('smtp')
    if from and from[1] and from[1].addr then table.insert(candidates, from[1].addr) end
    if #candidates == 0 then
      local return_path = task:get_header('Return-Path')
      if return_path then
        for _, address in ipairs(rspamd_util.parse_mail_address(return_path) or {}) do
          if address.addr then table.insert(candidates, address.addr) end
        end
      end
    end
    local hits = 0
    if #candidates == 0 and rule.if_unset then
      hits = rule.re:match(rule.if_unset) and 1 or 0
    end
    for _, cand in ipairs(candidates) do
      if rule.re:match(cand) then
        hits = hits + 1
        if not rule.multiple then break end
        if rule.maxhits and hits >= rule.maxhits then break end
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
  local tested_value = false
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
        tested_value = true
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

  -- SA [if-unset: X]: when the header is entirely absent, evaluate the regex
  -- against the fallback value X instead — the idiom `=~ /^UNSET$/
  -- [if-unset: UNSET]` fires exactly when the header is missing.
  if not tested_value and rule.if_unset then
    hits = rule.re:match(rule.if_unset, rule.header_mode == 'raw') and 1 or 0
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

-- Builtin evaluators for the handful of SA eval: atoms that map cleanly onto
-- the rspamd Lua API (SA: check_body_length / html_test / html_tag_exists).
-- Mirrors PLUGIN_EVAL_SYMBOLS in the generator: available to metas, but no
-- registered symbol — eval_atom computes them on demand (task-cached).
-- Approximation of SA check_body_length: sums ALL text parts, so a
-- multipart/alternative message counts both alternatives and looks longer
-- than SA's single rendered body — the LT_* atoms then under-fire, which is
-- the conservative direction (misses a short-body signal, never invents one).
local function sa_body_length(task)
  local total = 0
  for _, part in ipairs(task:get_text_parts() or {}) do
    total = total + (part:get_length() or 0)
  end
  return total
end
local builtin_evals = {
  HTML_MESSAGE = function(task)
    for _, part in ipairs(task:get_text_parts() or {}) do
      if part:is_html() then return 1 end
    end
    return 0
  end,
  __KAM_BODY_LENGTH_LT_128 = function(task) return sa_body_length(task) < 128 and 1 or 0 end,
  __KAM_BODY_LENGTH_LT_512 = function(task) return sa_body_length(task) < 512 and 1 or 0 end,
  __KAM_BODY_LENGTH_LT_1024 = function(task) return sa_body_length(task) < 1024 and 1 or 0 end,
  __TAG_EXISTS_HEAD = function(task)
    for _, part in ipairs(task:get_text_parts() or {}) do
      local html = part:is_html() and part:get_html()
      if html and html:has_tag('head') then return 1 end
    end
    return 0
  end,
}

local function eval_atom(name, task)
  local cache = task:cache_get('kam_lua_results')
  if not cache then cache = {}; task:cache_set('kam_lua_results', cache) end
  if cache[name] ~= nil then return cache[name] end
  cache[name] = 0
  local rule = rules[name]
  local result = 0
  if not rule then
    local builtin = builtin_evals[name]
    if builtin then
      result = builtin(task)
    else
      result = task:has_symbol(replacements[name] or name) and 1 or 0
    end
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
      -- Validate the fetched map before it can poison the next reload: a
      -- truncated download, an HTML error page, or a corrupt map must NOT
      -- overwrite the good cache. Require the `_kam` header sentinel and a sane
      -- minimum rule count (parse_map skips malformed/invalid entries, so this
      -- counts only rules that would actually load).
      local staged = parse_map(content)
      local staged_count = 0
      for _ in pairs(staged) do staged_count = staged_count + 1 end
      if staged_count < KAM_MIN_RULES then
        rspamd_logger.errx(rspamd_config,
          'KAM: rejected self-update — only %s valid rules (< %s); keeping current cache',
          tostring(staged_count), tostring(KAM_MIN_RULES))
        return
      end
      -- Skip the write if the cache already holds these exact bytes — avoids
      -- needless churn and log noise when the poll returns an unchanged map.
      local current = read_file(kam_cache_path)
      if current == content then return end
      -- Per-worker temp name so two workers writing at once never share (and
      -- tear) one .tmp file; os.rename onto the final path is atomic, so the
      -- last writer wins cleanly. The lock is a best-effort extra guard — its
      -- absence (e.g. lockfile not yet creatable) must not block the write,
      -- since the per-worker tmp + atomic rename already make the write safe.
      -- Unique per-call suffix: a fresh table's address string is distinct for
      -- each concurrent invocation, no rspamd/os API needed.
      local tmp = kam_cache_path .. '.tmp.' .. tostring({}):gsub('%W', '')
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
"""


# Default map location. The bundled file is read synchronously at config load so
# rules register and compile into the combined Hyperscan DB at init. Overridable
# via the `kam {}` config block (`map_path`). There is no live HTTP watch:
# rspamd registers native regexps only at config load, so an updated map is
# applied by `systemctl reload rspamd` (full reconfigure), not a map poll.
#
# Self-update (C1): rspamd itself polls DEFAULT_MAP_URL on `map_watch_interval`
# and atomically writes a fresh copy to DEFAULT_CACHE_PATH — under /var/lib/rspamd
# (DBDIR), the only map dir the dropped-priv rspamd user can write (/etc/rspamd is
# root-owned → EACCES). At config load the runtime PREFERS the cache copy and
# falls back to the shipped seed at DEFAULT_MAP_PATH. The poll only downloads; a
# separate `systemctl reload rspamd` (timer) re-registers the native regexps,
# which rspamd can only do at config load.
DEFAULT_MAP_PATH = "/etc/rspamd/kam_rules.map"
DEFAULT_CACHE_PATH = "/var/lib/rspamd/kam_rules.map"
DEFAULT_MAP_URL = (
    "https://raw.githubusercontent.com/myguard-labs/rspamd-kam-rules/main/dist/kam_rules.map"
)


def _map_rule_object(name: str, rule: Rule) -> dict[str, object]:
    """One rule as a plain dict for the jsonl map. Mirrors the Lua-table fields
    the runtime reads; omitted keys default to nil/false in Lua."""
    obj: dict[str, object] = {
        "name": name,
        "kind": rule.kind,
        "expression": rule.expression,
        "score": rule.score,
    }
    if rule.description:
        obj["description"] = rule.description
    if rule.header:
        obj["header"] = rule.header
    if rule.header_mode:
        obj["header_mode"] = rule.header_mode
    if rule.negate:
        obj["negate"] = True
    if rule.if_unset is not None:
        obj["if_unset"] = rule.if_unset
    if "multiple" in rule.tflags:
        obj["multiple"] = True
    # NOTE: SA `nosubject` (exclude Subject from body scan) is a no-op under
    # rspamd — its `sabody` re-cache type already scans body parts only and never
    # prepends the Subject (unlike SA's `body`). So we intentionally do NOT emit
    # it; the runtime would have nothing to do with it.
    if rule.maxhits is not None:
        obj["maxhits"] = rule.maxhits
    return obj


def generate_map(
    rules: dict[str, Rule],
    external_dependencies: set[str],
    source_url: str = DEFAULT_URL,
    source_sha256: str = "",
    generated_date: str | None = None,
) -> bytes:
    """The data half: jsonl. Line 1 is the header (metadata + replacements +
    external_dependencies); each later line is one rule object. Names are
    pre-validated by VALID_NAME at parse time, and the Lua loader re-validates
    them, so a tampered map can introduce no symbol outside the SA charset.
    The loader reads only `replacements`/`external_dependencies` from the header
    and ignores every `_`-prefixed metadata key, so they're safe to carry."""
    if generated_date is None:
        generated_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    header = {
        "_kam": 1,
        "_project": PROJECT_NAME,
        "_copyright": PROJECT_COPYRIGHT,
        "_license": PROJECT_LICENSE,
        "_homepage": PROJECT_HOMEPAGE,
        "_overview": PROJECT_OVERVIEW,
        "_howto": PROJECT_HOWTO,
        "_source_url": source_url,
        "_source_sha256": source_sha256,
        "_generated": generated_date,
        "_kam_credits": KAM_CREDITS,
        "_kam_license": KAM_LICENSE,
        "_sa_lift_provenance": SA_LIFT_PROVENANCE,
        "_builtin_evals": sorted(PLUGIN_EVAL_SYMBOLS),
        "replacements": dict(sorted(SYMBOL_REPLACEMENTS.items())),
        "external_dependencies": sorted(external_dependencies),
    }
    out = [json.dumps(header, sort_keys=True, ensure_ascii=False)]
    for name in sorted(rules):
        out.append(
            json.dumps(_map_rule_object(name, rules[name]), sort_keys=True, ensure_ascii=False)
        )
    return ("\n".join(out) + "\n").encode()


def generate_lua(map_path: str = DEFAULT_MAP_PATH) -> bytes:
    # The lua runtime is static and version-less by design — the ruleset version
    # (date + source SHA) lives in the map header, not here — so this takes no
    # source metadata and emits no generation date.
    howto = "\n".join(f"-- {line}".rstrip() for line in PROJECT_HOWTO)
    lines = [
        "-- ===========================================================================",
        f"-- {PROJECT_NAME} — KAM.cf compiled to a native Rspamd Lua plugin.",
        f"-- {PROJECT_COPYRIGHT}",
        f"-- License: {PROJECT_LICENSE}",
        f"-- Home:    {PROJECT_HOMEPAGE}",
        f"-- More Rspamd modules (olefy, yarad, gyzor, mailstrix, …): {PROJECT_OVERVIEW}",
        "--",
        howto,
        "-- ===========================================================================",
        "",
        KAM_LICENSE_POINTER,
        "",
        'local rspamd_expression = require "rspamd_expression"',
        'local rspamd_logger = require "rspamd_logger"',
        'local rspamd_regexp = require "rspamd_regexp"',
        'local rspamd_util = require "rspamd_util"',
        "",
        "-- Map locations + self-update URL, overridable via the kam {} config block.",
        "--   map_path   = shipped seed (read-only /etc/rspamd) — fallback only.",
        "--   cache_path = rspamd-writable copy (/var/lib/rspamd) the poll writes",
        "--                and the runtime PREFERS at load.",
        "--   map_url    = remote map polled on map_watch_interval; \"\" disables.",
        "local opts = rspamd_config:get_all_opt('kam') or {}",
        f"local kam_map_path = opts.map_path or {lua_string(map_path)}",
        f"local kam_cache_path = opts.cache_path or {lua_string(DEFAULT_CACHE_PATH)}",
        f"local kam_map_url = opts.map_url or {lua_string(DEFAULT_MAP_URL)}",
        "",
    ]
    return ("\n".join(lines) + "\n" + LUA_RUNTIME).encode()


def convert(
    source: bytes,
    source_url: str,
    min_bytes: int,
    min_rules: int,
    external_symbols: set[str] | None = None,
    unavailable_symbols: set[str] | None = None,
    expected_sha256: str | None = None,
    local_rules: bytes | None = None,
) -> tuple[bytes, bytes, dict]:
    if len(source) < min_bytes:
        raise ConversionError(f"source is unexpectedly small: {len(source)} bytes < {min_bytes}")
    # SHA gate runs on the pristine upstream source only, so update-if-changed.sh
    # keeps tracking the upstream KAM.cf SHA regardless of any local supplement.
    source_sha256 = hashlib.sha256(source).hexdigest()
    if expected_sha256 is not None:
        expected_sha256 = expected_sha256.lower()
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise ConversionError("expected SHA-256 must be exactly 64 hexadecimal characters")
        if source_sha256 != expected_sha256:
            raise ConversionError(
                f"source SHA-256 mismatch: {source_sha256} != {expected_sha256}"
            )
    # Builtin Lua evals count as available so metas over them survive, but they
    # are excluded from external_dependencies: no symbol exists to register a
    # dependency on — eval_atom computes them inline.
    external = set(external_symbols or ()) | PLUGIN_EVAL_SYMBOLS
    combined = source + b"\n" + local_rules if local_rules else source
    rules, omitted, examples, dropped = parse_rules(
        combined,
        external,
        unavailable_symbols or set(),
    )
    if len(rules) < min_rules:
        raise ConversionError(f"too few converted rules: {len(rules)} < {min_rules}")
    dependencies = external_meta_dependencies(rules, external) - PLUGIN_EVAL_SYMBOLS
    # Stamp map + lua with ONE shared date so the two artifacts never disagree and
    # a single regen is internally consistent. (CI is SHA-gated and only regens
    # when KAM.cf actually changes, so this dates the ruleset version.)
    generated_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    lua = generate_lua()
    mapdata = generate_map(rules, dependencies, source_url, source_sha256, generated_date)
    # F5 canary: a regex rule still carrying a `<tag>` token. Most are dead — an
    # unexpanded replace_tag (e.g. <S>, <NUM1>) compiles fine but matches the
    # literal string `<S>`, which never appears, so the rule silently never fires;
    # a parsing/replace_rules regression shows up here in CI, not only at runtime.
    # NOTE: this also catches rules whose regex *legitimately* contains literal
    # HTML tags (<small>, <tr>, <title>) — those compile AND fire correctly, so a
    # nonzero count is expected and not by itself a failure; inspect the names.
    unexpanded_tag_rules = sorted(
        name for name, rule in rules.items()
        if rule.kind != "meta" and re.search(r"<[A-Za-z0-9_]+>", rule.expression)
    )
    report = {
        "source_url": source_url,
        "source_bytes": len(source),
        "source_sha256": source_sha256,
        "local_rules_sha256": hashlib.sha256(local_rules).hexdigest() if local_rules else None,
        "output_bytes": len(lua),
        "output_sha256": hashlib.sha256(lua).hexdigest(),
        "map_bytes": len(mapdata),
        "map_sha256": hashlib.sha256(mapdata).hexdigest(),
        "converted_rule_count": len(rules),
        "converted_rule_types": dict(sorted(Counter(rule.kind for rule in rules.values()).items())),
        "omitted_directives": dict(sorted(omitted.items())),
        "omitted_examples": examples,
        "dropped_metas": dropped,
        "dropped_meta_count": len(dropped),
        "external_dependencies": sorted(dependencies),
        "external_dependency_count": len(dependencies),
        "unexpanded_tag_rules": unexpanded_tag_rules,
        "unexpanded_tag_rule_count": len(unexpanded_tag_rules),
        "generated_date": generated_date,
    }
    return lua, mapdata, report


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
    # kam.lua is a static thin runtime: its rule data lives in the map, so it
    # only changes when the runtime *code* changes, not when KAM.cf does. Daily
    # CI therefore regenerates the map + report only; pass --output (or
    # --emit-lua) to also re-emit the committed dist/kam.lua after a code change.
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument(
        "--emit-lua",
        action="store_true",
        help="also write dist/kam.lua (default: map + report only)",
    )
    parser.add_argument("--map", type=Path, default=root / "dist" / "kam_rules.map")
    parser.add_argument("--report", type=Path, default=root / "dist" / "report.json")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--min-bytes", type=int, default=100_000)
    parser.add_argument("--min-rules", type=int, default=1_000)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--external-symbols", type=Path, default=root / "config" / "external-symbols.txt")
    parser.add_argument("--unavailable-symbols", type=Path, default=root / "config" / "unavailable-symbols.txt")
    parser.add_argument(
        "--local-rules",
        type=Path,
        action="append",
        help="supplement .cf merged after the upstream source; repeatable, "
        "concatenated in order (default: config/{local-rules,KAM_redirectors,nonKAMrules}.cf)",
    )
    args = parser.parse_args()
    if args.local_rules is None:
        args.local_rules = [
            root / "config" / "local-rules.cf",
            root / "config" / "KAM_redirectors.cf",
            root / "config" / "nonKAMrules.cf",
        ]

    source = args.input.read_bytes() if args.input else download(args.url, args.timeout)
    # A missing supplement must fail loudly: silently skipping one would shrink
    # the ruleset with no signal beyond a shifted local_rules_sha256.
    missing = [str(path) for path in args.local_rules if not path.exists()]
    if missing:
        parser.error(f"local-rules file(s) not found: {', '.join(missing)}")
    local_chunks = [path.read_bytes() for path in args.local_rules]
    local_rules = b"\n".join(local_chunks) if local_chunks else None
    lua, mapdata, report = convert(
        source,
        args.url,
        args.min_bytes,
        args.min_rules,
        read_symbol_file(args.external_symbols),
        read_symbol_file(args.unavailable_symbols),
        args.expected_sha256,
        local_rules,
    )
    lua_out = args.output or (root / "dist" / "kam.lua" if args.emit_lua else None)
    if lua_out is not None:
        atomic_write(lua_out, lua)
    atomic_write(args.map, mapdata)
    atomic_write(args.report, (json.dumps(report, indent=2, sort_keys=True) + "\n").encode())
    wrote = f"{lua_out} + " if lua_out is not None else ""
    print(
        f"wrote {wrote}{args.map} ({report['converted_rule_count']} rules, "
        f"lua sha256 {report['output_sha256']}, map sha256 {report['map_sha256']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
