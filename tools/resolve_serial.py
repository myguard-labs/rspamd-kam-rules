#!/usr/bin/env python3
"""Resolve the KAM sa-update channel serial from a DNS TXT record.

The self-hosted CI runner has no dig/host/nslookup (dnsutils absent, isolated
filesystem), so the workflow resolves the serial in pure Python via dnspython
instead of shelling out to a system DNS client.

Prints the first run of digits found in the TXT payload to stdout (e.g.
"1782987265"), or an empty line on any resolver error — the workflow treats an
empty serial as "no change" and never aborts on it. Errors go to stderr so the
CI log shows why a lookup came back empty.

    python3 tools/resolve_serial.py 0.0.4.kam.sa-channels.mcgrail.com
"""
import re
import sys


def main() -> int:
    name = sys.argv[1] if len(sys.argv) > 1 else ""
    try:
        import dns.resolver

        answers = dns.resolver.resolve(name, "TXT", lifetime=15)
        txt = "".join(
            chunk.decode("ascii", "ignore")
            for record in answers
            for chunk in record.strings
        )
        match = re.search(r"[0-9]+", txt)
        print(match.group(0) if match else "")
    except Exception as exc:  # noqa: BLE001 - fail soft, empty serial = no change
        print(f"TXT resolve failed for {name!r}: {exc}", file=sys.stderr)
        print("")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
