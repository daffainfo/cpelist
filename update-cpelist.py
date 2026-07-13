#!/usr/bin/env python3
"""Build a normalised list of CPE 2.3 identifiers from the latest NVD data.

Downloads the official NVD CPE dictionary (and, as a fallback/supplement, the
community fkie-cad mirror of the NVD CVE feeds), extracts every CPE 2.3
identifier, and normalises each one down to the product level -- keeping only
``part:vendor:product`` and wildcarding every remaining component.

Example output entries::

    "cpe:2.3:a:sgi:propack:*:*:*:*:*:*:*:*"
    "cpe:2.3:a:squirrelmail:squirrelmail:*:*:*:*:*:*:*:*"

Any version / edition / target_sw etc. is discarded, so e.g.::

    cpe:2.3:a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7:*:*:*:*:*:wordpress:*:*

collapses to::

    cpe:2.3:a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7:*:*:*:*:*:*:*:*

The de-duplicated, sorted result is written to ``data/cpes.json`` as a JSON
array. Only the Python standard library is required.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

# --- configuration ----------------------------------------------------------

# Primary: the official NVD CPE dictionary in the JSON 2.0 feed format -- the
#   authoritative, complete list of CPE names (replaces the legacy XML feed that
#   NVD retired in 2023).
# Secondary: the community-maintained fkie-cad mirror of the NVD CVE feeds. It
#   contributes CPEs that are referenced by CVEs, and doubles as a fallback if
#   NVD itself is unreachable.
# Any source that fails to download is skipped automatically.
SOURCES = (
    "https://nvd.nist.gov/feeds/json/cpe/2.0/nvdcpe-2.0.tar.gz",
    "https://github.com/fkie-cad/nvd-json-data-feeds/archive/refs/heads/main.tar.gz",
)

DEFAULT_OUTPUT = Path(__file__).resolve().parent / "data" / "cpes.json"

# Which CPE `part` values to keep: a=application, o=operating system, h=hardware.
DEFAULT_PARTS = "aoh"

# Guard against overwriting the committed database with a truncated/failed run.
DEFAULT_MIN_ENTRIES = 10_000

USER_AGENT = "cpelist-update-bot (+https://github.com/daffainfo/cpelist)"

# --- CPE parsing ------------------------------------------------------------

# One component of a CPE 2.3 formatted string: a run of ordinary characters
# and/or backslash escape sequences (\:  \\  \+  ...). Matching escapes as a
# unit keeps an escaped colon inside its component instead of being mistaken for
# a field separator.
_COMPONENT = r"(?:[^:\\]|\\.)*"

# A well-formed CPE 2.3 formatted string has exactly 13 colon-separated
# components: cpe : 2.3 : part : vendor : product : version : update : edition :
# language : sw_edition : target_sw : target_hw : other. We capture the 11 that
# follow the "cpe:2.3:" prefix; groups 1-3 are part, vendor and product.
_CPE_RE = re.compile(
    r"^cpe:2\.3:" + ":".join(f"({_COMPONENT})" for _ in range(11)) + r"$"
)

# Locate JSON-encoded CPE strings inside raw feed bytes. Inside a JSON string a
# value runs until an unescaped double-quote, and ``\\.`` consumes any JSON
# escape sequence -- so this captures the complete, still-JSON-escaped cpeName.
_RAW_CPE_RE = re.compile(rb'cpe:2\.3:(?:\\.|[^"\\\n\r])*')


def normalise(cpe_name: str, wanted_parts: set[str]) -> str | None:
    """Return the product-level CPE for ``cpe_name`` or ``None`` if unwanted.

    The result keeps ``part:vendor:product`` and wildcards every other
    component, e.g. ``cpe:2.3:a:sgi:propack:*:*:*:*:*:*:*:*``.
    """
    match = _CPE_RE.match(cpe_name)
    if match is None:
        return None
    part, vendor, product = match.group(1), match.group(2), match.group(3)
    if part not in wanted_parts:
        return None
    return f"cpe:2.3:{part}:{vendor}:{product}" + ":*" * 8


def download(url: str, dest: Path) -> bool:
    """Download ``url`` to ``dest``; return ``False`` (and warn) if it fails."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=180) as response:
            with dest.open("wb") as handle:
                shutil.copyfileobj(response, handle)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        print(f"    ! skipping unreachable source: {url} ({exc})", file=sys.stderr)
        return False
    return True


def scrape(archive: Path, wanted_parts: set[str], results: set[str]) -> int:
    """Add every wanted, normalised CPE found in ``archive`` to ``results``.

    Returns the number of newly added (previously unseen) entries.
    """
    before = len(results)
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            if not member.isfile():
                continue
            handle = tar.extractfile(member)
            if handle is None:
                continue
            data = handle.read()
            for raw in _RAW_CPE_RE.findall(data):
                try:
                    # Wrap in quotes so json can decode the CPE's escape sequences.
                    cpe_name = json.loads(b'"' + raw + b'"')
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                normalised = normalise(cpe_name, wanted_parts)
                if normalised is not None:
                    results.add(normalised)
    return len(results) - before


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "-o", "--output", type=Path, default=DEFAULT_OUTPUT,
        help=f"output JSON file (default: {DEFAULT_OUTPUT})",
    )
    parser.add_argument(
        "-p", "--parts", default=DEFAULT_PARTS,
        help="CPE parts to keep: any combination of a (application), "
             "o (operating system) and h (hardware), e.g. 'a' or 'aoh' "
             f"(default: {DEFAULT_PARTS!r} = all parts)",
    )
    parser.add_argument(
        "--min-entries", type=int, default=DEFAULT_MIN_ENTRIES,
        help="refuse to write output with fewer than this many entries "
             f"(default: {DEFAULT_MIN_ENTRIES})",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    wanted_parts = set(args.parts)
    if not wanted_parts <= set("aoh"):
        print(f"error: --parts must be a combination of a/o/h, got {args.parts!r}",
              file=sys.stderr)
        return 2

    results: set[str] = set()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        downloaded_any = False
        for index, url in enumerate(SOURCES):
            dest = tmp / f"source-{index}.tar.gz"
            print(f"[+] downloading {url}")
            if not download(url, dest):
                continue
            downloaded_any = True
            print(f"[+] scanning {dest.name} ...")
            added = scrape(dest, wanted_parts, results)
            print(f"    +{added} new (running total: {len(results)})")

        if not downloaded_any:
            print("error: no data sources could be downloaded", file=sys.stderr)
            return 1

    if len(results) < args.min_entries:
        print(f"error: only {len(results)} entries (< {args.min_entries}); "
              "refusing to overwrite output", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        json.dump(sorted(results), handle, indent=2)
        handle.write("\n")
    print(f"[+] wrote {len(results)} CPEs to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
