# cpelist

A regularly updated list of **CPE 2.3** identifiers scraped from NVD data, normalised down to the product level.

The database lives in [`data/cpes.json`](./data/cpes.json) and is refreshed automatically every 3 hours by a [GitHub Action](./.github/workflows/update-cpelist.yml).

## Output format

`data/cpes.json` is a JSON array of unique CPE 2.3 strings. Every component after `part:vendor:product` is wildcarded (`*`), so each entry represents a *product* rather than a specific version/edition:

```json
[
  "cpe:2.3:a:sgi:propack:*:*:*:*:*:*:*:*",
  "cpe:2.3:a:squirrelmail:squirrelmail:*:*:*:*:*:*:*:*"
]
```

### Normalisation

All trailing components — `version`, `update`, `edition`, `language`, `sw_edition`, `target_sw`, `target_hw`, `other` — are collapsed to `*`. This means `target_sw` values like `wordpress` are dropped, and every version/edition variant of the same product folds into a single entry. For example, these source entries:

```
cpe:2.3:a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7:*:*:*:*:*:wordpress:*:*
cpe:2.3:a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7:*:*:*:*:pro:wordpress:*:*
cpe:2.3:a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7:*:*:*:*:standard:wordpress:*:*
```

all collapse into one:

```
cpe:2.3:a:codedropz:drag_and_drop_multiple_file_upload_-_contact_form_7:*:*:*:*:*:*:*:*
```

By default all parts are included — `a` (application), `o` (operating system) and `h` (hardware). Pass `--parts a` to limit the output to applications only.

## How it works

[`update-cpelist.py`](./update-cpelist.py) uses only the Python standard library and:

1. Downloads the official NVD CPE dictionary (`nvdcpe-2.0.tar.gz`, JSON 2.0 feed) and the community [fkie-cad mirror](https://github.com/fkie-cad/nvd-json-data-feeds) of the NVD CVE feeds. The two are merged: the fkie mirror contributes CPEs that NVD references in CVEs but never added to the formal dictionary, and also acts as a fallback if NVD is unreachable. Any source that fails to download is skipped.
2. Extracts every complete CPE 2.3 identifier, JSON-decoding each one so escaped characters (e.g. `cgi\:irc`, `g\+\+`) are handled correctly.
3. Keeps only `part:vendor:product`, de-duplicates, and rebuilds each as a fully wildcarded CPE 2.3 string.
4. Writes the sorted, unique result to `data/cpes.json`, guarded by a sanity check so a failed or truncated download never overwrites good data.

## Running locally

```bash
python3 update-cpelist.py                 # all parts: application, os, hardware (default)
python3 update-cpelist.py --parts a       # applications only
python3 update-cpelist.py --help          # all options (--output, --min-entries)
```

Requires Python 3 (standard library only — no third-party packages).

## Data source & terms

Data is derived from the [National Vulnerability Database (NVD)](https://nvd.nist.gov/). See the [NVD terms of use](https://nvd.nist.gov/developers/terms-of-use). This project is not affiliated with or endorsed by NIST/NVD.
