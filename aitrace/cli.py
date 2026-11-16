"""Command line for aitrace."""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .core import ALWAYS, inspect, render

EPILOG = """examples:
  aitrace photo.jpg                 report on one file
  aitrace *.png -v                  several files, with the metadata that was read
  aitrace clip.mp4 --json           machine-readable output

exit status: 0 when every file was read, 2 if a file could not be read.
"""


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="aitrace",
        description="Look inside an image or video for traces of how it was made: Content Credentials, AI generator "
                    "settings, declared source type, camera and editing metadata. Reads metadata only; gives no probability.",
        epilog=EPILOG, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("files", nargs="+")
    p.add_argument("-v", "--verbose", action="store_true", help="also print the metadata that was read")
    p.add_argument("--json", action="store_true", help="print one JSON document instead of text")
    p.add_argument("--version", action="version", version=f"aitrace {__version__}")
    a = p.parse_args(argv)
    reports, bad = [], 0
    for path in a.files:
        if not os.path.isfile(path):
            print(f"aitrace: not a file: {path}", file=sys.stderr)
            bad += 1
            continue
        try:
            reports.append(inspect(path))
        except OSError as e:
            print(f"aitrace: {path}: {e}", file=sys.stderr)
            bad += 1
    if a.json:
        print(json.dumps({"note": ALWAYS, "files": [r.to_dict() for r in reports]}, indent=1, ensure_ascii=False, default=str))
    else:
        for r in reports:
            print(render(r, a.verbose))
            print()
        if reports:
            print(ALWAYS)
    return 2 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
