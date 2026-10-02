"""Small JSON-only read-only CLI; error and unknown reports never exit clean."""

import argparse
import json

from . import __version__
from .review import review_wheel


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Read-only wheel installation namespace policy review; PASS is scoped, not a package safety guarantee.")
    parser.add_argument("wheel", help="An existing wheel file; never installed, imported or extracted")
    parser.add_argument("--allow-common-name", action="append", default=[], help="Explicitly accept a generic top-level name; cannot waive stdlib overlaps")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        result = review_wheel(args.wheel, allow_common_names=args.allow_common_name)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[result["status"]]
