#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Write the OpenAPI contract without the operations marked `x-status: designed` (not implemented yet), for contract
testing tools (Schemathesis) that must only exercise what exists.

    python3 tools/api/implemented_spec.py [--methods get] [--paths REGEX] > /tmp/implemented.yaml
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
METHODS = ("get", "post", "put", "patch", "delete")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--methods", default=",".join(METHODS))
    ap.add_argument("--paths", default=".*", help="regex the path template must match (re.search)")
    ap.add_argument("--exclude-paths", default=None)
    args = ap.parse_args()
    keep = set(args.methods.lower().split(","))
    spec = yaml.safe_load((ROOT / "schemas/api/openapi.yaml").read_text())
    for path in list(spec["paths"]):
        item = spec["paths"][path]
        wanted = re.search(args.paths, path) and not (args.exclude_paths and re.search(args.exclude_paths, path))
        for m in METHODS:
            if m in item and (item[m].get("x-status") == "designed" or m not in keep or not wanted):
                del item[m]
        if not any(m in item for m in METHODS):
            del spec["paths"][path]
    yaml.safe_dump(spec, sys.stdout, sort_keys=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
