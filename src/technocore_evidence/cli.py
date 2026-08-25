from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from .core import EvidenceError, verify_record


def _load_record(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EvidenceError("input must be one JSON object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify signed Technocore evidence offline")
    parser.add_argument("record", type=Path, help="JSON file with room/from/sig/nonce/text")
    args = parser.parse_args(argv)
    try:
        result = verify_record(_load_record(args.record))
    except (EvidenceError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"valid": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(result.as_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
