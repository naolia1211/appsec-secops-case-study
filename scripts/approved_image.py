"""Read the Task 1 approval; never silently fall back to a different image."""
import json
import re
import sys
from pathlib import Path

def read_record(path=Path("reports/task1/approved-image.json")):
    record = json.loads(path.read_text())
    if not isinstance(record, dict) or not re.fullmatch(r"appsec-demo:[A-Za-z0-9_.-]+", record.get("image", "")) or not re.fullmatch(r"sha256:[a-f0-9]{64}", record.get("image_id", "")):
        raise ValueError("invalid Task 1 approval")
    return record

if __name__ == "__main__":
    try:
        record = read_record()
        print(record[{"name": "image", "id": "image_id"}[sys.argv[1]]])
    except (OSError, ValueError, KeyError, IndexError) as error:
        print(f"BLOCK: {error}", file=sys.stderr)
        raise SystemExit(2)
