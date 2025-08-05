from __future__ import annotations

import traceback
from typing import Callable


def main(glob: dict[str, Callable[..., None]]) -> None:
    for var, val in sorted(glob.items()):
        if not var.startswith("test_"):
            continue

        print(f"{var:40s}", end="")
        try:
            val()
            print("PASSED")
        except Exception:
            print("FAILED")

            traceback.print_exc()
