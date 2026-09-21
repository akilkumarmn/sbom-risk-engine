"""Minimal test runner (works without pytest; pytest also collects these files).

    python -m tests.run_tests
"""
import importlib
import sys
import time
import traceback

MODULES = ["tests.test_metrics", "tests.test_scoring", "tests.test_parity", "tests.test_pipeline"]


def main() -> int:
    failed = total = 0
    for name in MODULES:
        mod = importlib.import_module(name)
        for attr in sorted(a for a in dir(mod) if a.startswith("test_")):
            total += 1
            t0 = time.time()
            try:
                getattr(mod, attr)()
                print(f"PASS  {name}.{attr}  ({time.time() - t0:.1f}s)")
            except Exception:  # noqa: BLE001
                failed += 1
                print(f"FAIL  {name}.{attr}")
                traceback.print_exc()
    print(f"\n{total - failed}/{total} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
