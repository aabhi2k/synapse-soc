"""
Comprehensive Test Runner for SYNAPSE-SOC.
Discovers and executes all unit test suites, reporting exact counts and timings.
"""

import sys
import unittest
import time
from pathlib import Path

# Fix Windows cp1252 encoding
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def run_all_tests():
    print("=" * 65)
    print("  SYNAPSE-SOC : COMPREHENSIVE AUTOMATED TEST SUITE")
    print("=" * 65)
    print("\n[*] Discovering tests in tests/ directory...")

    loader = unittest.TestLoader()
    start_dir = str(PROJECT_ROOT / "tests")
    suite = loader.discover(start_dir=start_dir, pattern="test_*.py")

    start_time = time.time()
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    duration = time.time() - start_time

    total = result.testsRun
    failures = len(result.failures)
    errors = len(result.errors)
    skipped = len(result.skipped)
    passed = total - failures - errors - skipped

    print("\n" + "=" * 65)
    print("  TEST EXECUTION SUMMARY")
    print("=" * 65)
    print(f"  • Total Tests Run: {total}")
    print(f"  • Passed:         {passed} [PASS]")
    print(f"  • Failures:       {failures}")
    print(f"  • Errors:         {errors}")
    print(f"  • Skipped:        {skipped}")
    print(f"  • Time Elapsed:   {duration:.2f} seconds")
    print("=" * 65)

    if result.wasSuccessful():
        print(f"\n[+] ALL {total} TESTS PASSED SUCCESSFULLY!\n")
        return 0
    else:
        print(f"\n[!] TESTS FAILED: {failures} failures, {errors} errors.\n")
        return 1


if __name__ == "__main__":
    exit_code = run_all_tests()
    sys.exit(exit_code)

