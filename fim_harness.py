"""
Alias entry point for safe FIM ransomware harness.
Redirects to test_fim_harness.py.
"""
import asyncio
from test_fim_harness import run_fim_harness

if __name__ == "__main__":
    asyncio.run(run_fim_harness())

