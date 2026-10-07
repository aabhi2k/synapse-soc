"""
Alias entry point for live attack demo simulation.
Redirects to demo_attack_simulation.py.
"""
import asyncio
from demo_attack_simulation import run_attack_demo

if __name__ == "__main__":
    asyncio.run(run_attack_demo())

