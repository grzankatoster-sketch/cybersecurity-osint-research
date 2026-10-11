"""Run: python examples/offline.py — no HTTP is performed."""

import asyncio

from ultimate_username.demo import make_demo
from ultimate_username.domain.codec import to_json
from ultimate_username.engine import UsernameEngine


async def main():
    registry, transport = make_demo()
    async with UsernameEngine(registry, transport) as engine:
        async for result in engine.search_stream("training_account"):
            print(to_json(result))


if __name__ == "__main__":
    asyncio.run(main())
