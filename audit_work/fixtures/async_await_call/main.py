import asyncio, lib
async def h():
    await lib.vulnerable()
asyncio.run(h())
