import asyncio
from .server import main

def cli():
    asyncio.run(main())

if __name__ == "__main__":
    cli() 