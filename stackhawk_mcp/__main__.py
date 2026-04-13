import asyncio
from .server import main


def cli() -> None:
    asyncio.run(main())


if __name__ == "__main__":
    cli()
