import asyncio
import logging
import signal
import sys

import toml

from .bot import BotConfig, Cryptomelane

if __name__ == "__main__":
    conf = BotConfig.from_dict(toml.load("./config.toml"))
    b = Cryptomelane(conf)
    loop = asyncio.get_event_loop()

    def on_sig():
        print("Caught SIGINT")
        sys.exit(0)

    loop.add_signal_handler(signal.SIGINT, on_sig)

    loop.run_until_complete(b.run())
