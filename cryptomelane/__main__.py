import sys
import asyncio
import signal

import toml

from .bot import Cryptomelane, BotConfig

if __name__ == '__main__':
    conf = BotConfig.from_dict(toml.load('./config.toml'))
    print(conf)
    b = Cryptomelane(conf)
    loop = asyncio.get_event_loop()

    def on_sig():
        print("Caught SIGINT")
        sys.exit(0)

    loop.add_signal_handler(signal.SIGINT, on_sig)

    loop.run_until_complete(b.run())
