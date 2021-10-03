import asyncio
import signal

import toml

from .bot import Cryptomelane, BotConfig

if __name__ == '__main__':
    conf = BotConfig.from_dict(toml.load('./config.example.toml'))
    print(conf)
    raise SystemExit(0)
    b = Bot(conf)
    loop = asyncio.get_event_loop()

    def on_sig():
        print("Caught SIGINT")
        loop.create_task(b.stop())

    loop.add_signal_handler(signal.SIGINT, on_sig)

    loop.run_until_complete(b.run())
