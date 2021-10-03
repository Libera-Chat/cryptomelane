import asyncio
import signal

import toml

from .bot import Cryptomelane, BotConfig

if __name__ == '__main__':
    conf = BotConfig.from_dict(toml.load('./config.example.toml'))
    print(conf)
    b = Cryptomelane(conf)
    loop = asyncio.get_event_loop()

    def on_sig():
        print("Caught SIGINT")
        loop.create_task(b.stop())

    loop.add_signal_handler(signal.SIGINT, on_sig)

    async def testing_things():
        print('testing')
        await b.testing_things()

    loop.run_until_complete(testing_things())
