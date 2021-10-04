from __future__ import annotations

import asyncio
import base64
import functools
import inspect
import itertools
import logging
import ssl
import traceback
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Mapping, cast

import irctokens
from ircstates.numerics import RPL_SASLSUCCESS


@dataclass
class IRCConfig:
    host: str
    port: int
    nick: str
    ident: str
    realname: str

    sasl_mech: str = ''
    sasl_plain_user: str = ''
    sasl_plain_passwd: str = ''

    use_tls: bool = False
    use_sasl: bool = False

    server_password: str = ''
    oper_user: str = ''
    oper_passwd: str = ''

    challenge_key_path = ''
    challenge_key_passwd = ''

    # TODO: challenge stuff
    # TODO: SASL EXTERNAL stuff

    join_channels: list[str] = field(default_factory=lambda: list(('#adtestchan', '#anothertestchan')))

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> IRCConfig:
        return IRCConfig(**d)


class IRC:
    def __init__(self, config: IRCConfig) -> None:
        self.decoder = irctokens.StatefulDecoder()
        self.msgQueue: asyncio.Queue[irctokens.Line] = asyncio.Queue()
        self.config = config

        self._socket_reader: asyncio.StreamReader
        self._writer_lock = asyncio.Lock()
        self._socket_write: asyncio.StreamWriter

        self.command_hooks: dict[str, list[Callable[[irctokens.Line], None | Awaitable[None]]]] = defaultdict(list)

        self._read_task: asyncio.Task | None = None
        self._write_task: asyncio.Task | None = None
        self.caps_to_request = {  # name: die_if_not_exist
            'account-notify': False,
            'away-notify': False,
            'chghost': False,
            'extended-join': False,
            'multi-prefix': False,
            # sasl -- special handling
            'account-tag': False,

            # solanum specific things
            'solanum.chat/oper': False,  # adds oper tag to messages
            'solanum.chat/realhost': False,  # adds real host tag to messages
            'solanum.chat/identify-msg': False,
        }

        self.logger = logging.getLogger('irc')

        # runtime things
        self.enabled_caps: list[str] = []
        self.isupport: dict[str, str] = {}
        self.nick = config.nick
        self.sock_done: asyncio.Future[None] = asyncio.Future()
        self.stopped: asyncio.Future[None] = asyncio.Future()
        self.connected = False
        self.connected_fut: asyncio.Future[None] = asyncio.Future()

    async def run(self) -> None:
        await self.connect()
        self.connected = True
        for chan in self.config.join_channels:
            self.write_cmd('JOIN', chan)

        await self.sock_done

        if self._read_task:
            self._read_task.cancel()
        if self._write_task:
            self._write_task.cancel()

        self.stopped.set_result(None)

    async def stop(self, quitmsg: str = 'stop requested'):
        if self.connected:
            self.write_cmd('QUIT', quitmsg)

        else:
            self.logger.warning('Stop requested while not connected!')
            traceback.print_stack()

        await self.stopped

    def start(self) -> asyncio.Future:
        """
        Start starts the connection process and returns a future for a final connect.
        """
        async def run_listen():
            try:
                await self.run()
            except Exception:
                self.logger.exception('wut?')

        asyncio.get_event_loop().create_task(run_listen())
        return self.connected_fut

    async def connect(self) -> None:
        self.logger.info('connecting!')
        ssl_ctx: ssl.SSLContext | None = None

        if self.config.use_tls:
            ssl_ctx = ssl.create_default_context()

        self._socket_reader, self._socket_write = await asyncio.open_connection(
            self.config.host, self.config.port, ssl=ssl_ctx
        )

        self.logger.debug(f'socket opened, {self._socket_reader=} {self._socket_write=}')

        self._write_task = asyncio.create_task(self._write_loop())
        self._read_task = asyncio.create_task(self._read_loop())

        self.setup_listeners()
        if self.config.server_password != '':
            self.write_cmd('PASS', self.config.server_password)

        caps = self.negotiate_capabilities()
        self.write_cmd('CAP', 'LS', '302')
        self.write_cmd('NICK', self.config.nick)
        self.write_cmd('USER', self.config.ident, '*', '*', self.config.realname)
        await caps

        self.logger.debug('cap negotiation complete')

        await self.await_command('004')
        self.logger.info('CONNECTED!')
        if self.config.oper_passwd != '' and self.config.oper_user != '':
            self.logger.info('we have oper creds, opering up (or trying to)')
            self.write_cmd('OPER', self.config.oper_user, self.config.oper_passwd)

        self.connected_fut.set_result(None)

    async def negotiate_capabilities(self) -> None:
        if self.config.sasl_plain_passwd != '' and self.config.sasl_plain_user != '':
            self.caps_to_request['sasl'] = False

        if len(self.caps_to_request) == 0:
            return

        while True:
            cmd = await self.await_command('CAP')
            subcmd = cmd.params[1]
            if subcmd == 'LS':
                available_caps: list[str] = cmd.params[-1].split(' ')
                for cap in list(available_caps):
                    if '=' in cap:
                        available_caps.remove(cap)
                        available_caps.append(cap.split('=')[0])

                caps_to_request = set(self.caps_to_request) & set(available_caps)

                self.write_cmd('CAP', 'REQ', ' '.join(caps_to_request))
                continue

            elif subcmd == 'NAK':
                # Shouldn't be possible. we only request what we want that they actually offer.
                raise NotImplementedError

            elif subcmd == 'ACK':
                self.enabled_caps = cmd.params[-1].split(' ')
                break

        if any('sasl' in x for x in self.enabled_caps):
            self.write_cmd('AUTHENTICATE PLAIN')
            await self.await_command('AUTHENTICATE', lambda l: '+' in l.params)
            to_encode = (
                f'{self.config.sasl_plain_user}\0{self.config.sasl_plain_user}\0{self.config.sasl_plain_passwd}').encode()
            self.write_cmd('AUTHENTICATE', f'{base64.b64encode(to_encode).decode()}')
            await self.await_command(RPL_SASLSUCCESS)

        self.write_cmd('CAP', 'END')

    def write(self, line: irctokens.Line):
        self.msgQueue.put_nowait(line)

    def write_cmd(self, command: str, *params: str, source: str | None = None, tags: dict[str, str] | None = None):
        self.write(irctokens.line.build(command=command, params=list(params), source=source, tags=tags))

    async def _write_raw(self, data: bytes):
        async with self._writer_lock:
            self.logger.debug(f'<< {data.decode("utf-8", errors="replace").strip()}')
            self._socket_write.write(data)
            await self._socket_write.drain()

    async def _write_loop(self):
        self.logger.debug('write loop started')
        while True:
            line = await self.msgQueue.get()
            formatted = line.format()
            if not formatted.endswith('\r\n'):
                formatted += '\r\n'

            await self._write_raw(formatted.encode('utf8'))

    async def _read_loop(self):
        self.logger.debug('read loop started')
        while True:
            data = await self._socket_reader.read(1024)
            if not data:
                self.logger.warning('Socket closed!')
                self.sock_done.set_result(None)
                return

            lines = self.decoder.push(data)
            if lines is None:
                continue

            for line in lines:
                # one by one.
                await self.handle_line(line)

    async def handle_line(self, line: irctokens.Line):
        """
        Handle individual IRC lines from the socket

        :param line: The line to handle.
        """
        self.logger.debug(f'>> {line.format()}')
        if line.command == 'PING':
            self.write(irctokens.line.build('PONG', line.params))

        command = line.command.casefold()

        to_await: list[Callable[[irctokens.Line], Awaitable[None]]] = []
        to_call: list[Callable[[irctokens.Line], None]] = []
        for hook in itertools.chain(self.command_hooks['*'], self.command_hooks[command]):
            if inspect.iscoroutinefunction(hook):
                hook = cast(Callable[[irctokens.Line], Awaitable[None]], hook)
                to_await.append(hook)

            else:
                hook = cast(Callable[[irctokens.Line], None], hook)
                to_call.append(hook)

        # coroutines are called whenever the loop says.
        def gather_complete(fut: asyncio.Future[list[Any]]):
            res = fut.result()
            for r in res:
                if isinstance(r, BaseException):
                    self.logger.error(f'Error from gather {r}]\n{"".join(traceback.format_tb(r.__traceback__))}')

        gather = asyncio.gather(*(x(line) for x in to_await), return_exceptions=True)
        gather.add_done_callback(gather_complete)

        for hook in to_call:
            try:
                hook(line)
            except Exception:
                self.logger.exception(f'Exception while running command hooks with {line=}')

    def await_command(self, command_name: str, predicate: Callable[[irctokens.Line], bool] | None = None) -> asyncio.Future[irctokens.Line]:
        fut: asyncio.Future[irctokens.Line] = asyncio.Future()

        def callback(line: irctokens.Line):
            if predicate is None or predicate(line):
                self.remove_command_hook(command_name, callback)
                if fut.cancelled():
                    self.logger.warning('future for await_command cancelled')
                    return

                fut.set_result(line)

        self.hook_command(command_name, callback)

        return fut

    def hook_command(self, command_name: str, callback: Callable[[irctokens.Line], Any]) -> None:
        self.command_hooks[command_name.casefold()].append(callback)

    def remove_command_hook(self, command_name: str, callback: Callable[[irctokens.Line], Any]) -> None:
        self.command_hooks[command_name.casefold()].remove(callback)

    def hook_command_oneshot(self, command_name: str, callback: Callable[[irctokens.Line], Any]) -> None:
        """
        Command hook that is removed after its called.

        :param command_name: the command to hook to
        :param calback: the callback to call.
        """
        @functools.wraps(callback)
        def wrapper(line: irctokens.Line):
            callback(line)
            self.remove_command_hook(command_name, wrapper)

        self.hook_command(command_name, wrapper)

    def setup_listeners(self):
        self.hook_command('005', self.parse_isupport)
        self.hook_command('433', lambda line: self.write_cmd('NICK', line.params[1]+'_'))
        # TODO: listen for NICK for ourself, and update our NICK accordingly.

    def parse_isupport(self, line: irctokens.Line) -> None:
        tokens = line.params[1:-1]
        for k, _, v in map(lambda t: t.partition('='), tokens):
            self.isupport[k] = v

    # some nice handy isupport wrappers

    @functools.cached_property
    def prefix_modes(self) -> dict[str, str]:
        raw = self.isupport.get('PREFIX')
        if raw is None:
            return {}

        modes, _, chars = raw[1:].partition(')')
        return dict(zip(modes, chars))
