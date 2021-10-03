from __future__ import annotations

import asyncio
import ipaddress
import logging
from dataclasses import dataclass
from typing import Any, Dict, Mapping, TypedDict

from irctokens.line import Line
from ircstates.numerics import RPL_YOUREOPER, RPL_RSACHALLENGE2, RPL_ENDOFRSACHALLENGE2

from cryptomelane.irc import IRC, IRCConfig
from ircchallenge import Challenge


@dataclass
class BotConfig:
    ips_to_check: dict[str, MaskDict]
    challenge_key_path: str
    challenge_key_passwd: str
    irc: IRCConfig

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> BotConfig:
        if not all(x in d for x in ('masks_to_ban', 'irc')):
            raise ValueError('Invalid dict provided')

        challenge_key_path = d.get('challenge', {}).get('key_path', '')
        challenge_key_password = d.get('challenge', {}).get('key_password', '')

        return BotConfig(d['masks_to_ban'], challenge_key_path, challenge_key_password, IRCConfig.from_dict(d['irc']))


class MaskDict(TypedDict):
    message: str
    max_users: int


@dataclass
class IPUsers:
    message: str
    network: ipaddress.IPv6Network | ipaddress.IPv4Network
    max_user_count: int
    user_count: int = 0


class Cryptomelane:
    def __init__(self, config: BotConfig) -> None:
        self.irc = IRC(config.irc)
        self.logger = logging.getLogger('cryptomelane')
        self.config = config
        self.IPs_lock = asyncio.Lock()
        self.IPs: Dict[ipaddress.IPv6Network | ipaddress.IPv4Network, IPUsers] = {}
        for net, rules in self.config.ips_to_check.items():
            network = ipaddress.ip_network(net)
            self.IPs[network] = IPUsers(
                message=rules['message'],
                network=network,
                max_user_count=rules['max_users']
            )

        self.irc.hook_command('727', self.handle_testmask_response)
        self.challenge: Challenge | None = None

    async def run(self):
        asyncio.create_task(self.irc.run())

        await self.irc.await_command('001')
        # Connected, lets oper
        await self.do_challenge()

        await self.irc.stopped

    async def send_testmasks(self):
        for network in self.IPs:
            self.irc.write_cmd('TESTMASK', f'*@{network.compressed}')
        ...

    async def handle_testmask_response(self, line: Line):
        me: str
        local_str: str
        remote_str: str
        mask: str
        (me, local_str, remote_str, mask, *_) = line.params
        # Technically its *possible* that something funky happened causing weird behaviour.
        # But I dont think Im going to worry about it.

        try:
            local, remote = int(local_str), int(remote_str)

        except ValueError:
            self.logger.exception(f'could not parse numbers from TESTMASK response {line=}')
            return

        total = local+remote
        ip = ipaddress.ip_network(mask.removeprefix('*!*@'))
        if ip not in self.IPs:
            return

        async with self.IPs_lock:
            self.IPs[ip].user_count = total

    async def on_snotice(self, line: Line):
        """Wait for a server notice matching what we expect."""
        msg: str = line.params[-1]
        if not msg.startswith('*** Notice -- '):
            return

        msg = msg.removeprefix('*** Notice -- ')
        nick: str
        ident: str
        host: str
        ip: str

        if msg.startswith('CLICONN'):
            # local variant
            (_, nick, ident, host, ip, *_) = msg.split(' ')

        elif msg.startswith('Client connecting:'):
            (_, _, nick, userhost, ip, *_) = msg.split(' ')

            split = userhost.split('@')
            ident, host = split[0][1:], split[1][:-1]
            ip = ip[1:-1]

        else:
            self.logger.warning(f'Unable to parse snotice {line=}. Bailing')
            return

        ip_addy: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(ip)

        await self.handle_connect(nick, ident, host, ip_addy)

    async def handle_connect(self, nick: str, ident: str, host: str, ip: ipaddress.IPv4Address | ipaddress.IPv6Address):
        async with self.IPs_lock:
            for net, data in self.IPs.items():
                if ip not in net:
                    continue

                self.logger.info(f'User {nick}!{ident}@{host} [{ip}] falls under check for {data.network}')

                data.user_count += 1
                if data.user_count > data.max_user_count:
                    self.logger.info(
                        f'User {nick}!{ident}@{host} [{ip}] pushes {data.network} to {data.user_count} which is > than {data.max_user_count}. Killing'
                    )
                    self.kill_user(nick, data.message)
                    data.user_count -= 1

                break

    def kill_user(self, nick: str, message: str):
        self.logger.info(f'Killing {nick!r} with message {message!r}')
        self.irc.write_cmd('KILL', nick, message)

    async def do_challenge(self):
        """Do CHALLENGE based authentication"""
        challenge = Challenge(keyfile=self.config.challenge_key_path, password=self.config.challenge_key_passwd)

        def on_rpl_chal(line: Line):
            challenge.push(line.params[-1])

        await self.irc.await_command(RPL_ENDOFRSACHALLENGE2)
        self.irc.remove_command_hook(RPL_RSACHALLENGE2, on_rpl_chal)
        self.irc.write_cmd('CHALLENGE', f'+{challenge.finalise()}')
        await self.irc.await_command(RPL_YOUREOPER)

    async def stop(self, msg: str = 'stop requested'):
        await self.irc.stop(msg)
