from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Dict, Mapping, Tuple, TypedDict, Union
from webbrowser import get

from ircchallenge import Challenge
from ircstates.numerics import RPL_ENDOFRSACHALLENGE2, RPL_RSACHALLENGE2, RPL_YOUREOPER
from irctokens.line import Line

from cryptomelane.irc import IRC, IRCConfig

NETSPLIT = re.compile(r"^Net(join|split) \S+ <-> \S+")


@dataclass
class BotConfig:
    ips_to_check: dict[str, MaskDict]
    challenge_user: str
    challenge_key_path: str
    challenge_key_passwd: str
    irc: IRCConfig

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> BotConfig:
        if not all(x in d for x in ("masks_to_ban", "irc")):
            raise ValueError("Invalid dict provided")

        challenge_key_path = d.get("challenge", {}).get("key_path", "")
        challenge_key_password = d.get("challenge", {}).get("key_password", "")
        challenge_user = d.get("challenge", {}).get("user", "")

        return BotConfig(
            d["masks_to_ban"],
            challenge_user,
            challenge_key_path,
            challenge_key_password,
            IRCConfig.from_dict(d["irc"]),
        )


class _BaseMaskDict(TypedDict):
    message: str
    max_users: int
    log_only: bool


class MaskDict(_BaseMaskDict, total=False):
    exclude: list[str]
    name: str


NET = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
ADD = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


@dataclass
class IPUsers:
    message: str
    name: str
    network: NET
    max_user_count: int
    user_count: int = 0
    log_only: bool = False
    exclude: list[NET] = field(default_factory=list)

    def __str__(self) -> str:
        return f"{self.name} [{self.network}] ({self.user_count}/{self.max_user_count})"


class Cryptomelane:
    def __init__(self, config: BotConfig) -> None:
        self.irc: IRC = IRC(config.irc)
        self.logger = logging.getLogger("cryptomelane")
        self.config = config
        self.IPs_lock = asyncio.Lock()
        self.IPs: Dict[NET, IPUsers] = {}
        for net, rules in self.config.ips_to_check.items():
            network = ipaddress.ip_network(net)
            excludes = []
            if (ex := rules.get("exclude")) is not None:
                excludes = [ipaddress.ip_network(x) for x in ex]

            self.IPs[network] = IPUsers(
                message=rules["message"],
                network=network,
                max_user_count=rules["max_users"],
                log_only=rules.get("log_only", False),
                exclude=excludes,
                name=rules.get("name", str(net)),
            )

        self.irc.hook_command("727", self.handle_testmask_response)
        self.irc.hook_command("NOTICE", self.on_snotice)
        self.challenge: Challenge | None = None

    async def run(self):
        asyncio.create_task(self.irc.run())

        await self.irc.await_command("001")
        # Connected, lets oper
        await self.do_challenge()
        self.irc.write_cmd("MODE", self.irc.nick, "+s", "+cFs")
        self.irc.write_cmd("MODE", self.irc.nick, "-w")
        self.send_testmasks()

        await self.irc.stopped

    def send_testmasks(self):
        self.logger.info("Sending TESTMASKs")
        to_send = set()
        for ip_user in self.IPs.values():
            to_send.add(ip_user.network)
            to_send.update(ip_user.exclude)
            ip_user.user_count = 0
            self.logger.debug(f"Set {ip_user} to 0")

        for net in sorted(to_send):
            self.logger.info(f"sending testmask for {net.compressed}")
            self.irc.write_cmd("TESTMASK", f"*@{net.compressed}")

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
            self.logger.exception(
                f"could not parse numbers from TESTMASK response {line=}"
            )
            return

        total = local + remote
        if mask.startswith("*!*@"):
            mask = mask[4:]

        try:
            net = ipaddress.ip_network(mask)
        except ValueError as e:
            self.logger.exception(f"Could not parse {mask} as an IP Network: {e}")
            return

        self.logger.info(f"Got a TESTMASK response for {net}")

        async with self.IPs_lock:
            for ip_user in self.IPs.values():
                if net in ip_user.exclude:
                    self.logger.info(
                        f"TESTMASK {net} is in {ip_user}'s excludes. Subtracting {total}"
                    )
                    # this is excluded, subtract the total to maintain the number
                    ip_user.user_count -= total

                if net == ip_user.network:
                    # this is the network we're checking
                    self.logger.info(
                        f"TESTMASK {net} is the network {ip_user} works on. Adding {total}"
                    )
                    ip_user.user_count += total

    async def on_snotice(self, line: Line):
        """Wait for a server notice matching what we expect."""
        if line.source is None or "@" in line.source:
            return  # Not a server notice

        msg: str = line.params[-1]
        if not msg.startswith("*** Notice -- "):
            return

        msg = msg[14:]

        try:
            if msg.startswith("CLICONN") or msg.startswith("Client connecting"):
                nick, ident, host, ip = self.extract_connect(msg)
                if ip is None:
                    # spoofed, dont care
                    return

                await self.handle_connect(nick, ident, host, ip)

            elif msg.startswith("CLIEXIT") or msg.startswith("Client exiting"):
                nick, ident, host, ip = self.extract_quit(msg)
                if ip is None:
                    # spoofed, dont care
                    return

                await self.handle_quit(nick, ident, host, ip)

            elif NETSPLIT.match(msg):

                self.logger.info(f'{msg.split(" ")[0]} detected! re-requesting')
                self.send_testmasks()

            else:
                # Not an snote we care about
                return

        except ValueError:
            self.logger.warning(f"unable to parse snotice {line=}. bailing")
            return

    @staticmethod
    def extract_connect(
        msg: str,
    ) -> Tuple[str, str, str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
        """
        Extract Nick, ident, host, and IP from a CONNECT server notice

        :raises ValueError: If the notice is invalid in some way
        :return: nick, ident, host, IP
        """
        nick: str
        ident: str
        host: str
        ip: str

        if msg.startswith("CLICONN"):
            # local variant
            (_, nick, ident, host, ip, *_) = msg.split(" ")

        elif msg.startswith("Client connecting:"):
            (_, _, nick, userhost, ip, *_) = msg.split(" ")

            split = userhost.split("@")
            ident, host = split[0][1:], split[1][:-1]
            ip = ip[1:-1]

        else:
            raise ValueError(f"I dont know how to break {msg!r} up")

        ip_addy: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        if ip == "0":
            ip_addy = None
        else:
            ip_addy = ipaddress.ip_address(ip)

        return nick, ident, host, ip_addy

    @staticmethod
    def extract_quit(
        msg: str,
    ) -> Tuple[str, str, str, ipaddress.IPv4Address | ipaddress.IPv6Address | None]:
        if msg.startswith("CLIEXIT"):
            # local
            (_, nick, ident, host, ip, *_) = msg.split(" ")

        elif msg.startswith("Client exiting:"):
            (_, _, nick, userhost, *rest) = msg.split(" ")
            ip = rest[-1]

            split = userhost.split("@")
            ident, host = split[0][1:], split[1][:-1]
            ip = ip[1:-1]

        else:
            raise ValueError(f"I dont know how to break {msg!r} up")

        ip_addy: ipaddress.IPv4Address | ipaddress.IPv6Address | None
        if ip == "0":
            ip_addy = None

        else:
            ip_addy = ipaddress.ip_address(ip)

        return nick, ident, host, ip_addy

    async def handle_connect(
        self,
        nick: str,
        ident: str,
        host: str,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ):
        async with self.IPs_lock:
            for ip_user in self.IPs.values():
                if not self._check(nick, ident, host, ip, ip_user):
                    continue

                # this connect matched this IPUser instance.

                log_msg = f"{nick}!{ident}@{host} [{ip}]"
                self.logger.info(
                    f"{log_msg:<100} matches {str(ip_user):>60}. Incrementing (now {ip_user.user_count+1})"
                )
                ip_user.user_count += 1

                if ip_user.user_count > ip_user.max_user_count:
                    self.logger.info(
                        f"{log_msg:<100} pushes {str(ip_user):>61} past max. Killing user"
                    )
                    if ip_user.log_only:
                        continue

                    self.kill_user(nick, ip_user.message)

    def _check(
        self,
        nick: str,
        ident: str,
        host: str,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
        to_check: IPUsers,
    ) -> bool:
        log_msg = f"{nick}!{ident}@{host} ({ip})"
        if ip not in to_check.network:
            # self.logger.debug(
            #     f"{log_msg} is not within {to_check.name} ({to_check.network}) -- ignoring"
            # )
            return False

        if to_check.exclude is not None:
            for ex in to_check.exclude:
                if ip not in ex:
                    continue

                self.logger.info(
                    f"{log_msg:<100} is excluded by {ex} in {str(to_check):>60} -- skipping"
                )
                return False

        return True

    async def handle_quit(
        self,
        nick: str,
        ident: str,
        host: str,
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    ):
        async with self.IPs_lock:
            for ip_user in self.IPs.values():
                if not self._check(nick, ident, host, ip, ip_user):
                    continue

                log_msg = f"{nick}!{ident}@{host} [{ip}]"
                self.logger.info(
                    f"{log_msg:<100} matches {str(ip_user):>60}. Decrementing (now {ip_user.user_count - 1})"
                )
                ip_user.user_count -= 1

    def kill_user(self, nick: str, message: str):
        self.logger.info(f"Killing {nick!r} with message {message!r}")
        self.irc.write_cmd("KILL", nick, message)

    async def do_challenge(self):
        """Do CHALLENGE based authentication"""
        challenge = Challenge(
            keyfile=self.config.challenge_key_path,
            password=self.config.challenge_key_passwd,
        )

        def on_rpl_chal(line: Line):
            challenge.push(line.params[-1])

        self.irc.hook_command(RPL_RSACHALLENGE2, on_rpl_chal)
        self.irc.write_cmd("CHALLENGE", self.config.challenge_user)
        await self.irc.await_command(RPL_ENDOFRSACHALLENGE2)
        self.irc.remove_command_hook(RPL_RSACHALLENGE2, on_rpl_chal)
        self.irc.write_cmd("CHALLENGE", f"+{challenge.finalise()}")
        await self.irc.await_command(RPL_YOUREOPER)

    async def stop(self, msg: str = "stop requested"):
        await self.irc.stop(msg)
