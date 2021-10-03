from __future__ import annotations

import ipaddress

import contextlib
from typing import ContextManager, Generic, Type, TypeVar
import pytest
from attr import dataclass
from cryptomelane.bot import Cryptomelane

_E = TypeVar('_E', bound=BaseException)


@dataclass
class Expected(Generic[_E]):
    nick: str
    ident: str
    host: str
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    exception: Type[_E] | None = None
    exception_re: str | None = None


@pytest.mark.parametrize(
    ('line', 'expect'),
    [
        (
            'Client connecting: test (ahhh@testy) [13.37.42.47] {?} <*> [somereal]',
            Expected('test', 'ahhh', 'testy', ipaddress.ip_address('13.37.42.47'))
        ),
        (
            'asdf', Expected('', '', '', ipaddress.ip_address('1.2.3.4'), ValueError, r'I dont know how to break')
        ),
        (
            'CLICONN a_nick ~an_ident 1.2.3.4 1.2.3.4 doesnt_matter 1337 * 8 * real name',
            Expected('a_nick', '~an_ident', '1.2.3.4', ipaddress.ip_address('1.2.3.4'))
        )
    ]
)
def test_connect(line: str, expect: Expected):
    wrapper: ContextManager = contextlib.nullcontext()
    if expect.exception is not None:
        wrapper = pytest.raises(expected_exception=expect.exception, match=expect.exception_re)

    with wrapper as e:
        nick, ident, host, ip = Cryptomelane.extract_connect(line)

        assert nick == expect.nick
        assert ident == expect.ident
        assert host == expect.host
        assert ip == expect.ip
