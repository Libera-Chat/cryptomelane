# Cryptomelane

Cryptomelane is an IRC oper bot designed to enforce global CIDR limits.

Specifically this exists to workaround a bug or two in solanum's limits.

## Running

To run, first create a virtual environment and install requirements.txt
(`pip install -r requirements.txt`) and then run the bot as a package:
`python3 -m cryptomelane`. For bonus points you can do this in a tmux
session with `tmux new -s name venv/bin/python -m cryptomelane`

## Configuring

Cryptomelane uses a TOML config file, you can find an example in `config.example.toml`

All of the banned masks are listed under the `masks_to_ban` table, with individual masks
being keys thereof (`[masks_to_ban.'127.0.0.1/8']`).

You can specify a message to use in the `KILL` message with `message`

The maximum user count is specified in the `max_users` key, per mask.

If you need to exclude a range within a larger range, you can use the
list `excludes` with CIDR strings. Users on these ranges will not be counted
towards the limit.

## How this all works

This relies on solanum TESTMASK on startup to gain insight into numbers, and from
there listens to connect and disconnect server notices.

As an additional safety, if a server splits or joins the network, all numbers are
cleared and TESTMASKs are reissued to ensure that the count is consistent.

## Performance

In our usage, Cryptomelane has happily kept up with connection rates of over 30 users a second,
and should happily continue to KILL users at speeds far beyond that.

