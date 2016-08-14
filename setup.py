#!/usr/bin/env python

from setuptools import setup

version = "0.3"

setup(
    name="bitcoin_tools",
    version=version,
    packages = [
        "bitcoin_tools",
        "bitcoin_tools.ecdsa",
    ],
    author="TheZero",
    entry_points = { 'console_scripts':
            [
                'bt-adr = bitcoin_tools.address_tools:main',
                'bt-msg = bitcoin_tools.message_tools:main',
            ]
        },
    author_email="io@thezero.org",
    url="https://github.com/zbad405/bit-tools",
    license="http://opensource.org/licenses/MIT",
    description="A bunch of utilities that might be helpful when dealing with Bitcoin addresses and Message Singing/Verify."
)
