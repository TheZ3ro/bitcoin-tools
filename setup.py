#!/usr/bin/env python

from setuptools import setup

version = "0.1"

setup(
    name="zetautils",
    version=version,
    packages = [
        "zetautils",
        "zetautils.ecdsa",
    ],
    author="TheZero",
    entry_points = { 'console_scripts':
            [
                'zetautils = zetautils.zetacoin_utils:main',
            ]
        },
    author_email="io@thezero.org",
    url="https://github.com/zbad405/zetacoin-address-utils",
    license="http://opensource.org/licenses/MIT",
    description="A bunch of utilities that might be helpful when dealing with Zetacoin addresses."
)
