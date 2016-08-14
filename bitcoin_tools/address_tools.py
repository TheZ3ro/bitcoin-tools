#!/usr/bin/env python

import argparse
import binascii
import sys

import ecdsa, encoding
from ecdsa import secp256k1

def b2h(b):
    return binascii.hexlify(b).decode("utf8")

def parse_as_number(s):
    try:
        return int(s)
    except ValueError:
        pass
    try:
        return int(s, 16)
    except ValueError:
        pass

def parse_as_private_key(s):
    v = parse_as_number(s)
    if v and v < secp256k1._r:
        return v
    try:
        v = encoding.wif_to_secret_exponent(s)
        return v
    except encoding.EncodingError:
        pass

def parse_as_public_pair(s):
    try:
        if s[:2] in (["02", "03", "04"]):
            return encoding.sec_to_public_pair(encoding.h2b(s))
    except (encoding.EncodingError, binascii.Error):
        pass
    for c in ",/":
        if c in s:
            s0, s1 = s.split(c, 1)
            v0 = parse_as_number(s0)
            if v0:
                if s1 in ("even", "odd"):
                    return ecdsa.public_pair_for_x(ecdsa.generator_secp256k1, v0, is_even=(s1=='even'))
                v1 = parse_as_number(s1)
                if v1:
                    if not ecdsa.is_public_pair_valid(ecdsa.generator_secp256k1, (v0, v1)):
                        sys.stderr.write("invalid (x, y) pair\n")
                        sys.exit(1)
                    return (v0, v1)

def parse_as_address(s):
    try:
        return encoding.bitcoin_address_to_hash160_sec(s)
    except encoding.EncodingError:
        pass
    try:
        v = encoding.h2b(s)
        if len(v) == 20:
            return v
    except binascii.Error:
        pass

def printer(k,f):
    flags = []
    if f.wif:
        flags.append("wif")
    if f.hash160:
        flags.append("hash160")
    if f.address:
        flags.append("address")

    def filter(text):
        r = False
        if flags == []:
            r = True
        elif len(flags) == 3:
            r = True
        else:
            for flag in flags:
                if flag in text:
                    if "uncompressed" in text and f.uncompressed:
                        r = True
                    elif "uncompressed" in text and not f.uncompressed:
                        r = False
                    else:
                        r = True
        return r

    for item in k:                  # For every input
        karray = k.get(item)        # Get the item array
        max_length = max(len(k.items()[0][0]) for k in karray)
        space_padding = ' ' * (1 + max_length - len("input"))
        print("input%s: %s" % (space_padding, item))
        for key in karray:
            label, value = key.items()[0]
            label = label.replace('-',' ')
            if filter(label) == True:
                space_padding = ' ' * (1 + max_length - len(label))
                print("%s%s: %s" % (label, space_padding, value))
        line_padding = '-' * (max_length + 2)
        print("%s" % line_padding)

def main():
    parser = argparse.ArgumentParser(description="Bitcoin Address utilities.")

    parser.add_argument('-a', "--address", help='show as Bitcoin address', action='store_true')
    parser.add_argument('-1', "--hash160", help='show as hash160', action='store_true')
    parser.add_argument('-w', "--wif", help='show as Bitcoin WIF', action='store_true')
    parser.add_argument('-n', "--uncompressed", help='show also uncompressed form', action='store_true')
    parser.add_argument('item', help='a WIF, secret exponent, X/Y public pair, SEC (as hex), hash160 (as hex), Bitcoin address', nargs="+")
    args = parser.parse_args()

    print("Bitcoin Address utilities.\n")

    key_collection = {}

    for c in args.item:
        # figure out what it is:
        #  - secret exponent
        #  - WIF
        #  - X/Y public key (base 10 or hex)
        #  - sec
        #  - hash160
        #  - Bitcoin address
        key_collection[c] = []
        key = key_collection[c]
        secret_exponent = parse_as_private_key(c)
        if secret_exponent:
            public_pair = ecdsa.public_pair_for_secret_exponent(secp256k1.generator_secp256k1, secret_exponent)
            key.append({"secret_exponent": secret_exponent})
            key.append({"secret_exponent-hex": format("%x" % secret_exponent)})
            key.append({"wif": encoding.secret_exponent_to_wif(secret_exponent, compressed=True)})
            key.append({"wif-uncompressed": encoding.secret_exponent_to_wif(secret_exponent, compressed=False)})
        else:
            public_pair = parse_as_public_pair(c)
        if public_pair:
            bitcoin_address_uncompressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=False)
            bitcoin_address_compressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=True)
            key.append({"public-pair-x": public_pair[0]})
            key.append({"public-pair-y": public_pair[1]})
            key.append({"public-pair-y-hex": format("%x" % public_pair[0])})
            key.append({"public-pair-y-hex": format("%x" % public_pair[1])})
            key.append({"y-parity": "odd" if (public_pair[1] & 1) else "even"})
            key.append({"SEC-keypair": b2h(encoding.public_pair_to_sec(public_pair, compressed=True))})
            key.append({"SEC-keypair-uncompressed": b2h(encoding.public_pair_to_sec(public_pair, compressed=False))})
            hash160 = encoding.public_pair_to_hash160_sec(public_pair, compressed=True)
            hash160_unc = encoding.public_pair_to_hash160_sec(public_pair, compressed=False)
        else:
            hash160 = parse_as_address(c)
            hash160_unc = None
        if not hash160:
            sys.stderr.write("can't decode input %s\n" % c)
            sys.exit(1)
        key.append({"hash160": b2h(hash160)})
        if hash160_unc:
            key.append({"hash160-uncompressed": b2h(hash160_unc)})
        key.append({"address": encoding.hash160_sec_to_bitcoin_address(hash160)})
        if hash160_unc:
            key.append({"address-uncompressed": encoding.hash160_sec_to_bitcoin_address(hash160_unc)})

    del args.item
    printer(key_collection, args)


if __name__ == '__main__':
    main()
