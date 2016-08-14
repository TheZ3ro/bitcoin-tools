import argparse
import binascii
import sys

import hashlib
import hmac
import io
import os
import re
import struct

import ecdsa, encoding
from ecdsa import ellipticcurve, numbertheory, secp256k1
from binascii import b2a_base64, a2b_base64
from encoding import public_pair_to_bitcoin_address, to_bytes_32, from_bytes_32, double_sha256, a2b_hashed_base58
from address_tools import parse_as_private_key

# According to brainwallet, this is "inputs.io" format, but it seems practical
# and is deployed in the wild. Core bitcoin doesn't offer a message wrapper like this.
signature_template = '''\
-----BEGIN BITCOIN SIGNED MESSAGE-----
{msg}
-----BEGIN SIGNATURE-----
{addr}
{sig}
-----END BITCOIN SIGNED MESSAGE-----'''

def parse_signed_message(msg_in):
    """
        Take an "armoured" message and split into the message body, signing address
        and the base64 signature. Should work on all altcoin networks, and should
        accept both Inputs.IO and Multibit formats but not Armory.

        Looks like RFC2550 <https://www.ietf.org/rfc/rfc2440.txt> was an "inspiration"
        for this, so in case of confusion it's a reference, but I've never found
        a real spec for this. Should be a BIP really.
    """

    # Convert to Unix line feeds from DOS style, iff we find them, but
    # restore to same at the end. The RFC implies we should be using
    # DOS \r\n in the message, but that does not always happen in today's
    # world of MacOS and Linux devs. A mix of types will not work here.
    dos_nl = ('\r\n' in msg_in)
    if dos_nl:
        msg_in = msg_in.replace('\r\n', '\n')

    try:
        # trim any junk in front
        _, body = msg_in.split('SIGNED MESSAGE-----\n', 1)
    except:
        raise ValueError("expecting text SIGNED MESSSAGE somewhere")

    try:
        # - sometimes middle sep is BEGIN BITCOIN SIGNATURE, other times just BEGIN SIGNATURE
        # - choose the last instance, in case someone signs a signed message
        parts = re.split('\n-----BEGIN [A-Z ]*SIGNATURE-----\n', body)
        msg, hdr = ''.join(parts[:-1]), parts[-1]
    except:
        raise ValueError("expected BEGIN SIGNATURE line", body)

    # after message, expect something like an email/http headers, so split into lines
    hdr = list(filter(None, [i.strip() for i in hdr.split('\n')]))

    if '-----END' not in hdr[-1]:
        raise ValueError("expecting END on last line")

    sig = hdr[-2]
    addr = None
    for l in hdr:
        l = l.strip()
        if not l:
            continue

        if l.startswith('-----END'):
            break

        if ':' in l:
            label, value = [i.strip() for i in l.split(':', 1)]

            if label.lower() == 'address':
                addr = l.split(':')[1].strip()
                break

            continue

        addr = l
        break

    if not addr or addr == sig:
        raise ValueError("Could not find address")

    if dos_nl:
        msg = msg.replace('\n', '\r\n')

    return msg, addr, sig

def sign_message(key, message=None, verbose=False, use_uncompressed=None, msg_hash=None):
    """
        Return a signature, encoded in Base64, which can be verified by anyone using the
        public key.
    """
    secret_exponent = parse_as_private_key(key)
    if not secret_exponent:
        raise TypeError("Private key is required to sign a message")

    public_pair = ecdsa.public_pair_for_secret_exponent(secp256k1.generator_secp256k1, secret_exponent)
    address_compressed = encoding.public_pair_to_bitcoin_address(public_pair, compressed=True)

    addr = address_compressed

    mhash = hash_for_signing(message) if message else msg_hash

    # Use a deterministic K so our signatures are deterministic.
    try:
        r, s, y_odd = _my_sign(ecdsa.generator_secp256k1, secret_exponent, mhash)
    except RuntimeError:
        # .. except if extremely unlucky
        k = from_bytes_32(os.urandom(32))
        r, s, y_odd = _my_sign(ecdsa.generator_secp256k1, secret_exponent, mhash, _k=k)

    is_compressed = True
    assert y_odd in (0, 1)

    # See http://bitcoin.stackexchange.com/questions/14263
    # for discussion of the proprietary format used for the signature
    #
    # Also from key.cpp:
    #
    # The header byte: 0x1B = first key with even y, 0x1C = first key with odd y,
    #                  0x1D = second key with even y, 0x1E = second key with odd y,
    #                  add 0x04 for compressed keys.

    first = 27 + y_odd + (4 if is_compressed else 0)
    sig = b2a_base64(bytearray([first]) + to_bytes_32(r) + to_bytes_32(s)).strip()

    if not isinstance(sig, str):
        # python3 b2a wrongness
        sig = str(sig, 'ascii')

    if not verbose or message is None:
        return sig, addr

    return signature_template.format(
        msg=message, sig=sig, addr=addr), None

def verify_message(address, signature, message=None, msg_hash=None, public_pair=None):
    """
        Take a signature, encoded in Base64, and verify it against a
        specific base58-encoded pubkey hash.
    """

    hash160 = a2b_hashed_base58(address)

    try:
        # Decode base64 and a bitmask in first byte.
        is_compressed, recid, r, s = _decode_signature(signature)
    except ValueError:
        return False

    # Calculate hash of message used in signature
    mhash = hash_for_signing(message) if message is not None else msg_hash

    # Calculate the specific public key used to sign this message.
    pair = _extract_public_pair(ecdsa.generator_secp256k1, recid, r, s, mhash)

    # Check signing public pair is the one expected for the signature. It must be an
    # exact match for this key's public pair... or else we are looking at a validly
    # signed message, but signed by some other key.
    #
    pp = public_pair
    if pp:
        # expect an exact match for public pair.
        return pp == pair
    else:
        # Key constructed from a hash of pubkey doesn't know the exact public pair, so
        # must compare hashed addresses instead.
        prefix = b'\0' # bitcoin prefix
        ta = public_pair_to_bitcoin_address(pair, compressed=is_compressed)
        return ta == address

def _my_sign(generator, secret_exponent, val, _k=None):
    """
        Return a signature for the provided hash (val), using the provided
        random nonce, _k or generate a deterministic K as needed.

        May raise RuntimeError, in which case retrying with a new
        random value k is in order.
    """
    G = generator
    n = G.order()

    k = _k or deterministic_make_k(n, secret_exponent, val)
    p1 = k * G
    r = p1.x()
    if r == 0:
        raise RuntimeError("amazingly unlucky random number r")
    s = (numbertheory.inverse_mod(k, n) *
         (val + (secret_exponent * r) % n)) % n
    if s == 0:
        raise RuntimeError("amazingly unlucky random number s")

    return (r, s, p1.y() % 2)

def deterministic_make_k(generator_order, secret_exponent, val,
                         hash_f=hashlib.sha256, trust_no_one=True):
    """
    Generate K value BUT NOT according to https://tools.ietf.org/html/rfc6979

    ecsda.deterministic_generate_k() was more general than it needs to be,
    and I felt the hand of NSA in the wholly constants, so I simplified and
    changed the salt.
    """
    n = generator_order
    assert hash_f().digest_size == 32

    # code below has been specialized for SHA256 / bitcoin usage
    assert n.bit_length() == 256
    hash_size = 32

    if trust_no_one:
        v = b"Edward Snowden rocks the world!!"
        k = b"Qwest CEO Joseph Nacchio is free"
    else:
        v = b'\x01' * hash_size
        k = b'\x00' * hash_size

    priv = to_bytes_32(secret_exponent)

    if val > n:
        val -= n

    h1 = to_bytes_32(val)
    k = hmac.new(k, v + b'\x00' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()
    k = hmac.new(k, v + b'\x01' + priv + h1, hash_f).digest()
    v = hmac.new(k, v, hash_f).digest()

    while 1:
        t = hmac.new(k, v, hash_f).digest()

        k1 = from_bytes_32(t)

        if k1 >= 1 and k1 < n:
            return k1

        k = hmac.new(k, v + b'\x00', hash_f).digest()
        v = hmac.new(k, v, hash_f).digest()

def _decode_signature(signature):
    """
        Decode the internal fields of the base64-encoded signature.
    """

    if signature[0] not in ('G', 'H', 'I'):
        # Because we know the first char is in range(27, 35), we know
        # valid first character is in this set.
        raise TypeError("Expected base64 value as signature", signature)

    # base 64 decode
    sig = a2b_base64(signature)
    if len(sig) != 65:
        raise ValueError("Wrong length, expected 65")

    # split into the parts.
    first = ord(sig[0:1])           # py3 accomidation
    r = from_bytes_32(sig[1:33])
    s = from_bytes_32(sig[33:33+32])

    # first byte encodes a bits we need to know about the point used in signature
    if not (27 <= first < 35):
        raise ValueError("First byte out of range")

    # NOTE: The first byte encodes the "recovery id", or "recid" which is a 3-bit values
    # which selects compressed/not-compressed and one of 4 possible public pairs.
    #
    first -= 27
    is_compressed = bool(first & 0x4)

    return is_compressed, (first & 0x3), r, s

def _extract_public_pair(generator, recid, r, s, value):
    """
    Using the already-decoded parameters of the bitcoin signature,
    return the specific public key pair used to sign this message.
    Caller must verify this pubkey is what was expected.
    """
    assert 0 <= recid < 4, recid

    G = generator
    n = G.order()

    curve = G.curve()
    order = G.order()
    p = curve.p()

    x = r + (n * (recid // 2))

    alpha = (pow(x, 3, p) + curve.a() * x + curve.b()) % p
    beta = numbertheory.modular_sqrt(alpha, p)
    inv_r = numbertheory.inverse_mod(r, order)

    y = beta if ((beta - recid) % 2 == 0) else (p - beta)

    minus_e = -value % order

    R = ellipticcurve.Point(curve, x, y, order)
    Q = inv_r * (s * R + minus_e * G)
    public_pair = (Q.x(), Q.y())

    # check that this is the RIGHT public key? No. Leave that for the caller.

    return public_pair

def hash_for_signing(msg):
    """
    Return a hash of msg, according to odd bitcoin method: double SHA256 over a bitcoin
    encoded stream of two strings: a fixed magic prefix and the actual message.

    We need the constant "strMessageMagic" in C++ source code, from file "main.cpp"

    It is not shown as part of the signed message, but it is prefixed to the message
    as part of calculating the hash of the message (for signature). It's also what
    prevents a message signature from ever being a valid signature for a transaction.

    Each altcoin finds and changes this string... But just simple substitution.
    """
    magic = 'Bitcoin Signed Message:\n'

    fd = io.BytesIO()
    stream_bc_string(fd, bytearray(magic, 'ascii'))
    stream_bc_string(fd, bytearray(msg, 'utf-8'))

    # return as a number, since it's an input to signing algos like that anyway
    return from_bytes_32(double_sha256(fd.getvalue()))

def stream_bc_string(f, v):
    stream_bc_int(f, len(v))
    f.write(v)

def stream_bc_int(f, v):
    if v < 253:
        f.write(struct.pack("<B", v))
    elif v <= 65535:
        f.write(b'\xfd' + struct.pack("<H", v))
    elif v <= 0xffffffff:
        f.write(b'\xfe' + struct.pack("<L", v))
    else:
        f.write(b'\xff' + struct.pack("<Q", v))


def main():
    parser = argparse.ArgumentParser(description="Bitcoin Message utilities.")

    parser.add_argument("--sign", help='sign a message', action='store_true')
    parser.add_argument("--verify", help='verify a message', action='store_true')
    parser.add_argument('-f', "--file", help='set text as input/output file path (always Armored "inputs.io" format)', type=str)
    parser.add_argument('-p', "--priv", help='private key (secret_exponent or WIF as hex) file path', type=str)
    parser.add_argument('-a', "--armored", help='show signed message as Armored "inputs.io" format', action='store_true')
    #parser.add_argument('text', help='a message for --sign or a signature for --verify')
    args = parser.parse_args()

    print("Bitcoin Address utilities.\n")

    if args.sign == True and args.verify == False:
        print("Insert the Message to sign:")
        msg = sys.stdin.readline().rstrip()
        if args.priv:
            with open(args.priv) as f:
                content = f.read().splitlines()[0]
                if content == "":
                    raise ValueError("File is empty")
                key = content
        else:
            print("\nInsert your Private Key (secret_exponent or WIF as hex): DONT USE YOUR REAL KEY PLEASE!")
            key = sys.stdin.readline().rstrip()
        if args.armored:
            sig, nil = sign_message(key,message=msg,verbose=True)
            if args.file:
                with open(args.file,'w') as f:
                    f.write(sig)
            else:
                print("\nSignature: \n%s\n " % sig)
        else:
            sig, addr = sign_message(key,message=msg,verbose=False)
            print("\nSigned with address %s\nSignature: \"%s\" " % (addr, sig))
    elif args.sign == False and args.verify == True:
        if args.file:
            with open(args.file) as f:
                content = f.read().splitlines()
                content = '\n'.join(content)
                if content == "":
                    raise ValueError("File is empty")
                msg, addr, sig = parse_signed_message(content)
        else:
            print("Insert the signed Message (plaintext):")
            msg = sys.stdin.readline().rstrip()
            print("\nInsert the Message Signature (base64):")
            sig = sys.stdin.readline().rstrip()
            print("\nInsert the target Bitcoin address:")
            addr = sys.stdin.readline().rstrip()
            print("")
        vrf = verify_message(addr, sig, msg)
        vrf = "VERIFIED" if vrf == True else "NOT VERIFIED"
        print("Message \"%s\"\n%s for address %s" % (msg, vrf, addr))
    else:
        print("Specify an action with --sign or --verify")
        exit(1)

if __name__ == '__main__':
    main()
