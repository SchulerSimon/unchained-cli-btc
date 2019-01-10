# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007

from hashlib import sha256
from binascii import hexlify, unhexlify
import hashlib
import base58


def bin_sha256(bin_s):
    return sha256(bin_s).digest()


def bin_double_sha256(bin_s):
    return bin_sha256(bin_sha256(bin_s))


def bin_ripemd160(bin_s):
    return hashlib.new('ripemd160', bin_s).digest()


def hex_to_bin_reversed(s):
    return unhexlify(s.encode('utf8'))[::-1]


def bin_to_hex_reversed(s):
    return hexlify(s[::-1])


def hex_to_bin_reversed_hashes(hex_hashes):
    return [hex_to_bin_reversed(h) for h in hex_hashes]


def reverse_data(_data, hex_format=True):
    '''
    _data is in hex-str or binary, returns hex-str
    '''
    if not hex_format:
        _data = hexlify(_data)
    return ''.join(reversed([_data[i:i + 2] for i in range(0, len(_data), 2)]))


def format_len_hex(_int_or_str, _len):
    '''
    formats ints or hexstrings with leading zeros, outputs hexstring
    '''
    if type(_int_or_str) == str:
        temp = _int_or_str
    elif type(_int_or_str) == int:
        temp = hex(_int_or_str)[2:]
    else:
        raise ValueError('input must be int or hex_string')
    if len(temp) % 2 != 0:
        # make the input have even length
        temp = '0' + temp
    length = int(len(temp) / 2)
    missing = _len - length
    return '00' * missing + temp


def get_public_key_list(tx):
    '''
    this should only ever return a single entry list if the tx is accepted as unchained-worthy
    '''
    return [str(base58.b58encode(bytes.fromhex(key)))[2:-1] for key in tx.get_all_input_pubkeys()]
