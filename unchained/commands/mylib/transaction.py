# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007

from blockcypher import get_transaction_details
from .const import *
from .utils import *
from typing import List
from binascii import hexlify, unhexlify
import hashlib
from hashlib import sha256
import base58
from ecdsa import VerifyingKey, SECP256k1
from bitcoin import deserialize


class BtcTransactionInput():
    '''
    one input of a transaction
    '''
    fields = [
        ('prev_hash', str),
        ('script', str),
        ('output_index', int)
    ]

    def __init__(self, prev_hash, script, output_index):
        self.prev_hash = prev_hash
        self.script = script
        self.output_index = output_index

    def pubkey(self):
        return get_pubkey_from_input(self)

    def r_s_sig(self):
        '''
        returns r, s, sig (==r[2:]+s of this input)
        '''
        len_r = int(self.script[8:10], 16)
        r = self.script[10:(10 + len_r * 2)]
        len_s = int(self.script[
            ((10 + len_r * 2) + 2):((10 + len_r * 2) + 4)], 16)
        s = self.script[
            ((10 + len_r * 2) + 4):(((10 + len_r * 2) + 4) + len_s * 2)]
        # sig = r(ohne 0x00) + s
        sig = r[2:] + s
        return r, s, sig


class BtcTransactionOutput():
    '''
    one output of a transaction
    '''
    fields = [
        ('script', str),
        ('value', int)
    ]

    def __init__(self, script, value):
        self.script = script
        self.value = value

    def get_addr(self):
        '''
        for more info look here: https://en.bitcoin.it/wiki/File:PubKeyToAddr.png
        '''
        rip = network_byte
        rip += self.script[6:-4]
        checksum = bin_double_sha256(unhexlify(rip)).hex()[:8]
        rip += checksum
        return str(base58.b58encode(unhexlify(rip)))[2:-1]


input_ = List[BtcTransactionInput]
output_ = List[BtcTransactionOutput]


class BtcTransaction():
    '''
    a transaction object, containing all information, aswell as two lists (inputs, outputs)
    '''
    fields = [
        ('block_hash', str),
        ('hash', str),
        ('hex', str),
        ('sig_hex', str),
        ('version', int),
        ('n_input', int),
        ('n_output', int),
        ('input', input_),
        ('output', output_)
    ]

    def __init__(self, hash_=None, version=None, n_input=0, n_output=0, input_=None, output_=None, block_hash=None, hex_=None):
        if hex_ == None:
            self.block_hash = block_hash
            self.hash = hash_
            self.hex = hex_
            self.version = version
            self.n_input = n_input
            self.n_output = n_output
            self.input = input_
            self.output = output_
        else:
            tx = deserialize(hex_)
            self.block_hash = None
            self.hex = hex_
            self.version = tx['version']
            self.input = [BtcTransactionInput(prev_hash=i['outpoint']['hash'], script=i[
                'script'], output_index=i['outpoint']['index']) for i in tx['ins']]
            self.n_input = len(self.input)
            self.output = [BtcTransactionOutput(
                script=i['script'], value=i['value']) for i in tx['outs']]
            self.n_output = len(self.output)
            self.hash = self.hash_()

    def hash_(self):
        '''
        returns the hash of this tx
        '''
        if not self.hex:
            self.hex = self.hex_()
        return reverse_data(bin_double_sha256(unhexlify(self.hex)).hex())

    def hex_(self):
        '''
        returns a hex-serialization of this tx
        '''
        if not self.hex:
            hex_ = reverse_data(format_len_hex(self.version, 4))
            hex_ += get_varint_str(self.n_input)
            for i in self.input:
                hex_ += reverse_data(i.prev_hash)
                hex_ += reverse_data(format_len_hex(i.output_index, 4))
                hex_ += get_varint_str(len(i.script) // 2)
                hex_ += i.script
            hex_ += 'ffffffff'  # who knows why... sequence, can be ignored
            hex_ += get_varint_str(self.n_output)
            for o in self.output:
                hex_ += reverse_data(format_len_hex(o.value, 8))
                hex_ += get_varint_str(len(o.script) // 2)
                hex_ += o.script
            hex_ += '00000000'
            self.hex = hex_
        return self.hex

    def verify_sig(self):
        '''
        verifies the tx-signature
        '''
        message = self.sig_hash().hex()
        for i in self.input:
            pubkey = decompress_pubkey(self.input[0].pubkey())[2:]
            _, _, sig = self.input[0].r_s_sig()
            vk = VerifyingKey.from_string(
                bytes.fromhex(pubkey), curve=SECP256k1)
            if not vk.verify(bytes.fromhex(sig), bytes.fromhex(message), hashlib.sha256):
                return False
        return True

    def sig_hash(self):
        '''
        returns the 'message' that is used to verify signature.
        Same as self.hex_() but replaced the inputscript with fundingscript for the address.
        '''
        hex_ = reverse_data(format_len_hex(self.version, 4))
        hex_ += get_varint_str(self.n_input)
        for i in self.input:
            hex_ += reverse_data(i.prev_hash)
            hex_ += reverse_data(format_len_hex(i.output_index, 4))
            new_script = get_funding_script_for_addr(
                get_addr_from_pubkey(i.pubkey()))
            hex_ += new_script.hex()
        hex_ += 'ffffffff'  # who knows why... sequence, can be ignored
        hex_ += get_varint_str(self.n_output)
        for o in self.output:
            hex_ += reverse_data(format_len_hex(o.value, 8))
            hex_ += get_varint_str(len(o.script) // 2)
            hex_ += o.script
        # append SIGHASH_ALL
        hex_ += '00000000' + '01000000'
        return bin_sha256(unhexlify(hex_))

    def get_all_input_pubkeys(self):
        temp = []
        for i in self.input:
            temp += [get_pubkey_from_input(i)]
        return temp


def get_pubkey_from_input(input_):
    '''
    gets pubkey from BtcTransactionInput object
    '''
    r, s, _ = input_.r_s_sig()
    return input_.script[(10 + len(r) + 4 + len(s)):][4:]


def get_r_s_from_script(script_str):
    '''
    parses the hex representation of a script to get r, s
    '''
    len_r = int(script_str[8:10], 16)
    r = script_str[10:(10 + len_r * 2)]
    len_s = int(script_str[
        ((10 + len_r * 2) + 2):((10 + len_r * 2) + 4)], 16)
    s = script_str[
        ((10 + len_r * 2) + 4):(((10 + len_r * 2) + 4) + len_s * 2)]
    return r[2:], s


def get_addr_from_pubkey(pubkey_str):
    '''
    convert pubkey to addr
    for more info look here: https://en.bitcoin.it/wiki/File:PubKeyToAddr.png
    '''
    rip = network_byte
    rip += bin_ripemd160(bin_sha256(unhexlify(pubkey_str))).hex()
    checksum = bin_double_sha256(unhexlify(rip)).hex()[:8]
    rip += checksum
    return base58.b58encode(unhexlify(rip))


def get_funding_script_for_addr(addr_b58):
    '''
    creates a fundingscript for a given address.
    '''
    hash160 = base58.b58decode(addr_b58)
    # slices are in bytes, so its not [2:-8]
    # aufbau von funding_script: size_script, op_dup, op_hash160, size_addr,
    # hash160_addr, op_eq, op_check
    return (bytes([0x19]) + bytes([OP_DUP]) + bytes([OP_HASH160]) +
            bytes([0x14]) + hash160[1:-4] + bytes([OP_EQUALVERIFY]) + bytes([OP_CHECKSIG]))


def get_varint_str(int_):
    '''
    implementation of bitcoin specific var(length)Int
    '''
    if int_ < 0xfc:
        return reverse_data(format_len_hex(int_, 1))
    elif int_ < 0xffff:
        return 'fd' + reverse_data(format_len_hex(int_, 2))
    elif int_ < 0xffffffff:
        return 'fe' + reverse_data(format_len_hex(int_, 4))
    elif int_ < 0xffffffffffffffff:
        return 'ff' + reverse_data(format_len_hex(int_, 8))
    else:
        raise ValueError('int too big for varInt')


def decompress_pubkey(compressed_pubkey: str):
    '''
    decompresses public key
    '''
    prefix = compressed_pubkey[0:2]
    compressed_pubkey = compressed_pubkey[2:]
    x = int(compressed_pubkey, 16)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    y_squared = (x**3 + 7) % p
    y = modular_sqrt(y_squared, p)
    y_str = "%x" % y
    y_is_even = (int(y_str[-1], 16) % 2 == 0)
    if prefix == "02" and y_is_even == False or prefix == "03" and y_is_even == True:
        y = p - y
        y_str = "%x" % y
    return "04" + compressed_pubkey + y_str


def modular_sqrt(a, p):
    '''
    returns the quadratic residue of x^2 == a (mod p),
    I could not find a library supporting this operation
    '''
    def legendre_symbol(a, p):
        ls = pow(a, (p - 1) // 2, p)
        return -1 if ls == p - 1 else ls

    if legendre_symbol(a, p) != 1:
        return 0
    elif a == 0:
        return 0
    elif p == 2:
        return p
    elif p % 4 == 3:
        return pow(a, (p + 1) // 4, p)
    s = p - 1
    e = 0
    while s % 2 == 0:
        s //= 2
        e += 1
    n = 2
    while legendre_symbol(n, p) != -1:
        n += 1
    x = pow(a, (s + 1) // 2, p)
    b = pow(a, s, p)
    g = pow(n, s, p)
    r = e
    while True:
        t = b
        m = 0
        for m in range(r):
            if t == 1:
                break
            t = pow(t, 2, p)

        if m == 0:
            return x
        gs = pow(g, 2 ** (r - m - 1), p)
        g = (gs * gs) % p
        x = (x * gs) % p
        b = (b * g) % p
        r = m


def make_transaction(tx_hash, api_key):
    '''
    creates a tx-object from a hex_hash
    '''
    tx = get_transaction_details(
        tx_hash, coin_symbol=coin_symbol, include_hex=True)
    inputs = tx['inputs']
    outputs = tx['outputs']
    # take all inputs/outputs
    inputs = [BtcTransactionInput(prev_hash=i['prev_hash'], script=i[
        'script'], output_index=i['output_index']) for i in inputs]
    outputs = [BtcTransactionOutput(script=o['script'], value=o[
        'value']) for o in outputs]

    return BtcTransaction(
        block_hash=tx['block_hash'],
        version=tx['ver'],
        hash_=tx['hash'],
        n_input=tx['vin_sz'],
        n_output=tx['vout_sz'],
        input_=inputs,
        output_=outputs
    )


def tx_from_hex(hex_):
    return BtcTransaction(hex_=hex_)

    # just used for testing.
if __name__ == '__main__':
    tx = make_transaction(
        'fa4c68d2d984468f51a95f44c2bbb6735046eda2d5c0a8c89b492716834365fe')
    print(tx.verify_sig())
    print(tx.hex_())
    print(tx.block_hash)
