# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007

from .const import *
from .utils import *
import blockcypher as bc
from binascii import hexlify, unhexlify


class BtcBlock():
    fields = [
        ('n_version', str),
        ('prev_block_hash', str),
        ('merkle_root', str),
        ('datetime', str),
        ('current_target', str),
        ('nonce', str),
        ('txs', list),
        ('hex_str', str),
        ('hash', str)
    ]

    def __init__(self, version=None, prev_block=None, merkle_root=None, datetime=None,
                 current_target=None, nonce=None, txs=None, hex_str=None, hash_=None):
        if hex_str == None:
            self.n_version = version
            self.prev_block_hash = prev_block
            self.merkle_root = merkle_root
            self.datetime = str(hex(int(datetime.timestamp())))[2:]
            self.current_target = current_target
            self.nonce = nonce
        else:
            self.n_version = int(reverse_data(hex_str[:8]), 16)
            self.prev_block_hash = reverse_data(hex_str[8:72])
            self.merkle_root = reverse_data(hex_str[72:136])
            self.datetime = reverse_data(hex_str[136:144])
            self.current_target = reverse_data(hex_str[144:152])
            self.nonce = reverse_data(hex_str[152:])
        self.txs = txs
        self.hex_str = hex_str
        self.hash = hash_

    def hex_(self):
        if not self.hex_str:
            block_hex = reverse_data(
                format_len_hex('0' + str(self.n_version), 4))
            block_hex += reverse_data(self.prev_block_hash)
            block_hex += reverse_data(self.merkle_root)
            block_hex += reverse_data(self.datetime)
            block_hex += reverse_data(format_len_hex(self.current_target, 4))
            block_hex += reverse_data(
                format_len_hex(str(hex(self.nonce))[2:], 4))
            self.hex_str = block_hex
        return self.hex_str

    def hash_(self):
        if not self.hash:
            self.hash = reverse_data(
                bin_double_sha256(unhexlify(self.hex_())).hex())
        return self.hash

    def create_merkle_root(self):
        return str(calculate_merkle_root(self.txs))[2:-1]

    def get_all_tx_ids(self):
        return self.txs


def calculate_merkle_pairs(bin_hashes, hash_function=bin_double_sha256):
    ''' 
    takes in a list of binary hashes, returns a binary hash
    '''
    hashes = list(bin_hashes)
    # if there are an odd number of hashes, double up the last one
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    # build the new list of hashes
    new_hashes = []
    for i in range(0, len(hashes), 2):
        new_hashes.append(hash_function(hashes[i] + hashes[i + 1]))
    # return the new list of hashes
    return new_hashes


def calculate_merkle_root(hashes, hash_function=bin_double_sha256,
                          hex_format=True):
    ''' 
    takes in a list of binary hashes, returns a binary hash
    '''
    if hex_format:
        hashes = hex_to_bin_reversed_hashes(hashes)
    # keep moving up the merkle tree, constructing one row at a time
    while len(hashes) > 1:
        hashes = calculate_merkle_pairs(hashes, hash_function)
    # get the merkle root
    merkle_root = hashes[0]
    # if the user wants the merkle root in hex format, convert it
    if hex_format:
        return bin_to_hex_reversed(merkle_root)
    # return the binary merkle root
    return merkle_root


def make_block(block_hash, api_token):
    b = bc.get_block_overview(
        block_hash, coin_symbol=coin_symbol, api_key=api_token)
    return BtcBlock(
        version=b['ver'],
        prev_block=b['prev_block'],
        merkle_root=b['mrkl_root'],
        datetime=b['received_time'],
        current_target=b['bits'],
        nonce=b['nonce'],
        txs=b['txids']
    )


def block_from_hex(hex_):
    return BtcBlock(hex_str=hex_)

    # debug
if __name__ == '__main__':
    block = make_block(
        '000055f67563d1c2cb141d06d52d2fca63ef457c553519aeb635a2643a9af0b1')
    print(block.hex_())
    print(block.hash_())
    print(block.txs)
    print(block.create_merkle_root())
