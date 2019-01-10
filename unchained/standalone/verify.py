# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007

from mylib.const import *
from mylib.transaction import *
from mylib.block import *
from lxml import etree
import sys
from binascii import hexlify, unhexlify
import hmac
from base64 import (
    b64decode,
    b64encode,
)


def run(path):
    try:
        xml_doc = etree.parse(path)
    except Exception as e:
        print(e)
        print(False)
        exit(1)

    if not validate_structure(xml_doc):
        print(e)
        print(False)
        exit(1)

    block, tx, tx_hash_list, index, nodeid, key = parse_user_input_verify(
        xml_doc)
    # key = strip_string(key)

    if not verify_tx_hash_and_transaction_trie(tx, block, tx_hash_list, index):
        print(False)
        exit(1)

    if not verify_block_difficulty(block):
        print(False)
        exit(1)

    if not verify_difficulty_against_network_target(block):
        print(False)
        exit(1)

    if not verify_tx_details_and_signature(tx, key):
        print(False)
        exit(1)

    if not verify_node_id(block, index, nodeid):
        print(False)
        exit(1)

    info = {
        'nodeid': nodeid,
        'publickey': key
    }

    print(info)
    print(True)


def validate_structure(xml_doc) -> bool:
    xmlschema = etree.XMLSchema(etree.XML(xsd))
    return xmlschema.validate(xml_doc)


def parse_user_input_verify(xml_doc):
    block = deserialize_block(
        str(xml_doc.xpath('//root/proof/block/text()'))[2:-2])

    tx = deserialize_tx(
        str(xml_doc.xpath('//root/proof/transaction/text()'))[10:-20])

    tx_hash_list = str(xml_doc.xpath(
        '//root/proof/trie/text()'))[2:-2].split(sep1)

    index = int(str(xml_doc.xpath(
        '//root/proof/transaction/index/text()'))[2:-2])

    nodeid = str(xml_doc.xpath('//root/proof/nodeinfo/nodeid/text()'))[2:-2]

    public_key = str(xml_doc.xpath('//root/proof/nodeinfo/publickey/text()'))

    return block, tx, tx_hash_list, index, nodeid, public_key[2:-2]


def verify_tx_hash_and_transaction_trie(tx, block, tx_hash_list, index):
    '''
    checks weather the tx-hash is in the tx_list, 
    and checks if merkle_root of that block is correct
    when tx_hash is in tx_list
    '''
    if not tx.hash_() in tx_hash_list:
        return False
    if not str(calculate_merkle_root(tx_hash_list))[2:-1] == block.merkle_root:
        return False
    if not tx_hash_list.index(tx.hash_()) == index:
        return False
    return True


def verify_block_difficulty(block):
    '''
    uses the formula (1byte exponent, 2bytes mantissa) 
    mantissa * ( 2**(8 * exponent - 3))
    from the blockchain wiki to decompress the target 
    and test it against blockhash
    '''
    target = int(block.current_target[2:], 16) * \
        (2**(8 * (int(block.current_target[:2], 16) - 3)))
    hash_ = int(block.hash_(), 16)
    if not target >= hash_:
        return False
    return True


def verify_difficulty_against_network_target(block):
    if not difficulty_network_target >= int(block.hash_(), 16):
        return False
    return True


def verify_tx_details_and_signature(tx, key):
    '''
    1. check that there is only one input
    2. check that the tx was signed using provided key
    3. check that the signature is correct
    4. check that tx has donation output
    5. check that outpu.value satisfies unchained-requirements 
    '''
    list_ = get_public_key_list(tx)
    if not len(list_) == 1:
        return False
    if not list_[0] == key:
        return False
    if not tx.verify_sig():
        return False
    output = get_donation(tx)
    if not output:
        return False
    if not int(output.value) >= value_network_target:
        return False
    return True


def verify_node_id(block, index, nodeid):
    blockhash = unhexlify(block.hash_())
    tx_index = bytes([index])
    dig = hmac.new(blockhash, msg=tx_index,
                   digestmod=hashlib.sha256).digest()
    return nodeid == b64encode(dig).decode()


def get_donation(tx):
    for o in tx.output:
        if o.get_addr() in donation_addresses:
            return o
    return None


def deserialize_block(hex_):
    return block_from_hex(hex_)


def deserialize_tx(hex_):
    return tx_from_hex(hex_)


if __name__ == "__main__":
    run(sys.argv[1:][0])
