# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007

from .base import Base
from .mylib.transaction import *
from .mylib.block import *
import sys
import hmac
from base64 import (
    b64decode,
    b64encode,
)
from xml.etree import ElementTree
from xml.etree.ElementTree import Element, SubElement, Comment
from xml.dom import minidom
import base58


class Create(Base):

    def run(self):
        block, tx, private_key, path = parse_user_input_create()
        if not len(tx.input) == 1:
            print(error_no_multisig)
            exit(1)

        if not tx.verify_sig():
            print(error_wrong_key)
            exit(1)

        tx_index = block.txs.index(tx.hash_())

        nodeid = create_node_id(block.hash_(), tx_index)

        public_key_list = get_public_key_list(tx)
        # make sure that tx that is not signed with a multisig_addr
        if not len(public_key_list) == 1:
            print(error_no_multisig)
            exit(1)

        public_key_str = str(public_key_list)[2:-2]

        block_str = block.hex_()

        tx_str = tx.hex_()

        merkle_trie_str = serialize_list(block.get_all_tx_ids())

        xml = make_proof_xml(
            block_str, tx_str, merkle_trie_str, tx_index, nodeid, public_key_str)

        try:
            file = open(path + name_proof_file, 'w')
            file.write(xml)
            file.close()
        except Exception as e:
            print(e)
            exit(1)

        xml = make_nodeid_xml(nodeid, public_key_str, private_key)

        try:
            file = open(path + name_id_file, 'w')
            file.write(xml)
            file.close()
        except Exception as e:
            print(e)
            exit(1)


def parse_user_input_create():
    args = sys.argv[2:]
    private_key = args[0]
    tx_hash = args[1]
    api_key = args[2]
    path = args[3]

    if path[-1:] == '/':
        path = path[:-1]

    try:
        tx = make_transaction(tx_hash, api_key)
    except Exception as e:
        print(e)
        exit(1)

    try:
        block = make_block(tx.block_hash, api_key)
    except Exception as e:
        print(e)
        exit(1)

    return block, tx, private_key, path


def prettify_xml(elem) -> str:
    '''Return a pretty-printed XML string for the Element'''
    rough_string = ElementTree.tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


def create_node_id(blockhash: str, tx_index: int) -> str:
    '''calculates the nodeid as nid=HMAC(k_HMAC,TX_index)'''
    blockhash = unhexlify(blockhash)
    tx_index = bytes([tx_index])
    dig = hmac.new(blockhash, msg=tx_index,
                   digestmod=hashlib.sha256).digest()
    return b64encode(dig).decode()


def serialize_list(list_):
    return sep1.join(list_)


def make_proof_xml(block_str, tx_str, trie_str, tx_index, nodeid_str, public_key):
    root = Element('root')
    comment = Comment(text_proof_comment)
    root.append(comment)

    proof = SubElement(root, 'proof')

    block = SubElement(proof, 'block')
    block.text = block_str

    transaction = SubElement(proof, 'transaction')
    transaction.text = tx_str
    index = SubElement(transaction, 'index')
    index.text = str(tx_index)

    trie = SubElement(proof, 'trie')
    trie.text = trie_str

    nodeinfo = SubElement(proof, 'nodeinfo')

    nodeid = SubElement(nodeinfo, 'nodeid')
    nodeid.text = str(nodeid_str)

    publickey = SubElement(nodeinfo, 'publickey')
    publickey.text = public_key

    return prettify_xml(root)


def make_nodeid_xml(nodeid_str, public_key, private_key):
    root = Element('root')
    comment = Comment(text_nodeid_comment)
    root.append(comment)

    nodeinfo = SubElement(root, 'nodeinfo')

    nodeid = SubElement(nodeinfo, 'nodeid')
    nodeid.text = str(nodeid_str)

    publickey = SubElement(nodeinfo, 'publickey')
    publickey.text = public_key

    privatekey = SubElement(nodeinfo, 'privatekey')
    warning = Comment(text_private_key_warning)
    privatekey.append(warning)
    privatekey.text = private_key

    return prettify_xml(root)
