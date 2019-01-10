unchained-cli-btc
=========

*A command line implementation of unchained-identities in Python for the Bitcoin Network.*

Purpose
-------
This is a Python implementation of the paper "Unchained Identities: Putting a 
Price on Sybil Nodes in Mobile Ad hoc Networks". 

http://filepool.informatik.uni-goettingen.de/publication/tmg/2018/bo_le_ho_unchained_securecomm2018.pdf

Usage
-----
**This whole project needs python3**

.. code:: bash

 $ unchained create <private_key_wif> <tx_hash_hex> <blockcypher_token> <path/for/proof>
  $ unchained verify <path/to/proof.xml>
  $ unchained deploy <path/to/unchained-identities/repo/folder> <path/to/proof-and-id/folder> <path/to/raspberry/dist/path/to/destination/folder>
  $ unchained -h | --help
  $ unchained --version

Example
-------
On the blockcypher(.com) testnetwork there is a transaction (hash: fa4c68d2d984468f51a95f44c2bbb6735046eda2d5c0a8c89b492716834365fe) of 1000 satoshi that is accepted as valid transaction. This can be taken to verify that everything is working.

.. code:: bash

 $ pip install .
  $ unchained create 9239Ht5evonDtUd8gNN4tgb7kXxnFQF3Ltb4m52oRMtsudx4NeP fa4c68d2d984468f51a95f44c2bbb6735046eda2d5c0a8c89b492716834365fe 93d4f219eeeb44e5aa469ff14a59a6ab ./example_proof/
  $ unchained verify ./example_proof/unchained-proof.xml

output: 
    {'nodeid': 'XSGts5+aavY+uRroHB7QM3CFJg7FFLmDVZo2XWXJfF0=', 'publickey': 'rKvRKA7hXsk9uJTiTo9u4WdF7aL7QR3ybH361NabNuoC'}
    True

Dependencies
------------
* blockcypher
* base58
* ecdsa
* docopt
* lxml

Installation
------------
If you've cloned this project, and want to install the library (*and all
development dependencies*), the command you'll want to run is

.. code:: bash

 $ cd unchained-cli-btc
  $ pip install .

You should consider using a clean python3 environment, this can be done with virtualenv:
https://virtualenv.pypa.io/en/stable/

Installation on a raspberry pi
-----
After You installed this tool, you can use it to install unchained-identities on a raspberry pi
It is recommended to use virtualenv.

* Flash a sd-card with raspbian (strech-lite is recommended)
* change the rights, so You can write on the sdcard:

.. code:: bash

 $ sudo chmod -R a+rwx /meidia/<user>/rootfs/home/pi/<some sub folder>

* * be sure to not run chmod -R on /media/<user>>/rootfs/ because it will mess up the raspberry os
* Run unchained deploy

.. code:: bash

 $ unchained deploy <path/to/unchained-identities/repo/folder> <path/to/proof-and-id/folder> <path/to/raspberry/dist/path/to/destination/folder>
 
* boot up the raspberry

Under /<destination-folder>/unchained-btc you can find 
    * 'verify.py' - the skript that verifies proofs
    * 'unchained-proof.xml' - the proof for this node
    * 'unchained-id.xml' - the id for this node (contains private key, be carefull)
    * 'requirements.txt' - requirements for pip
    
* install python3 on the raspberry
* run 

.. code:: bash

 $ pip install -r /path/to/requirements.txt

* now You can try to verify Your own proof with

.. code:: bash

 $ python3 verify.py unchained-proof.xml

* output should be True
* Done

* if You get the error, that the import "from lxml import etree" is not working try installing lxml with 

.. code:: bash

 $ apt-get install python3-lxml

Configuration
-----
under <repo>/unchained/commands/mylib/ is a file called const.py

There are some options to custamize how this tool behaves, they are explained there.

Notes
-----
There is also a version of this Project for ethereum: https://github.com/SchulerSimon/unchained-cli-eth

please note that due to naming reasons it is not possible to install and run both versions in the same python3 environment on a PC (use virtualenv: https://virtualenv.pypa.io/en/stable/). Both versions can run alongside eachother on a pi.

this was implemented by Simon Schuler (schuler.simon@gmx.net)

Performance Measures
-----
Bitcoin:
    * Proof size (depending on blocksize): 
    * * ~10kb-50kb
    * Verify proof time on a raspberry pi 3:
    * * ~2 sec
    * Create proof time on desktop intel i7 quadcore
    * * ~1 sec

Ethereum:
    * Proof size (depending on blocksize): 
    * * ~50kb-150kb
    * Verify proof time on a raspberry pi 3:
    * * ~60 sec (!!)
    * Create proof time on desktop intel i7 quadcore
    * * ~10 sec (dependent on the speed of the provided rpc)


All in all we can say that the Bitcoin-Network has superior performance properties for IOT-devices. This is due to the deliberate design of the Ethereum hash function ethash. See: https://github.com/ethereum/wiki/wiki/Ethash-Design-Rationale
