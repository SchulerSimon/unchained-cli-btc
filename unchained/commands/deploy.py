# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007

from .base import Base
from .mylib.const import target_folder
import sys
import shutil
import os


class Deploy(Base):

    def run(self):
        copy_files()


def copy_files():
    unchained_dir = sys.argv[2]
    if unchained_dir[-1:] == '/':
        unchained_dir = unchained_dir[:-1]

    requirements = unchained_dir + '/unchained/standalone/requirements.txt'
    verify = unchained_dir + '/unchained/standalone/verify.py'
    mylib = unchained_dir + '/unchained/commands/mylib/'

    proof_dir = sys.argv[3]
    if proof_dir[-1:] == '/':
        proof_dir = proof_dir[:-1]
    id_dir = proof_dir + '/unchained-id.xml'
    proof_dir += '/unchained-proof.xml'

    target = sys.argv[4]
    if target[-1:] == '/':
        target = target[:-1]
    target += target_folder

    if os.path.exists(target):
        shutil.rmtree(target)

    shutil.copytree(mylib, target + 'mylib/',
                    ignore=shutil.ignore_patterns('__pycache__'))
    shutil.copy2(requirements, target)
    shutil.copy2(verify, target)
    shutil.copy2(proof_dir, target)
    shutil.copy2(id_dir, target)
