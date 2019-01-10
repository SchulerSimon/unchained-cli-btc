"""
unchained-identities-cli

This is a command line implementation of the creation tool for unchained-identities described in the paper
"Unchained Identities: Putting a Price on Sybil Nodes in Mobile Ad hoc Networks" by
Prof. Dr. Dieter Hogrefe, M.Sc. Arne Bochem and M.Sc. Bejmain Leiding.

Usage:
  unchained create <private_key_wif> <tx_hash_hex> <blockcypher_token> <path/for/proof>
  unchained verify <path/to/proof.xml>
  unchained deploy <path/to/unchained-identities/repo/folder> <path/to/proof-and-id/folder> <path/to/raspberry/dist/path/to/destination/folder>
  unchained -h | --help
  unchained --version

Options:
  -h --help                         Show this screen.
  --version                         Show version.

Examples:
  unchained create 9239Ht5evonDtUd8gNN4tgb7kXxnFQF3Ltb4m52oRMtsudx4NeP fa4c68d2d984468f51a95f44c2bbb6735046eda2d5c0a8c89b492716834365fe 93d4f219eeeb44e5aa469ff14a59a6ab
  unchained verify ./proof.xml
  unchained deploy ./proof.xml /sdcard/root/unchained/python

Help:
  For help using this tool, please write an Email to s.schuler@stud.uni-goettingen.de

Mentions:
  For this CLI the Template from
  <https://stormpath.com/blog/building-simple-cli-interfaces-in-python>
  was used.
"""


from inspect import getmembers, isclass

from docopt import docopt

from unchained import __version__ as VERSION


def main():
    """Main CLI entrypoint."""
    import unchained.commands
    options = docopt(__doc__, version=VERSION)
    # Here we'll try to dynamically match the command the user is trying to run
    # with a pre-defined command class we've already created.
    for (k, v) in options.items():
        if hasattr(unchained.commands, k) and v:
            module = getattr(unchained.commands, k)
            unchained.commands = getmembers(module, isclass)
            command = [c for c in unchained.commands if
                       c[0].lower() == k.lower()][0][1]
            command = command(options)
            command.run()
