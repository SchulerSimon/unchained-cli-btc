# This software is licensed under the GNU GENERAL PUBLIC LICENSE
# Version 3, 29 June 2007
'''The base command.'''


class Base(object):
    '''A base command.'''

    def __init__(self, options, *args, **kwargs):
        self.options = options
        self.args = args
        self.kwargs = kwargs

    def run(self):
        raise NotImplementedError(
            'You must implement the run() method yourself!')
