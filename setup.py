"""Packaging settings."""


from codecs import open
from os.path import abspath, dirname, join
from subprocess import call

from setuptools import Command, find_packages, setup

from unchained import __version__


this_dir = abspath(dirname(__file__))
with open(join(this_dir, 'README.rst'), encoding='utf-8') as file:
    long_description = file.read()


class RunTests(Command):
    """Run all tests."""
    description = 'run tests'
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        """Run all tests!"""
        errno = call(['py.test', '--cov=unchained',
                      '--cov-report=term-missing'])
        raise SystemExit(errno)


setup(
    name='unchained',
    version=__version__,
    description='A command line implementation of unchained-identities in Python.',
    long_description=long_description,
    url='https://gitlab.gwdg.de/s.schuler/unchained-cli-btc',
    author='Simon Schuler',
    author_email='schuler.simon@gmx.net',
    license='GNU GENERAL PUBLIC LICENSE Version 3, 29 June 2007',
    classifiers=[
        'Intended Audience :: Developers',
        'Topic :: Utilities',
        'License :: GNUv3',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.6',
    ],
    keywords='cli, unchained, unchained-identities, bitcoin',
    packages=find_packages(exclude=['docs', 'tests*']),
    install_requires=['docopt', 'blockcypher', 'base58', 'ecdsa', 'lxml'],
    extras_require={
        'test': ['coverage', 'pytest', 'pytest-cov'],
    },
    entry_points={
        'console_scripts': [
            'unchained=unchained.cli:main',
        ],
    },
    cmdclass={'test': RunTests},
)
