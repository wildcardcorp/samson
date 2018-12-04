import os
import setuptools
from distutils.core import setup

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()


# see requirements.txt for requirements
requires = [
    "scipy",
    "fastecdsa",
    "sympy",
    "pyasn1"
]

tests_require = [
]

setup(name='samson-crypto',
      version=__import__('samson').VERSION,
      description='Cryptanalysis and attack framework',
      scripts=['scripts/samson'],
      long_description=README,
      classifiers=[
          "Topic :: Security",
          "Topic :: Security :: Cryptography",
          "Programming Language :: Python",
          "Programming Language :: Python :: 3.6",
      ],
      author='Daniel Cronce',
      author_email='daniel.cronce@wildcardcorp.com',
      keywords='cryptography security cryptanalysis',
      url="https://github.com/wildcardcorp/samson",
      packages=[
          "samson",
          "samson/analyzers",
          "samson/attacks",
          "samson/auxiliary",
          "samson/block_ciphers",
          "samson/classical",
          "samson/constructions",
          "samson/kdfs",
          "samson/hashes",
          "samson/macs",
          "samson/oracles",
          "samson/padding",
          "samson/prngs",
          "samson/protocols",
          "samson/publickey",
          "samson/stream_ciphers",
          "samson/utilities"
      ],
      include_package_data=True,
      install_requires=requires)