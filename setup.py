import os
from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()


# see requirements.txt for requirements
requires = [
    "pycrypto",
    "scipy",
    "sklearn",
    "fastecdsa",
    "sympy"
]

tests_require = [
]

setup(name='samson',
      version='0.0.1',
      description='Cryptanalysis and attack framework',
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
          "samson/hashes",
          "samson/oracles",
          "samson/prngs",
          "samson/protocols",
          "samson/publickey",
          "samson/stream_ciphers",
          "samson/utilities"
      ],
      include_package_data=True,
      install_requires=requires)