import os
import setuptools
from distutils.core import setup

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md'), encoding="utf-8") as f:
    README = f.read()

requires = [
    "pyasn1>=0.4.8",
    "pyasn1-modules",
    "ipython",
    "tqdm",
    "z3-solver",
    "sortedcontainers",
    "rich",
    "dill"
]

tests_require = [
]

setup(name='samson-crypto',
      version=__import__('samson').VERSION,
      description='Cryptanalysis and attack library',
      scripts=['scripts/samson', 'scripts/samson-py'],
      long_description=README,
      long_description_content_type='text/markdown',
      classifiers=[
          "Topic :: Security",
          "Topic :: Security :: Cryptography",
          "Topic :: Scientific/Engineering",
          "Topic :: Scientific/Engineering :: Mathematics",
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.6",
          "Programming Language :: Python :: Implementation :: CPython",
          "Programming Language :: Python :: Implementation :: PyPy",
      ],
      author='Daniel Cronce',
      author_email='daniel.cronce@wildcardcorp.com',
      keywords='cryptography security cryptanalysis',
      url="https://github.com/wildcardcorp/samson",
      data_files = [
          ('man/man1', ['man/artifacts/samson.1']),
          ('/etc/bash_completion.d', ['scripts/samson-autocomplete.sh'])
        ],
      packages=[
          "samson",
          "samson/ace",
          "samson/analysis",
          "samson/analyzers",
          "samson/attacks",
          "samson/auxiliary",
          "samson/block_ciphers",
          "samson/block_ciphers/modes",
          "samson/classical",
          "samson/constructions",
          "samson/core",
          "samson/encoding",
          "samson/encoding/dns_key",
          "samson/encoding/jwk",
          "samson/encoding/openssh",
          "samson/encoding/openssh/core",
          "samson/encoding/pkcs1",
          "samson/encoding/pkcs8",
          "samson/encoding/x509",
          "samson/kdfs",
          "samson/hashes",
          "samson/macs",
          "samson/math",
          "samson/math/factorization",
          "samson/math/algebra",
          "samson/math/algebra/curves",
          "samson/math/algebra/fields",
          "samson/math/algebra/rings",
          "samson/oracles",
          "samson/padding",
          "samson/prngs",
          "samson/protocols",
          "samson/protocols/jwt",
          "samson/public_key",
          "samson/stream_ciphers",
          "samson/utilities"
      ],
      include_package_data=True,
      install_requires=requires)