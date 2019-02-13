import os
import setuptools
from distutils.core import setup

here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, 'README.md')) as f:
    README = f.read()


requires = [
    "scipy",
    "numpy==1.15.2",
    "fastecdsa",
    "sympy",
    "pyasn1",
    "ipython",
    "tqdm",
    "z3",
    "z3-solver"
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
          "Programming Language :: Python",
          "Programming Language :: Python :: 3.6",
      ],
      author='Daniel Cronce',
      author_email='daniel.cronce@wildcardcorp.com',
      keywords='cryptography security cryptanalysis',
      url="https://github.com/wildcardcorp/samson",
      packages=[
          "samson",
          "samson/ace",
          "samson/analyzers",
          "samson/attacks",
          "samson/auxiliary",
          "samson/block_ciphers",
          "samson/block_ciphers/modes",
          "samson/classical",
          "samson/constructions",
          "samson/encoding",
          "samson/encoding/jwk",
          "samson/encoding/openssh",
          "samson/kdfs",
          "samson/hashes",
          "samson/macs",
          "samson/oracles",
          "samson/padding",
          "samson/prngs",
          "samson/protocols",
          "samson/public_key",
          "samson/stream_ciphers",
          "samson/utilities"
      ],
      include_package_data=True,
      install_requires=requires)