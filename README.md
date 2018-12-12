# Samson

Samson is a cryptanalysis and attack framework. The intent is to provide a way to quickly prototype and execute cryptographic and side-channel attacks.


### **DO NOT USE SAMSON'S CRYPTOGRAPHIC PRIMITIVES TO SECURE THINGS**

Includes:
* Block cipher attacks
    * ECB
        * Prepend attack
    * CBC
        * Padding oracle attack
        * CBC/IV key equivalence attack
* Stream cipher attacks
    * ARC4
        * Prepend attack
    * CTR/OTP
        * Nonce-reuse plaintext recovery
* PKI attacks
    * RSA
        * PKCS15 Padding Oracle
        * CRT factorization
        * Shared-`p` factorization
    * DSA/ECDSA
        * `k`-reuse derivation
        * Private key derivation from `k`
* Hash attacks
    * Merkle-Damgard Length Extension
    * Iterated-hash multicollision
    * Nostradamus attack
* PRNG Attacks
    * MT19937 cloning
* Other side-channel attacks
    * CRIME
* Text analyzers
    * English
* Optimization algorithms
    * Grey Wolf Metaheuristic Optimizer
* Markov chain generator
* Common functions in cryptography


## Environment
* **Runtime**: Python 3.6.7
* **Architecture**: Linux 4.16.3-301.fc28.x86_64 #1 SMP Mon Apr 23 21:59:58 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
* **OS**: Fedora Security Lab (Fedora release 28)


## Installation
RHEL derivatives
```bash
sudo dnf -y install python3-devel gmp-devel redhat-rpm-config
pip3 install samson-crypto
```


## Performance
Samson's primitives aren't the fastest nor were they meant to be. If you're concerned about performance, you have a couple of options:

* Use primitives from a faster library (e.g. pycrypto)
* Use PyPy instead of CPython

Since samson mostly calls Python, PyPy offers large speed-ups. However, `multiprocessing` doesn't work very well with PyPy. There seems to be a memory leak, and sometimes bytes are unpickled as strings. I recommend against running the RC4 prepend attack with PyPy as it uses `multiprocessing`. Additionally, the latest stable version of PyPy works with Python 3.5 while SHA3 was introduced in 3.6. samson's SHA3 will still work, but the tests will fail.