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
* PRNG Attacks
    * MT19937 cloning
* Text analyzers
    * English
* Optimization algorithms
    * Grey Wolf Metaheuristic Optimizer
* Markov chain generator
* Common functions in cryptography


## Environment
* **Runtime**: Python 3.6.6
* **Architecture**: Linux 4.16.3-301.fc28.x86_64 #1 SMP Mon Apr 23 21:59:58 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
* **OS**: Fedora Security Lab (Fedora release 28)