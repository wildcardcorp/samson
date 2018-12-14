# samson

### **DO NOT USE SAMSON'S CRYPTOGRAPHIC PRIMITIVES TO SECURE THINGS**

samson is a cryptanalysis and attack framework. The intent is to provide a way to quickly prototype and execute cryptographic and side-channel attacks. samson was born from frustration with existing libraries artificially limiting user control over cryptographic primitives.

Many of the biggest cryptographic attacks have been implemented including:
* CBC Padding Oracle
* PKCS#1v1.5 Padding Oracle
* CRIME/BREACH
* DSA/ECDSA key reuse
* Stream cipher nonce reuse
* Merkle-Damgard Length Extension
* PRNG cracking

samson's key focuses are:
* _Flexibility_: Allow the user to freely manipulate internal state
* _Uniformity_: Present the user with a uniform interface
* _Convenience_: Minimize time spent not directly solving a problem
* _Real world applicability_: Build attacks to work generically and include interfaces to common standards

## Example Use Cases
* Auditing infrastructure
* Modelling existing systems
* Solving/creating CTFs


## Testing Environment
* **Runtime**: Python 3.6.7
* **Architecture**: Linux 4.18.17-200.fc28.x86_64 #1 SMP Mon Nov 5 18:04:28 UTC 2018 GNU/Linux
* **OS**: Fedora Security Lab (Fedora release 28)


## Installation
### RHEL derivatives
```bash
sudo dnf -y install python3-devel gmp-devel redhat-rpm-config
pip3 install samson-crypto
```


## Performance
Samson's primitives aren't the fastest nor were they meant to be. If you're concerned about performance, you have a couple of options:

* Use primitives from a faster library (e.g. pycrypto)
* Use PyPy instead of CPython

Since samson mostly calls Python, PyPy offers large speed-ups. However, `multiprocessing` doesn't work very well with PyPy. There seems to be a memory leak, and sometimes bytes are unpickled as strings. I recommend against running the RC4 prepend attack with PyPy as it uses `multiprocessing`. Additionally, the latest stable version of PyPy works with Python 3.5 while SHA3 was introduced in 3.6. samson's SHA3 will still work, but the tests will fail.