# samson

### **DO NOT USE SAMSON'S CRYPTOGRAPHIC PRIMITIVES TO SECURE THINGS**

samson is a cryptanalysis and attack library. The intent is to provide a way to quickly prototype and execute cryptographic and side-channel attacks. samson was born from frustration with existing libraries artificially limiting user control over cryptographic primitives.

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


## Examples
### **REPL**
```bash
[root@localhost ~]# samson


                                                                
  /$$$$$$$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$$  /$$$$$$  /$$$$$$$ 
 /$$_____/ |____  $$| $$_  $$_  $$ /$$_____/ /$$__  $$| $$__  $$
|  $$$$$$   /$$$$$$$| $$ \ $$ \ $$|  $$$$$$ | $$  \ $$| $$  \ $$
 \____  $$ /$$__  $$| $$ | $$ | $$ \____  $$| $$  | $$| $$  | $$
 /$$$$$$$/|  $$$$$$$| $$ | $$ | $$ /$$$$$$$/|  $$$$$$/| $$  | $$
|_______/  \_______/|__/ |__/ |__/|_______/  \______/ |__/  |__/
                                                                
                                                                
                                                                
    v0.1.0 -- https://github.com/wildcardcorp/samson

Python 3.6.7 (default, Nov 23 2018, 12:11:28) 
[GCC 8.2.1 20181105 (Red Hat 8.2.1-5)]
IPython 6.5.0


In [1]: RC4(b'what a key!').generate(12) ^ b'Hello world!'
Out[1]: <Bytes: b')\x1f\xb8xW}\xfc\xc5,\x0f\xc3,', byteorder=big>

In [2]: gcm = GCM(Rijndael(Bytes.random(32)).encrypt)
   ...: data = b"Auth'd data"
   ...: nonce = Bytes.random(8)
   ...: ciphertext = gcm.encrypt(nonce=nonce, plaintext=b'Hello world!', data=data)
   ...: gcm.decrypt(nonce, ciphertext, data)
   ...: 
   ...: 
Out[2]: <Bytes: b'Hello world!', byteorder=big>

In [3]: bf = Blowfish(b"world's worst key")
   ...: cbc = CBC(bf.encrypt, bf.decrypt, block_size=8, iv=Bytes.random(8))
   ...: 
   ...: def oracle_func(attempt):
   ...:     try:
   ...:         PKCS7().unpad(cbc.decrypt(attempt, unpad=False), allow_padding_oracle=True)
   ...:         return True
   ...:     except Exception as _:
   ...:         return False
   ...: 
   ...: 
   ...: ciphertext = cbc.encrypt(b'secret plaintext')
   ...: attack = CBCPaddingOracleAttack(PaddingOracle(oracle_func), block_size=8, iv=cbc.iv)
   ...: recovered_plaintext = attack.execute(ciphertext)
   ...: 
   ...: 
2018-12-17 16:24:03,152 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Starting iteration 0
2018-12-17 16:24:03,152 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x01'
2018-12-17 16:24:03,153 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,154 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,155 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,156 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,156 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,157 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,158 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,159 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'\x08'
2018-12-17 16:24:03,159 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Starting iteration 1
2018-12-17 16:24:03,168 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b't'
2018-12-17 16:24:03,176 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'x'
2018-12-17 16:24:03,183 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'e'
2018-12-17 16:24:03,191 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b't'
2018-12-17 16:24:03,199 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'n'
2018-12-17 16:24:03,206 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'i'
2018-12-17 16:24:03,213 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'a'
2018-12-17 16:24:03,220 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'l'
2018-12-17 16:24:03,220 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Starting iteration 2
2018-12-17 16:24:03,228 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'p'
2018-12-17 16:24:03,230 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b' '
2018-12-17 16:24:03,239 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b't'
2018-12-17 16:24:03,246 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'e'
2018-12-17 16:24:03,254 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'r'
2018-12-17 16:24:03,261 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'c'
2018-12-17 16:24:03,268 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b'e'
2018-12-17 16:24:03,276 - samson.attacks.cbc_padding_oracle_attack [DEBUG] Found working byte: b's'

In [4]: recovered_plaintext
Out[4]: <Bytes: b'secret plaintext\x08\x08\x08\x08\x08\x08\x08\x08', byteorder=big>
```

### **CLI**
```bash
[root@localhost ~]# samson hash md5 texttohash
0d7e83711c9c8efa135653ef124cc23b

[root@localhost ~]# echo -n "texttohash" | samson hash md5
0d7e83711c9c8efa135653ef124cc23b

[root@localhost ~]# samson hash blake2b texttohash
de92a99c2d5cb8386cada3589b7c70efa27c6d99a3ec1a2f9313258c0e91229f2279ccf68d6766aa20d124ca415dacbb89fb657013de1a2009752084186445a7

[root@localhost ~]# samson hash keccak texttohash --args=r=1044,c=512,digest_bit_size=256
1a568ef9ead0b2a9eeffc1d1e9a688c9153f33719ac5b30a533d1edba0e301b8

[root@localhost ~]# samson pki generate rsa --args=bits=1024
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQChL/Xmka6z8EEiwNC+NXrEs1WHFjUz364hPfFlOMVAmrrWHsAls71U+6
5VybjZPpYOBGcr/M2C6al9W7y18fkf3gAZhfPLvat8OpsfM+ltmlLJ3kTLiVJo2Y+KTPNz
I9nrKUgD/KEcL73kvwJGYL+YwX8YNcbxKv5rNxB0kdW33wIDAQABAoGBAJhMe7ie4AZutO
zEaLfASj6+/8oC5sQbzijkoUi16lLPoEeeiIlXGkbJA4FVd430/81AxccfN4NBin7DBjyX
5H2BmsN3rPGnsCKC+uY4z2+er7B+i2YHgF1K5ymC/8pFV5eU5GTVF0FxZHtviLhDA0p8Fh
liii2JNpM2MDgj7j9BAkEAuzKx+nspNtH+myjMHMRkswLiMIQ8VonOXmH6aBnQekzYvAmy
nCbSlbYohxCYjrPy+a76siSIGK+SO8YpxG7MIQJBANxt8S+ZnrmPZKoWEu3pcn95Fa26Up
qz2L2YemqRid6BlE2/2+cLYMVglEUfhgrqvNCFbwqc1UgeK47065iUA/8CQExZE7+uBZQn
N2k+zWiaLNvZvDi/ZgCBedqCqWdVx/JpbyfZ6K/JIbAPuB3GBgKFn/53gCWxwpQW31RjsN
s9uSECQQDOpkN2XI5xZ/z3d7pHUJQG7X1lYUgPwItxM4GQZuDZuKFQQo3mDMSsRd667tK7
aVWaJ33ydRV+hspPO02jvSABAkAPaMHmQcEN8c8bOWc5VjH8kxcV5iHUw88WH9hEKpHTsk
j+LYTu11aOZXFh4dmw5jHd1gjA4bD24c0f5NN7vQLJ
-----END RSA PRIVATE KEY-----


[root@localhost ~]# samson pki generate rsa --args=bits=128,p=7
-----BEGIN RSA PRIVATE KEY-----
MD0CAQACCQRsJXO1QfNPyQIDAQABAgkCcRw0yU5C5DUCAQcCCQChvDUZ5NmdrwIBBQIJAI
vnlXuftgsrAgEC
-----END RSA PRIVATE KEY-----

[root@localhost ~]# samson pki generate rsa --args=bits=256 --pub
-----BEGIN PUBLIC KEY-----
MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAKItLmP4OG4LIOgWZRt+MFOifSHsoow9NcwAwt
p3Xx0NAgMBAAE=
-----END PUBLIC KEY-----

[root@localhost ~]# samson pki generate ecdsa --args=curve=nistp256
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIJi3UXr8EQ5YtBs3Av55J9mFTcgHdd4ZI8VNi62dwA0xoAoGCCqGSM49AwEHoU
QDQgAEHDlmxAnUm6yFJrp7lfzipJPWhYoc3uL1a9q+/6c8AiICIBPBkfkxhttBF9DdT3U3
XmtOsZIPWcYxT68yomeTvw==
-----END EC PRIVATE KEY-----

[root@localhost ~]# openssl genrsa 128 | samson pki parse rsa
Generating RSA private key, 128 bit long modulus
.+++++++++++++++++++++++++++
..+++++++++++++++++++++++++++
e is 65537 (0x010001)
<RSA: bits=128, p=18204634713468071783, q=14777058483132963961, e=65537, n=269010951824990204830693900060300012463, phi=134505475912495102398856103431849488360, d=14600484545241469070379515690589701393, alt_d=14600484545241469070379515690589701393>
```



## Example Use Cases
* Auditing infrastructure
* Modelling existing systems
* Solving/creating CTFs


## Testing Environment
* **Runtime**: Python 3.6.7
* **Architecture**: Linux 4.18.17-200.fc28.x86_64 #1 SMP Mon Nov 5 18:04:28 UTC 2018 GNU/Linux
* **OS**: Fedora Security Lab (Fedora release 28)


## Installation
### **Recommended OS is Fedora and recommended Python implementation is PyPy**

### RHEL derivatives (tested on Fedora Security Lab 28)
```bash
sudo dnf -y install pypy3 pypy3-devel redhat-rpm-config gmp-devel lapack-devel.x86_64 blas-devel.x86_64 gcc-c++
pypy3 -m ensurepip
pypy3 -m pip install samson-crypto
```

### Debian derivatives (tested on Kali Linux 2018.4 64-bit)
```bash
apt-get -y install python3-pip
pip3 install samson-crypto
```

## Performance
Samson's primitives aren't the fastest nor were they meant to be. If you're concerned about performance, you have a couple of options:

* Use primitives from a faster library (e.g. pycrypto)
* Use PyPy instead of CPython

Since samson mostly calls Python, PyPy offers large speed-ups. However, the latest stable version of PyPy works with Python 3.5 while SHA3 was introduced in 3.6. samson's SHA3 will still work, but the tests will fail.