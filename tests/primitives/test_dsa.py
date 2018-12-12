from samson.publickey.dsa import DSA
from samson.utilities.bytes import Bytes
import hashlib
import unittest


TEST_PRIV = b"""-----BEGIN DSA PRIVATE KEY-----
MIIDTgIBAAKCAQEAj3k12bmq6b+r7Yh6z0lRtvMuxZ47rzcY6OrElh8+/TYG50NR
qcQYMzm4CefCrhxTm6dHW4XQEa24tHmHdUmEaVysDo8UszYIKKIv+icRCj1iqZNF
NAmg/mlsRlj4S90ggZw3CaAQV7GVrc0AIz26VIS2KR+dZI74g0SGd5ec7AS0NKas
LnXpmF3iPbApL8ERjJ/6nYGB5zONt5K3MNe540lZL2gJmHIVORXqPWuLRlPGM0WP
gDsypMLg8nKQJW5OP4o7CDihxFDk4YwaKaN9316hQ95LZv8EkD7VzxYj4VjUh8YI
6X8hHNgdyiPLbjgHZfgi40K+SEwFdjk5YBzWZwIdALr2lqaFePff3uf6Z8l3x4Xv
MrIzuuWAwLzVaV0CggEAFqZcWCBIUHBOdQKjl1cEDTTaOjR4wVTU5KXALSQu4E+W
5h5L0JBKvayPN+6x4J8xgtI8kEPLZC+IAEFg7fnKCbMgdqecMqYn8kc+kYebosTn
RL0ggVRMtVuALDaNH6g+1InpTg+gaI4yQopceMR4xo0FJ7ccmjq7CwvhLERoljnn
08502xAaZaorh/ZMaCbbPscvS1WZg0u07bAvfJDppJbTpV1TW+v8RdT2GfY/Pe27
hzklwvIk4HcxKW2oh+weR0j4fvtf3rdUhDFrIjLe5VPdrwIRKw0fAtowlzIk/ieu
2oudSyki2bqL457Z4QOmPFKBC8aIt+LtQxbh7xfb3gKCAQBW8DU/53O9vfPP/Osi
ljfZVSqRNE21df0bReIZ0hzATr56mNvlDJhbWWfkvLslbj19yvqry+qvodXqs8xi
NvrsUOxQ30vET6crIxWW0hnNtnuwnEB99aHPpNffHbIsGlzCXA1i+A/lIDo7GeVn
It+thpXxrzJCIAicBivVApRMbgSmJYPG2/N0HXwB0OFEakw8QN0cGZAdnTM6vNK2
nV/kTbaHqcLoZfR6qoLLH2xWiLT5+2a16jeDxndp6rFTYUeGu3WMRozV2ikhIAde
xEHmnJLaF7LWhU9xfsZh5mkA9IGRxupJX79YnYiVXs5Taw96X8t51TCTp3eLAG4T
YQV2Ah0AtUPQeEtDUjNmNE8BbAysePT+BtuLtYD4UnGeyg==
-----END DSA PRIVATE KEY-----"""


TEST_PUB = b"ssh-dss AAAAB3NzaC1kc3MAAAEBAI95Ndm5qum/q+2Ies9JUbbzLsWeO683GOjqxJYfPv02BudDUanEGDM5uAnnwq4cU5unR1uF0BGtuLR5h3VJhGlcrA6PFLM2CCiiL/onEQo9YqmTRTQJoP5pbEZY+EvdIIGcNwmgEFexla3NACM9ulSEtikfnWSO+INEhneXnOwEtDSmrC516Zhd4j2wKS/BEYyf+p2BgeczjbeStzDXueNJWS9oCZhyFTkV6j1ri0ZTxjNFj4A7MqTC4PJykCVuTj+KOwg4ocRQ5OGMGimjfd9eoUPeS2b/BJA+1c8WI+FY1IfGCOl/IRzYHcojy244B2X4IuNCvkhMBXY5OWAc1mcAAAAdALr2lqaFePff3uf6Z8l3x4XvMrIzuuWAwLzVaV0AAAEAFqZcWCBIUHBOdQKjl1cEDTTaOjR4wVTU5KXALSQu4E+W5h5L0JBKvayPN+6x4J8xgtI8kEPLZC+IAEFg7fnKCbMgdqecMqYn8kc+kYebosTnRL0ggVRMtVuALDaNH6g+1InpTg+gaI4yQopceMR4xo0FJ7ccmjq7CwvhLERoljnn08502xAaZaorh/ZMaCbbPscvS1WZg0u07bAvfJDppJbTpV1TW+v8RdT2GfY/Pe27hzklwvIk4HcxKW2oh+weR0j4fvtf3rdUhDFrIjLe5VPdrwIRKw0fAtowlzIk/ieu2oudSyki2bqL457Z4QOmPFKBC8aIt+LtQxbh7xfb3gAAAQBW8DU/53O9vfPP/OsiljfZVSqRNE21df0bReIZ0hzATr56mNvlDJhbWWfkvLslbj19yvqry+qvodXqs8xiNvrsUOxQ30vET6crIxWW0hnNtnuwnEB99aHPpNffHbIsGlzCXA1i+A/lIDo7GeVnIt+thpXxrzJCIAicBivVApRMbgSmJYPG2/N0HXwB0OFEakw8QN0cGZAdnTM6vNK2nV/kTbaHqcLoZfR6qoLLH2xWiLT5+2a16jeDxndp6rFTYUeGu3WMRozV2ikhIAdexEHmnJLaF7LWhU9xfsZh5mkA9IGRxupJX79YnYiVXs5Taw96X8t51TCTp3eLAG4TYQV2"


# Test values and Known Answers
p, q, g = (89884656743115801690508003283032491320041051484130708380666508310605797591517657358448008016999203132296409109102891732381220932613670902301632476397501213820805847702280695479500940353078645163835996628341628828734609016397792501661682873394045725954243200605294871617235478335283698125903031997252753894013, 1207753555331593152985388036246139579485647958891, 5685459514059326809802874748014957316613560771138779799702167979852700053970957043705475419576800042124393749290154460175165016805439205742686078247106048259784394071586242286134792733247049365228417141823234012958591708840401400841693876682668942266225335842678094931739699394533691980318928257007905664651)
x, y = (25699150469538346273151504617195356896428318293, 87776125859689842027622448321257490281265790877998817249106298815115428969131775305386159545084670793191253582533101771837559797201510474157521867255147636248371470086721784879086813365664064382328859209285425076675844776906158328001899804552410472894735495394660855543401958332363658604533641691539985334580)
k = 707729718173049907897274687372338676901147366291
H = lambda msg: msg
message = int.from_bytes(b'\xf7\xff\x9e\x8b{\xb2\xe0\x9bp\x93Z]x^\x0c\xc5\xd9\xd0\xab\xf0', byteorder='big')
sig = (503181762231277455297502611450705228583240869840, 1148561876858258037434302178106550418252606972216)


class DSATestCase(unittest.TestCase):
    def hash(self, m):
        return m

    def setUp(self):
        dsa = DSA(self)
        dsa.p, dsa.q, dsa.g = p, q, g
        dsa.x, dsa.y = x, y

        self.dsa = dsa

    def test_dsa_sign(self):
        self.assertEqual(self.dsa.sign(message, k), sig)


    def test_dsa_verify(self):
        self.assertTrue(self.dsa.verify(message, sig))

    
    def test_k_derivation(self):
        messageB = int.from_bytes(hashlib.sha1(b'deadbeef').digest(), byteorder='big')
        sig_genB = self.dsa.sign(messageB, k)
        found_k = self.dsa.derive_k_from_sigs(message, sig, messageB, sig_genB)
        self.assertEqual(found_k, k)


    def test_x_derivation(self):
        self.dsa.x = 0
        self.dsa.x = self.dsa.derive_x_from_k(message, k, sig)
        self.assertEqual(self.dsa.x, x)
    


    def test_der_encode(self):
        for _ in range(20):
            dsa = DSA(None)

            should_pem_encode = Bytes.random(1).int() & 1

            der_bytes = dsa.export_private_key(should_pem_encode)
            recovered_dsa = DSA.import_key(der_bytes)

            self.assertEqual((dsa.p, dsa.q, dsa.g, dsa.x), (recovered_dsa.p, recovered_dsa.q, recovered_dsa.g, recovered_dsa.x))



    def test_import_export_private(self):
        dsa = DSA.import_key(TEST_PRIV)
        der_bytes = dsa.export_private_key()
        new_dsa = DSA.import_key(der_bytes)
        
        self.assertEqual((dsa.p, dsa.q, dsa.g, dsa.x), (new_dsa.p, new_dsa.q, new_dsa.g, new_dsa.x))
        self.assertEqual(TEST_PRIV.replace(b'\n', b''), der_bytes.replace(b'\n', b''))



    # TODO: Test with actual public key.
    def test_import_export_public(self):
        dsa_pub = DSA.import_key(TEST_PRIV)
        # dsa_pub  = DSA.import_key(TEST_PUB)
        dsa_priv = DSA.import_key(TEST_PRIV)

        der_bytes = dsa_pub.export_public_key()
        new_pub  = DSA.import_key(der_bytes)


        self.assertEqual((dsa_pub.p, dsa_pub.q, dsa_pub.g, dsa_pub.y), (dsa_priv.p, dsa_priv.q, dsa_priv.g, dsa_priv.y))
        self.assertEqual((new_pub.p, new_pub.q, new_pub.g, new_pub.y), (dsa_priv.p, dsa_priv.q, dsa_priv.g, dsa_priv.y))