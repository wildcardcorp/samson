from samson.publickey.dsa import DSA
from samson.utilities.bytes import Bytes
import hashlib
import unittest


TEST_PRIV = b"""-----BEGIN DSA PRIVATE KEY-----
MIIDVgIBAAKCAQEAr9QOzmLmfkEjvB4xt3dBnyGLSKrLpp1WAVkZeElygI+CkbR8
h4fTuaUHuCFX70w/q7egnu5TwG/DZGPcThg6FKe8i6mRDwnD5y6s/Lu3Niojhrrv
CUxs3yJJYvyjrPwKdtMkeVkoiTZeFEeWBXhrgxF6rEWkJBKloZNG32NXqW9gcpfy
ecJ4v0yffuZWjftU0nO+3Yo1VQsGiY0fA8mFfYXNGXCbLENF8jclW7QpuKdcHXkB
deKofZRj+6nV/duLTWL6hOPqqEBc34B4ApeGfFAissN5Juf0Nzku3KIkp23hHZtW
pH0cHz4JpASDg3Y3grhcDy0mjuWt9iyYo2YuIwIhAJD4vs9Y2Oo+I7PRFFouK6Wz
CtO44JKlADo4c4poFGFbAoIBAFgxG8YaNzWyFf1sJuMbBZ1Pq6SOfZ+7A8bH1QRw
0d3DnT8fIkDy4uwmYKtq2lDxyGd+HyJcvzVVttuphfgMo6DevT8DpicKAmGA7y//
0NPCAt1eHx5aYIELxZGfhjdManb6N8hhUmhzzJ1JqqrKj4P60/JZwzYlIfntkIpP
gsXKuAOW3Wf/3s55dnguNwrRHD525xi9qisBXaUBKLViKmEH0lVjEN+RmB2fEjt1
C6xJx4CKQd7hZrBneXz8zLpZc5pCaEStcYpc411IZXQTl3SwMiA7IdlYTN1okXQB
oPal453z1cov8exg3erfs2OkWBH/JLMFssICuGPAVJ7CesACggEBAIU5+UpNOO6r
fvNzveNGnirqEzYTa2w0uEWEun4d/t0jhxDI34vSO6zA5oFwaZ4BFsuxTVzVAKF5
oSaKw2G3qsQ4QLr89VO/QHkbnrRLvkCa1cPZbY4eqPGzMlQsLTrBCb1zwH8Gbpx+
gcSVAwEyOdotoS8VWtURJNI/JaiTQN5ueZtrtKc4rJRg/oHvxgDrDEaqAuAakbr2
03+ZLCimsXVGDpVYoUu+i1su7P9ksLuVJE08ugcmVmZTSJURnao54AzOiVxQE3dH
hg6B3Jd661aatPJNRXyYBFTR5XHH8wclAjxbdMTqru/d8Ig6zAzNZulCbbBydawh
tZSAKpT1c+QCIGfUX0ksNEYbIsoy+Xt1caTltO3zbXuiMOA6bR4E/j8J
-----END DSA PRIVATE KEY-----"""

TEST_PUB = b"""-----BEGIN PUBLIC KEY-----
MIIDRzCCAjkGByqGSM44BAEwggIsAoIBAQCv1A7OYuZ+QSO8HjG3d0GfIYtIqsum
nVYBWRl4SXKAj4KRtHyHh9O5pQe4IVfvTD+rt6Ce7lPAb8NkY9xOGDoUp7yLqZEP
CcPnLqz8u7c2KiOGuu8JTGzfIkli/KOs/Ap20yR5WSiJNl4UR5YFeGuDEXqsRaQk
EqWhk0bfY1epb2Byl/J5wni/TJ9+5laN+1TSc77dijVVCwaJjR8DyYV9hc0ZcJss
Q0XyNyVbtCm4p1wdeQF14qh9lGP7qdX924tNYvqE4+qoQFzfgHgCl4Z8UCKyw3km
5/Q3OS7coiSnbeEdm1akfRwfPgmkBIODdjeCuFwPLSaO5a32LJijZi4jAiEAkPi+
z1jY6j4js9EUWi4rpbMK07jgkqUAOjhzimgUYVsCggEAWDEbxho3NbIV/Wwm4xsF
nU+rpI59n7sDxsfVBHDR3cOdPx8iQPLi7CZgq2raUPHIZ34fIly/NVW226mF+Ayj
oN69PwOmJwoCYYDvL//Q08IC3V4fHlpggQvFkZ+GN0xqdvo3yGFSaHPMnUmqqsqP
g/rT8lnDNiUh+e2Qik+Cxcq4A5bdZ//eznl2eC43CtEcPnbnGL2qKwFdpQEotWIq
YQfSVWMQ35GYHZ8SO3ULrEnHgIpB3uFmsGd5fPzMullzmkJoRK1xilzjXUhldBOX
dLAyIDsh2VhM3WiRdAGg9qXjnfPVyi/x7GDd6t+zY6RYEf8kswWywgK4Y8BUnsJ6
wAOCAQYAAoIBAQCFOflKTTjuq37zc73jRp4q6hM2E2tsNLhFhLp+Hf7dI4cQyN+L
0juswOaBcGmeARbLsU1c1QCheaEmisNht6rEOEC6/PVTv0B5G560S75AmtXD2W2O
HqjxszJULC06wQm9c8B/Bm6cfoHElQMBMjnaLaEvFVrVESTSPyWok0Debnmba7Sn
OKyUYP6B78YA6wxGqgLgGpG69tN/mSwoprF1Rg6VWKFLvotbLuz/ZLC7lSRNPLoH
JlZmU0iVEZ2qOeAMzolcUBN3R4YOgdyXeutWmrTyTUV8mARU0eVxx/MHJQI8W3TE
6q7v3fCIOswMzWbpQm2wcnWsIbWUgCqU9XPk
-----END PUBLIC KEY-----"""

# openssl dsaparam -out dsaparam.pem 2048
# openssl gendsa -out test_dsa.pem dsaparam.pem
# openssl dsa -in test_dsa.pem -text
# openssl dsa -in test_dsa.pem -pubout -text
# openssl dsa -pubin -in test_dsa.pub -pubout -text


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
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PRIV.replace(b'\n', b''))


    def test_import_export_public(self):
        dsa_pub  = DSA.import_key(TEST_PUB)
        dsa_priv = DSA.import_key(TEST_PRIV)

        der_bytes = dsa_pub.export_public_key()
        new_pub  = DSA.import_key(der_bytes)

        self.assertEqual((dsa_pub.p, dsa_pub.q, dsa_pub.g, dsa_pub.y), (dsa_priv.p, dsa_priv.q, dsa_priv.g, dsa_priv.y))
        self.assertEqual((new_pub.p, new_pub.q, new_pub.g, new_pub.y), (dsa_priv.p, dsa_priv.q, dsa_priv.g, dsa_priv.y))
        self.assertEqual(der_bytes.replace(b'\n', b''), TEST_PUB.replace(b'\n', b''))
