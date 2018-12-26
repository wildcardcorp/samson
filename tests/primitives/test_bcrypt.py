from samson.kdfs.bcrypt import Bcrypt
from samson.encoding.general import bcrypt_b64_decode
import unittest

# Test vectors from https://github.com/patrickfav/bcrypt/wiki/Published-Test-Vectors
TEST_VECTORS = [
    ("", 4, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$04$zVHmKQtGGQob.b/Nc7l9NO8UlrYcW05FiuCj/SxsFO/ZtiN9.mNzy"),
    ("", 5, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$05$zVHmKQtGGQob.b/Nc7l9NOWES.1hkVBgy5IWImh9DOjKNU8atY4Iy"),
    ("", 6, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$06$zVHmKQtGGQob.b/Nc7l9NOjOl7l4oz3WSh5fJ6414Uw8IXRAUoiaO"),
    ("", 7, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$07$zVHmKQtGGQob.b/Nc7l9NOBsj1dQpBA1HYNGpIETIByoNX9jc.hOi"),
    ("", 8, "zVHmKQtGGQob.b/Nc7l9NO", "$2a$08$zVHmKQtGGQob.b/Nc7l9NOiLTUh/9MDpX86/DLyEzyiFjqjBFePgO"),
    ("<.S.2K(Zq'", 4, "VYAclAMpaXY/oqAo9yUpku", "$2a$04$VYAclAMpaXY/oqAo9yUpkuWmoYywaPzyhu56HxXpVltnBIfmO9tgu"),
    ("5.rApO%5jA", 5, "kVNDrnYKvbNr5AIcxNzeIu", "$2a$05$kVNDrnYKvbNr5AIcxNzeIuRcyIF5cZk6UrwHGxENbxP5dVv.WQM/G"),
    ("oW++kSrQW^", 6, "QLKkRMH9Am6irtPeSKN5sO", "$2a$06$QLKkRMH9Am6irtPeSKN5sObJGr3j47cO6Pdf5JZ0AsJXuze0IbsNm"),
    ("ggJ\\KbTnDG", 7, "4H896R09bzjhapgCPS/LYu", "$2a$07$4H896R09bzjhapgCPS/LYuMzAQluVgR5iu/ALF8L8Aln6lzzYXwbq"),
    ("49b0:;VkH/", 8, "hfvO2retKrSrx5f2RXikWe", "$2a$08$hfvO2retKrSrx5f2RXikWeFWdtSesPlbj08t/uXxCeZoHRWDz/xFe"),
    ("^Q&\"]A`%/A(BVGt>QaX0M-#<Q148&f", 4, "vrRP5vQxyD4LrqiLd/oWRO", "$2a$04$vrRP5vQxyD4LrqiLd/oWROgrrGINsw3gb4Ga5x2sn01jNmiLVECl6"),
    ("nZa!rRf\\U;OL;R?>1ghq_+\":Y0CRmY", 5, "YuQvhokOGVnevctykUYpKu", "$2a$05$YuQvhokOGVnevctykUYpKutZD2pWeGGYn3auyLOasguMY3/0BbIyq"),
    ("F%uN/j>[GuB7-jB'_Yj!Tnb7Y!u^6)", 6, "5L3vpQ0tG9O7k5gQ8nAHAe", "$2a$06$5L3vpQ0tG9O7k5gQ8nAHAe9xxQiOcOLh8LGcI0PLWhIznsDt.S.C6"),
    ("Z>BobP32ub\"Cfe*Q<<WUq3rc=[GJr-", 7, "hp8IdLueqE6qFh1zYycUZ.", "$2a$07$hp8IdLueqE6qFh1zYycUZ.twmUH8eSTPQAEpdNXKMlwms9XfKqfea"),
    ("Ik&8N['7*[1aCc1lOm8\\jWeD*H$eZM", 8, "2ANDTYCB9m7vf0Prh7rSru", "$2a$08$2ANDTYCB9m7vf0Prh7rSrupqpO3jJOkIz2oW/QHB4lCmK7qMytGV6"),
    ("-O_=*N!2JP", 4, "......................", "$2a$04$......................JjuKLOX9OOwo5PceZZXSkaLDvdmgb82"),
    ("7B[$Q<4b>U", 5, "......................", "$2a$05$......................DRiedDQZRL3xq5A5FL8y7/6NM8a2Y5W"),
    (">d5-I_8^.h", 6, "......................", "$2a$06$......................5Mq1Ng8jgDY.uHNU4h5p/x6BedzNH2W"),
    (")V`/UM/]1t", 4, ".OC/.OC/.OC/.OC/.OC/.O", "$2a$04$.OC/.OC/.OC/.OC/.OC/.OQIvKRDAam.Hm5/IaV/.hc7P8gwwIbmi"),
    (":@t2.bWuH]", 5, ".OC/.OC/.OC/.OC/.OC/.O", "$2a$05$.OC/.OC/.OC/.OC/.OC/.ONDbUvdOchUiKmQORX6BlkPofa/QxW9e"),
    ("b(#KljF5s\"", 6, ".OC/.OC/.OC/.OC/.OC/.O", "$2a$06$.OC/.OC/.OC/.OC/.OC/.OHfTd9e7svOu34vi1PCvOcAEq07ST7.K"),
    ("@3YaJ^Xs]*", 4, "eGA.eGA.eGA.eGA.eGA.e.", "$2a$04$eGA.eGA.eGA.eGA.eGA.e.stcmvh.R70m.0jbfSFVxlONdj1iws0C"),
    ("'\"5\\!k*C(p", 5, "eGA.eGA.eGA.eGA.eGA.e.", "$2a$05$eGA.eGA.eGA.eGA.eGA.e.vR37mVSbfdHwu.F0sNMvgn8oruQRghy"),
    ("edEu7C?$'W", 6, "eGA.eGA.eGA.eGA.eGA.e.", "$2a$06$eGA.eGA.eGA.eGA.eGA.e.tSq0FN8MWHQXJXNFnHTPQKtA.n2a..G"),
    ("N7dHmg\\PI^", 4, "999999999999999999999u", "$2a$04$999999999999999999999uCZfA/pLrlyngNDMq89r1uUk.bQ9icOu"),
    ("\"eJuHh!)7*", 5, "999999999999999999999u", "$2a$05$999999999999999999999uj8Pfx.ufrJFAoWFLjapYBS5vVEQQ/hK"),
    ("ZeDRJ:_tu:", 6, "999999999999999999999u", "$2a$06$999999999999999999999u6RB0P9UmbdbQgjoQFEJsrvrKe.BoU6q")
]

class BcryptTestCase(unittest.TestCase):
    def test_all(self):
        for plaintext, cost, salt, expected_hash in TEST_VECTORS:
            bcrypt = Bcrypt(cost)
            derived_key = bcrypt.derive(plaintext.encode('utf-8'), bcrypt_b64_decode(salt.encode('utf-8')))

            if derived_key != expected_hash.encode('utf-8'):
                print(plaintext.encode('utf-8'), salt.encode('utf-8'))
                print(derived_key)
                print(expected_hash)

            self.assertEqual(derived_key, expected_hash.encode('utf-8'))
