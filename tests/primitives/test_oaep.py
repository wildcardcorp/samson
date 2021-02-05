from samson.utilities.bytes import Bytes
from samson.public_key.rsa import RSA
from samson.padding.oaep import OAEP
import unittest

# https://github.com/pyca/cryptography/blob/master/vectors/cryptography_vectors/asymmetric/RSA/pkcs-1v2-1d2-vec/oaep-vect.txt
class OAEPTestCase(unittest.TestCase):
    def _run_oaep(self, e, d, modulus, bits, message, seed, expected_ciphertext):
        rsa = RSA(n=modulus, e=e)
        rsa.d = d

        oaep = OAEP(rsa.bits)
        padded_plain = oaep.pad(message, seed=seed)
        ciphertext = Bytes(rsa.encrypt(padded_plain))

        self.assertEqual(ciphertext, expected_ciphertext)
        self.assertEqual(oaep.unpad(rsa.decrypt(ciphertext.int())), message)


    # RSA parameters by set
    def _vec_1(self, message, seed, expected_ciphertext):
        modulus = 0xa8b3b284af8eb50b387034a860f146c4919f318763cd6c5598c8ae4811a1e0abc4c7e0b082d693a5e7fced675cf4668512772c0cbc64a742c6c630f533c8cc72f62ae833c40bf25842e984bb78bdbf97c0107d55bdb662f5c4e0fab9845cb5148ef7392dd3aaff93ae1e6b667bb3d4247616d4f5ba10d4cfd226de88d39f16fb
        e       = 0x010001
        d       = 0x53339cfdb79fc8466a655c7316aca85c55fd8f6dd898fdaf119517ef4f52e8fd8e258df93fee180fa0e4ab29693cd83b152a553d4ac4d1812b8b9fa5af0e7f55fe7304df41570926f3311f15c4d65a732c483116ee3d3d2d0af3549ad9bf7cbfb78ad884f84d5beb04724dc7369b31def37d0cf539e9cfcdd3de653729ead5d1

        self._run_oaep(e, d, modulus, 1024, message, seed, expected_ciphertext)



    def _vec_2(self, message, seed, expected_ciphertext):
        modulus = 0x01947c7fce90425f47279e70851f25d5e62316fe8a1df19371e3e628e260543e4901ef6081f68c0b8141190d2ae8daba7d1250ec6db636e944ec3722877c7c1d0a67f14b1694c5f0379451a43e49a32dde83670b73da91a1c99bc23b436a60055c610f0baf99c1a079565b95a3f1526632d1d4da60f20eda25e653c4f002766f45
        e       = 0x010001
        d       = 0x0823f20fadb5da89088a9d00893e21fa4a1b11fbc93c64a3be0baaea97fb3b93c3ff713704c19c963c1d107aae99054739f79e02e186de86f87a6ddefea6d8ccd1d3c81a47bfa7255be20601a4a4b2f08a167b5e279d715b1b455bdd7eab245941d9768b9acefb3ccda5952da3cee72525b4501663a8ee15c9e992d92462fe39

        self._run_oaep(e, d, modulus, 1025, message, seed, expected_ciphertext)



    def _vec_3(self, message, seed, expected_ciphertext):
        modulus = 0x02b58fec039a860700a4d7b6462f93e6cdd491161ddd74f4e810b40e3c1652006a5c277b2774c11305a4cbab5a78efa57e17a86df7a3fa36fc4b1d2249f22ec7c2dd6a463232accea906d66ebe80b5704b10729da6f833234abb5efdd4a292cbfad33b4d33fa7a14b8c397b56e3acd21203428b77cdfa33a6da706b3d8b0fc43e9
        e       = 0x010001
        d       = 0x15b48a5b5683a94670e23b5718f814fa0e13f85038f50711182cba61510581f3d22c7e232ef937e22e551d68b86e2f8cb1aad8be2e488f5df7efd279e3f568d4eaf36f80cf7141ace60fcc9113fb6c4a841fd50bbc7c512ffcbeff21487aa811eb3ca8c62005346a86de86bfa1d8a948fd3f348c22eaadf333c3ce6ce13208fd

        self._run_oaep(e, d, modulus, 1026, message, seed, expected_ciphertext)



    def _vec_10(self, message, seed, expected_ciphertext):
        modulus = 0xae45ed5601cec6b8cc05f803935c674ddbe0d75c4c09fd7951fc6b0caec313a8df39970c518bffba5ed68f3f0d7f22a4029d413f1ae07e4ebe9e4177ce23e7f5404b569e4ee1bdcf3c1fb03ef113802d4f855eb9b5134b5a7c8085adcae6fa2fa1417ec3763be171b0c62b760ede23c12ad92b980884c641f5a8fac26bdad4a03381a22fe1b754885094c82506d4019a535a286afeb271bb9ba592de18dcf600c2aeeae56e02f7cf79fc14cf3bdc7cd84febbbf950ca90304b2219a7aa063aefa2c3c1980e560cd64afe779585b6107657b957857efde6010988ab7de417fc88d8f384c4e6e72c3f943e0c31c0c4a5cc36f879d8a3ac9d7d59860eaada6b83bb
        e       = 0x010001
        d       = 0x056b04216fe5f354ac77250a4b6b0c8525a85c59b0bd80c56450a22d5f438e596a333aa875e291dd43f48cb88b9d5fc0d499f9fcd1c397f9afc070cd9e398c8d19e61db7c7410a6b2675dfbf5d345b804d201add502d5ce2dfcb091ce9997bbebe57306f383e4d588103f036f7e85d1934d152a323e4a8db451d6f4a5b1b0f102cc150e02feee2b88dea4ad4c1baccb24d84072d14e1d24a6771f7408ee30564fb86d4393a34bcf0b788501d193303f13a2284b001f0f649eaf79328d4ac5c430ab4414920a9460ed1b7bc40ec653e876d09abc509ae45b525190116a0c26101848298509c1c3bf3a483e7274054e15e97075036e989f60932807b5257751e79

        self._run_oaep(e, d, modulus, 2048, message, seed, expected_ciphertext)




    # Parameters per test
    def test_vec_1_1(self):
        message = Bytes(0x6628194e12073db03ba94cda9ef9532397d50dba79b987004afefe34)
        seed    = Bytes(0x18b776ea21069d69776a33e96bad48e1dda0a5ef)
        expected_ciphertext = Bytes(0x354fe67b4a126d5d35fe36c777791a3f7ba13def484e2d3908aff722fad468fb21696de95d0be911c2d3174f8afcc201035f7b6d8e69402de5451618c21a535fa9d7bfc5b8dd9fc243f8cf927db31322d6e881eaa91a996170e657a05a266426d98c88003f8477c1227094a0d9fa1e8c4024309ce1ecccb5210035d47ac72e8a)

        self._vec_1(message, seed, expected_ciphertext)


    def test_vec_1_2(self):
        message  = Bytes(0x750c4047f547e8e41411856523298ac9bae245efaf1397fbe56f9dd5)
        seed     = Bytes(0x0cc742ce4a9b7f32f951bcb251efd925fe4fe35f)
        expected_ciphertext = Bytes(0x640db1acc58e0568fe5407e5f9b701dff8c3c91e716c536fc7fcec6cb5b71c1165988d4a279e1577d730fc7a29932e3f00c81515236d8d8e31017a7a09df4352d904cdeb79aa583adcc31ea698a4c05283daba9089be5491f67c1a4ee48dc74bbbe6643aef846679b4cb395a352d5ed115912df696ffe0702932946d71492b44)

        self._vec_1(message, seed, expected_ciphertext)



    def test_vec_1_3(self):
        message  = Bytes(0xd94ae0832e6445ce42331cb06d531a82b1db4baad30f746dc916df24d4e3c2451fff59a6423eb0e1d02d4fe646cf699dfd818c6e97b051)
        seed     = Bytes(0x2514df4695755a67b288eaf4905c36eec66fd2fd)
        expected_ciphertext = Bytes(0x423736ed035f6026af276c35c0b3741b365e5f76ca091b4e8c29e2f0befee603595aa8322d602d2e625e95eb81b2f1c9724e822eca76db8618cf09c5343503a4360835b5903bc637e3879fb05e0ef32685d5aec5067cd7cc96fe4b2670b6eac3066b1fcf5686b68589aafb7d629b02d8f8625ca3833624d4800fb081b1cf94eb)

        self._vec_1(message, seed, expected_ciphertext)




    def test_vec_2_1(self):
        message  = Bytes(0x8ff00caa605c702830634d9a6c3d42c652b58cf1d92fec570beee7)
        seed     = Bytes(0x8c407b5ec2899e5099c53e8ce793bf94e71b1782)
        expected_ciphertext = Bytes(0x0181af8922b9fcb4d79d92ebe19815992fc0c1439d8bcd491398a0f4ad3a329a5bd9385560db532683c8b7da04e4b12aed6aacdf471c34c9cda891addcc2df3456653aa6382e9ae59b54455257eb099d562bbe10453f2b6d13c59c02e10f1f8abb5da0d0570932dacf2d0901db729d0fefcc054e70968ea540c81b04bcaefe720e)

        self._vec_2(message, seed, expected_ciphertext)



    def test_vec_2_2(self):
        message  = Bytes(0x2d)
        seed     = Bytes(0xb600cf3c2e506d7f16778c910d3a8b003eee61d5)
        expected_ciphertext = Bytes(0x018759ff1df63b2792410562314416a8aeaf2ac634b46f940ab82d64dbf165eee33011da749d4bab6e2fcd18129c9e49277d8453112b429a222a8471b070993998e758861c4d3f6d749d91c4290d332c7a4ab3f7ea35ff3a07d497c955ff0ffc95006b62c6d296810d9bfab024196c7934012c2df978ef299aba239940cba10245)

        self._vec_2(message, seed, expected_ciphertext)



    def test_vec_3_1(self):
        message  = Bytes(0x087820b569e8fa8d)
        seed     = Bytes(0x8ced6b196290805790e909074015e6a20b0c4894)
        expected_ciphertext = Bytes(0x026a0485d96aebd96b4382085099b962e6a2bdec3d90c8db625e14372de85e2d5b7baab65c8faf91bb5504fb495afce5c988b3f6a52e20e1d6cbd3566c5cd1f2b8318bb542cc0ea25c4aab9932afa20760eaddec784396a07ea0ef24d4e6f4d37e5052a7a31e146aa480a111bbe926401307e00f410033842b6d82fe5ce4dfae80)

        self._vec_3(message, seed, expected_ciphertext)



    def test_vec_3_2(self):
        message  = Bytes(0x4653acaf171960b01f52a7be63a3ab21dc368ec43b50d82ec3781e04)
        seed     = Bytes(0xb4291d6567550848cc156967c809baab6ca507f0)
        expected_ciphertext = Bytes(0x024db89c7802989be0783847863084941bf209d761987e38f97cb5f6f1bc88da72a50b73ebaf11c879c4f95df37b850b8f65d7622e25b1b889e80fe80baca2069d6e0e1d829953fc459069de98ea9798b451e557e99abf8fe3d9ccf9096ebbf3e5255d3b4e1c6d2ecadf067a359eea86405acd47d5e165517ccafd47d6dbee4bf5)

        self._vec_3(message, seed, expected_ciphertext)




    def test_vec_10_1(self):
        message  = Bytes(0x8bba6bf82a6c0f86d5f1756e97956870b08953b06b4eb205bc1694ee)
        seed     = Bytes(0x47e1ab7119fee56c95ee5eaad86f40d0aa63bd33)
        expected_ciphertext = Bytes(0x53ea5dc08cd260fb3b858567287fa91552c30b2febfba213f0ae87702d068d19bab07fe574523dfb42139d68c3c5afeee0bfe4cb7969cbf382b804d6e61396144e2d0e60741f8993c3014b58b9b1957a8babcd23af854f4c356fb1662aa72bfcc7e586559dc4280d160c126785a723ebeebeff71f11594440aaef87d10793a8774a239d4a04c87fe1467b9daf85208ec6c7255794a96cc29142f9a8bd418e3c1fd67344b0cd0829df3b2bec60253196293c6b34d3f75d32f213dd45c6273d505adf4cced1057cb758fc26aeefa441255ed4e64c199ee075e7f16646182fdb464739b68ab5daff0e63e9552016824f054bf4d3c8c90a97bb6b6553284eb429fcc)

        self._vec_10(message, seed, expected_ciphertext)



    def test_vec_10_2(self):
        message  = Bytes(0xe6ad181f053b58a904f2457510373e57)
        seed     = Bytes(0x6d17f5b4c1ffac351d195bf7b09d09f09a4079cf)
        expected_ciphertext = Bytes(0xa2b1a430a9d657e2fa1c2bb5ed43ffb25c05a308fe9093c01031795f5874400110828ae58fb9b581ce9dddd3e549ae04a0985459bde6c626594e7b05dc4278b2a1465c1368408823c85e96dc66c3a30983c639664fc4569a37fe21e5a195b5776eed2df8d8d361af686e750229bbd663f161868a50615e0c337bec0ca35fec0bb19c36eb2e0bbcc0582fa1d93aacdb061063f59f2ce1ee43605e5d89eca183d2acdfe9f81011022ad3b43a3dd417dac94b4e11ea81b192966e966b182082e71964607b4f8002f36299844a11f2ae0faeac2eae70f8f4f98088acdcd0ac556e9fccc511521908fad26f04c64201450305778758b0538bf8b5bb144a828e629795)

        self._vec_10(message, seed, expected_ciphertext)


    def test_vec_10_3(self):
        message  = Bytes(0x510a2cf60e866fa2340553c94ea39fbc256311e83e94454b4124)
        seed     = Bytes(0x385387514deccc7c740dd8cdf9daee49a1cbfd54)
        expected_ciphertext = Bytes(0x9886c3e6764a8b9a84e84148ebd8c3b1aa8050381a78f668714c16d9cfd2a6edc56979c535d9dee3b44b85c18be8928992371711472216d95dda98d2ee8347c9b14dffdff84aa48d25ac06f7d7e65398ac967b1ce90925f67dce049b7f812db0742997a74d44fe81dbe0e7a3feaf2e5c40af888d550ddbbe3bc20657a29543f8fc2913b9bd1a61b2ab2256ec409bbd7dc0d17717ea25c43f42ed27df8738bf4afc6766ff7aff0859555ee283920f4c8a63c4a7340cbafddc339ecdb4b0515002f96c932b5b79167af699c0ad3fccfdf0f44e85a70262bf2e18fe34b850589975e867ff969d48eabf212271546cdc05a69ecb526e52870c836f307bd798780ede)

        self._vec_10(message, seed, expected_ciphertext)
