from samson.protocols.ecdhe import ECDHE
from fastecdsa.point import Point
from fastecdsa.curve import P192, P224, P256
import unittest

class ECDHETestCase(unittest.TestCase):
    def test_gauntlet(self):
        for _ in range(1000):
            ecdhe1 = ECDHE()
            ecdhe2 = ECDHE()

            ch1 = ecdhe1.pub
            ch2 = ecdhe2.pub

            self.assertEqual(ecdhe1.derive_key(ch2), ecdhe2.derive_key(ch1))
            self.assertEqual(ecdhe1.derive_point(ch2), ecdhe2.derive_point(ch1))


    # Tests manually generated from http://www-cs-students.stanford.edu/~tjw/jsbn/ecdh.html
    def _run_correctness_test(self, key_a, key_b, G, expected_chall_a, expected_chall_b, expected_secret):
        echde_a = ECDHE(d=key_a, G=G)
        echde_b = ECDHE(d=key_b, G=G)

        chall_a = echde_a.pub
        chall_b = echde_b.pub

        self.assertEqual(chall_a, expected_chall_a)
        self.assertEqual(chall_b, expected_chall_b)

        S_a = echde_a.derive_point(chall_b)
        S_b = echde_b.derive_point(chall_a)

        self.assertEqual(S_a, expected_secret)
        self.assertEqual(S_b, expected_secret)



    # P192
    def test_vec0(self):
        curve = P192
        key_a = 1343336258932205431243705973427736404561310951793694213529
        key_b = 2739224124954967355906436155613367231565396653290723243498

        expected_chall_a = Point(
            x=6188285744536752406038814907731196625852141841146217866262,
            y=1038408800907418356706786291905439665302754377242770044043,
            curve=curve
        )

        expected_chall_b = Point(
            x=4026896707767806324564556977150622203157964732784961051329,
            y=3971860200665129474886124719560295042130387723445296752658,
            curve=curve
        )

        expected_secret = Point(
            x=1306663265114722938145503931992673936412358572133731713568,
            y=5247488590479933709406586612625288267325718485468363073335,
            curve=curve
        )

        self._run_correctness_test(key_a, key_b, curve.G, expected_chall_a, expected_chall_b, expected_secret)



    def test_vec1(self):
        curve = P192
        key_a = 146464493939115428598736204098139199903895644120440475629
        key_b = 5463763543052294454616502537705235637864279473761049915736

        expected_chall_a = Point(
            x=5444205681722706718083811915461116556168212769750334639446,
            y=5531345568352707982030860705686030927214968448175019134509,
            curve=curve
        )

        expected_chall_b = Point(
            x=6230915644511356316710141920988309453442304907050961221791,
            y=5703666572724080039310192710473352524610239291372852061524,
            curve=curve
        )

        expected_secret = Point(
            x=3640097373044518118894341969157690034510483789156041547335,
            y=142000995409851126602905215191251750635634079826096657528,
            curve=curve
        )

        self._run_correctness_test(key_a, key_b, curve.G, expected_chall_a, expected_chall_b, expected_secret)


    # P224
    def test_vec2(self):
        curve = P224
        key_a = 2129288262482417377584901511568613795093948189764951917927579537563
        key_b = 4800629497468672065822461080637158805273522272285333222395782669960

        expected_chall_a = Point(
            x=22053458300901593877093837012553818730947147333453791741274325079931,
            y=18973483699511021001209967134137516791866052087110806197187645437032,
            curve=curve
        )

        expected_chall_b = Point(
            x=16884794872246094122184945987820602784441775852702982372408841712084,
            y=18199649981497912192843703485082021512716195695931196311894246794085,
            curve=curve
        )

        expected_secret = Point(
            x=15615603596497237442643035982408882777794728576786318176166432006882,
            y=24620331879232866747650717728838958147751895454041139627212381574177,
            curve=curve
        )

        self._run_correctness_test(key_a, key_b, curve.G, expected_chall_a, expected_chall_b, expected_secret)



    def test_vec3(self):
        curve = P224
        key_a = 16294319315086424528574067800469935779587993471263244732762547443138
        key_b = 22829149718507195608261658904386350722207159898320556368981131867566

        expected_chall_a = Point(
            x=26186616424126453448457066060328787495824898679826594426466592430446,
            y=11982874080009860830524392728610999279746990552070605149359231558390,
            curve=curve
        )

        expected_chall_b = Point(
            x=4673882334705788803290275179592683917875750347542704938635098899561,
            y=23953670988869978317201253143378284497541435312582098850596664223063,
            curve=curve
        )

        expected_secret = Point(
            x=11922270649043036577530158405442610576971286566724450292330932971451,
            y=23323712056893279905452047437558766398544512288367767234692036097827,
            curve=curve
        )

        self._run_correctness_test(key_a, key_b, curve.G, expected_chall_a, expected_chall_b, expected_secret)


    # P256
    def test_vec4(self):
        curve = P256
        key_a = 17357183322248276894849157147208609681295348833271728233118265450527981996515
        key_b = 110204950077917401250349164523282354478362452862977247660870548883463019559236

        expected_chall_a = Point(
            x=37668467326798426225453901797446814763060916985915337952521081052637525687343,
            y=49044012563068473564030562828289155103987955120208809251591748867271871010524,
            curve=curve
        )

        expected_chall_b = Point(
            x=11431296317569480823062610707395012504393184829562921857415622004502905324286,
            y=79433321501490383545225447427397294251946648796959676677209698771934246272820,
            curve=curve
        )

        expected_secret = Point(
            x=101173106233161665221514241900221397986223075660310537911481168270454296837095,
            y=111884590099490997568836853202493568596302265187721871715834462935604062527701,
            curve=curve
        )

        self._run_correctness_test(key_a, key_b, curve.G, expected_chall_a, expected_chall_b, expected_secret)


    def test_vec5(self):
        curve = P256
        key_a = 8868470271837190167142535210791446964163029260066868980823100115101630553880
        key_b = 48207774866239728204111512369254665847975776566761466795888369371064717357111

        expected_chall_a = Point(
            x=19848726290805363209881160673956767978642191531000643686517224797688055851274,
            y=29336470283165727603977011893786668803019136632264112747219903108399311147854,
            curve=curve
        )

        expected_chall_b = Point(
            x=95982986445171011092364040725381994709839967039669832862070369602076301274698,
            y=99685317491761186186477991574495696307926559442728026503776752270191450068337,
            curve=curve
        )

        expected_secret = Point(
            x=74557933571477610844818057403948842492480526846163778150414781021431183437525,
            y=72740859861967859527789136714015037486259345763870620830308150116178756323402,
            curve=curve
        )

        self._run_correctness_test(key_a, key_b, curve.G, expected_chall_a, expected_chall_b, expected_secret)
