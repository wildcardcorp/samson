from samson.math.general import miller_rabin, is_prime, totient, cyclomotic_polynomial
from samson.math.prime_gen import PrimeEngine
from samson.math.factorization.factors import Factors
from samson.utilities.exceptions import SearchspaceExhaustedException

_fac_cache = {
    29: (233, 1103, 2089),
    43: (431, 9719, 2099863),
    47: (2351, 4513, 13264529),
    53: (6361, 69431, 20394401),
    71: (228479, 48544121, 212885833),
    73: (439, 2298041, 9361973132609),
    79: (2687, 202029703, 1113491139767),
    113: (3391, 23279, 65993, 1868569, 1066818132868207),
    151: (18121, 55871, 165799, 2332951, 7289088383388253664437433),
    157: (852133201, 60726444167, 1654058017289, 2134387368610417),
    163: (150287, 704161, 110211473, 27669118297, 36230454570129675721),
    173: (730753, 1505447, 70084436712553223, 155285743288572277679887),
    179: (359, 1433, 1489459109360039866456940197095433721664951999121),
    181: (43441, 1164193, 7648337, 7923871097285295625344647665764672671),
    191: (383, 7068569257, 39940132241, 332584516519201, 87274497124602996457),
    193: (13821503, 61654440233248340616559, 14732265321145317331353282383),
    211: (15193, 60272956433838849161, 3593875704495823757388199894268773153439),
    223: (18287, 196687, 1466449, 2916841, 1469495262398780123809, 596242599987116128415063),

    229: [1504073,
  20492753,
  27989799426064405296116028686382091986123298539659506519],
 233: [1399,
  135607,
  622577,
  116868129879077600270344856324766260085066532853492178431],
 239: [479,
  1913,
  5737,
  176383,
  134000609,
  7110008717824458123105014279253754096863768062879],
 251: [503,
  54217,
  132686104398972053177608575506090561429353935989033525802891469459697],
 283: [9623,
  68492481833,
  23579543011798993222850893929565870383844167873851502677311057483194673],
 307: [14608903,
  85798519,
  23487583303,
  78952752017,
  112177476474470525577861298937835338545723093134076373561],
 337: [18199,
  2806537,
  95763203297,
  726584894969,
  78778047326466742993612420842416198311394008068822475527239136925369],
 359: [719,
  855857,
  778165529,
  2452259113942451520912910088057035488434323680189646612956871952666770024269864228081559241],
 367: [12479,
  51791041,
  465129605827000625477564483495401572628650332493307107634948086953668801150789194665513399654382593],
 383: [1440847,
  7435494593,
  1838910576096307526551940053067053122772868151895278435453932003529481809754390501703466313248412817],
 389: [56478911,
  4765678679,
  4684435266636161232578932847604331726884269415306219621279642876954933236537677535849040755779223719],
 397: [6353,
  2383,
  202471,
  50023,
  53993,
  5877983,
  6632954753511771661119272183910878630954818813644871756718305268982309035241537392082451127],
 431: [3449,
  863,
  36238481,
  76859369,
  558062249,
  4642152737,
  258199424946325265767428763990478681858110633973257229086197078793400535808424072676344233],
 463: [11113,
  3407681,
  628923387971796709441340150821854557913581310227044359824072832706676392247229855176619076633284826951891707393081613810208290919],
 479: [33385343,
  6293443049,
  7428887369938569365573912381823074703193413648637832036793563991856837158431295806505751058260493620667409719901084694185326041],
 491: [983,
  7707719,
  843817406658217122659918090830470893003399128476171457389533322631035126142677792700918220649813581058604251752928047795135831448579223711],
  557: [3343,
  21993703,
  6416125528696558168688268234810295605564949381116559270010369428469312695837126915215901320575633117248770546631104498924016155625521277184128812176074684999],
 569: [15854617,
  55470673,
  2197092504979940333495931439578759550563149826147396903624131304226803755242486587154735314565315090142962274281650175114649036310648131530063859244762293671],
 571: [5711,
  27409,
  49376712710762405068797778169570549163934995242836423038180455093651256338801690047543247042837617411574728386879508583723275511875859162982742149438816087977791553],
 587: [554129,
  2926783,
  312324498763037541964352443569527655839995493499517867544684906260348629736971604157822308313958804288023772370124581551173679349292040097761444615666713907505453361],
 601: [3607,
  64863527,
  35471592915846971611761284522335718240146788795718453993482701842577505470302273171353780850775279693945678834840172667458519819530578294315203146051414787170811175493759],
 617: [59233,
  68954123297,
  133162933696720252644109076239739315294641129598571214674268232878869403201703608966454713865163367575359986404237817149731676559992850220509804718874844608767326097407871],
 641: [35897,
  49999,
  1173835097,
  4331124388227537867882431295014140277674717868883945609635571318249893552551045412577643866352044484645254190316836129208950722878801697147739513742302549921826573333064716161],
 653: [78557207,
  289837969,
  1641518783151614502311505532153576801641811661695207527584609323899811520528432253831281401328915776960430833447998659045601114408444242208878923795548831700644761879222543709512777],
 701: [796337,
  2983457,
  28812503,
  15865578195367,
  9686645161734711363697372445438627197806115468935259901589260373743560800743202873269976114991606538760444137933541217015350034390835020998811801805432214054700909139753066196239],
 719: [1439,
  772207,
  2481831853628975239734324283683350274917109400971062161087619357919015825532905467342080904365328434433942599199768597162844127710603241348951685886630958534414913327306172329325612742053655244488373754631919],
 743: [1487,
  1219280833,
  14904366017,
  1712216018506249606407831452734243572920960441744220468439904700189164675275171052575051567087754970994687827298154275442714792321513872782669916067596365477250059678729642973584249294688940479455896401]
}


def is_pseudoprime(n: int, base: int=2) -> bool:
    return pow(base, n-1, n) == 1 and not is_prime(n)

def is_strong_pseudoprime(n: int, bases: list=None) -> bool:
    return miller_rabin(n, bases=bases or [2]) and not is_prime(n)


class PPGen(object):
    def __init__(self, size: int):
        self.size = size

    def generate(self, constraints: list=None) -> int:
        for p in self.generate_many(constraints=constraints):
            return p


    def generate_many(self, constraints: list=None) -> list:
        p = 1
        constraints = constraints or []
        gen = self._gen(constraints)

        try:
            while True:
                while not (not is_prime(p) and p.bit_length() == self.size and all([c(p) for c in constraints])):
                    p = gen.__next__()

                yield p
                p = 1
        except StopIteration:
            raise SearchspaceExhaustedException



class SemiprimeGen(PPGen):
    def __init__(self, size: int, bases: list):
        self.size  = size
        self.bases = bases

        if 2 in self.bases:
            raise ValueError("This generator cannot generate pseudoprimes to base 2")
    

    @staticmethod
    def check_bases(bases: list) -> bool:
        return 2 not in bases


    def _gen(self, constraints: list):
        """
        References:
            https://mathoverflow.net/questions/249872/generating-dataset-of-strong-pseudoprimes#comment614685_249884
        """
        gen = PrimeEngine.GENS.CONGRUENT((self.bits // 2)-1, 3, 4)
        for p in gen.generate_many(constraints=[lambda p: is_prime(2*p-1)]):
            n = p*(2*p-1)
            if is_strong_pseudoprime(n, self.bases):
                yield n


class FourPFiveGen(PPGen):
    def __init__(self, size: int):
        self.size = size

    @staticmethod
    def check_bases(bases: list) -> bool:
        return bases == [2]


    def _gen(self, constraints: list):
        """
        References:
            https://mathcrypto.wordpress.com/2014/11/19/a-formula-for-generating-strong-pseudoprimes/
        """
        if self.size % 2:
            return

        p = (self.size+2) // 2
        if not is_prime(p):
            return
        
        yield (4**p+1) // 5






def find_pseudo2(bits):
    if is_pseudoprime(bits):
        return 2**bits-1


def find_pseudo3(bits):
    if is_prime(bits):
        n = 2**bits-1
        if not is_prime(n):
            return n


import itertools
def find_pseudo4(bits):
    for facs in itertools.chain(_fac_cache.values()):
        facs = Factors({f:1 for f in facs})
        for d in facs.divisors():
            if d > 1 and d.bit_length() == bits:
                if is_strong_pseudoprime(d):
                    return d




def find_pseudo5(bits):
    for i in range(bits+1, 4*bits):
        if totient(i) == bits:
            k = int(cyclomotic_polynomial(i)(2))
            if gcd(i, k) == 1 and k.bit_length() == bits and not is_prime(k):
                return k



def find_pseudo6(bits):
    if bits < 40:
        for n in range(2**(bits-1)+1, 2**bits, 2):
            if is_strong_pseudo(n):
                return n
