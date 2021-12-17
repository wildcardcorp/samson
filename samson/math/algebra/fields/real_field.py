from samson.math.algebra.fields.field import Field, FieldElement
from samson.utilities.exceptions import CoercionException, NoSolutionException
from samson.utilities.runtime import RUNTIME
import mpmath
import math

class RealElement(FieldElement):
    """
    Element of a `RealField`.
    """

    def __init__(self, val: FieldElement, field: Field):
        """
        Parameters:
            val     (MPF): Value of the element.
            field (Field): Parent field.
        """
        self.val = val
        super().__init__(field)


    def shorthand(self) -> str:
        return str(self.val)


    def tinyhand(self) -> str:
        return self.shorthand()


    def __hash__(self) -> int:
        return hash((self.val, self.field))


    def __pow__(self, other: 'RealElement') -> 'RealElement':
        return self.field(self.val**self.field(other).val)


    def __abs__(self):
        return self.field(abs(self.val))


    def __round__(self):
        a = abs(self)
        n = int(a) + ((a - int(a)) > 0.5)
        if self < 0:
            n = -n
        return n


    def __invert__(self) -> 'RealElement':
        return self**-1


    def __neg__(self) -> 'RealElement':
        return self.field(-self.val)


    def __eq__(self, other: 'RealElement') -> bool:
        if type(other) is int:
            return self.val == other

        return type(self) == type(other) and self.val == other.val and self.field == other.field


    def __elemtruediv__(self, other: 'RingElement') -> 'RingElement':
        return self.field(self.val / other.val)


    def sqrt(self) -> 'RealElement':
        return self.field(self.field.ctx.sqrt(self.val))


    def kth_root(self, k: int, return_all: bool=False) -> 'RealElement':
        if self < 0 and not k % 2:
            raise NoSolutionException('No even roots for negative number')

        base = self**(self.field(1)/self.field(k))
        if return_all:
            if k % 2:
                return [base]
            else:
                return [base, -base]

        else:
            return base


    def get_ground(self) -> 'RealElement':
        return self


    def log(self, other: 'RealElement'=None) -> 'RealElement':
        if other is None:
            other = self.field.e
        else:
            other = self.field(other)
        return self.field(self.field.ctx.log(self.val, other.val))


    def exp(self) -> 'RealElement':
        return self.field(self.field.ctx.exp(self.val))


    def ceil(self) -> 'RealElement':
        return self.field(self.field.ctx.ceil(self.val))


    def floor(self) -> 'RealElement':
        return self.field(self.field.ctx.floor(self.val))


    def li(self, offset: bool=False):
        return self.field(self.field.ctx.li(self.val, offset=offset))


    def sin(self):
        return self.field(self.field.ctx.sin(self.val))


    def cos(self):
        return self.field(self.field.ctx.sin(self.val))


    def log1p(self):
        return self.field(self.field.ctx.log1p(self.val))


    def is_effectively_zero(self) -> bool:
        return abs(self) < self.field(1)/2**self.field.prec


class RealField(Field):

    def __init__(self, prec: int=53, ctx: object=None):
        """
        Parameters:
            prec (int): Desired precision in bits.
        """
        self.prec = prec
        if ctx:
            self.ctx = ctx
        else:
            self.ctx     = mpmath.ctx_mp.MPContext()
            self.ctx.dps = math.ceil(prec/math.log(10, 2))

        self.zero = self(0)
        self.one  = self(1)


    def __reprdir__(self):
        return ['prec']



    def __getstate__(self):
        return {'prec': self.prec}


    def __setstate__(self, state):
        R = self.__class__(state['prec'])
        self.prec = R.prec
        self.ctx  = R.ctx
        self.one  = R.one
        self.zero = R.zero


    @property
    def e(self):
        return self(self.ctx.e)


    @property
    def pi(self):
        return self(self.ctx.pi)


    @property
    @RUNTIME.global_cache()
    def mills_constant(self):
        _mills_constant = RealField(23000)('1.30637788386308069046861449260260571291678458515671364436805375996643405376682659882150140370119739570729696093810308688223886144781635348688713392214619435345787110033188140509357535583193264801721383236152235906221860161085667905721519797609516199295279707992563172152784123713076584911245631751842633105652153513186684155079079372385923352208421842040532051768902602579344300869529063620569896872621227499787666438515766191438772844982077590564825560915004123788524793626088046688154064374425340131073611440941376503643793012676721171310302652283866154666880487476095144107907540698417260347310774677574064007810935083421437442654204085311165490420993090855747058348793757769523336364858305492927387281493416741250273266926840468154062676311322374882380011804120628601384191443885715160918938894478991212554338474935909274442208280226020332302710637502228813106477844481700372333640604211874260838332822176968781235304962300880267221110401606508880971834777831402249082184410637749400023282419270071233303228854128584088916313729295257781669730936517951304701393525757057288415991731506781288275420005462290126288405806701552761743270631625705587885293887371663631869096785158480771725887503591755610651534304682508915720529218979451918656896107079679454091800398939472486242136261078017853543289004499330170496366824138991559390863407971519521054913832178750248935369436911007271030372613750972234285323116168628543944188065497790739237618709141899171623410941638308575746659514814198482696364651230580936617898571875292558924261792245960356189889945433295534390881876592175906931349704982012002981508269262773957866658038145591108464886110468516407348185577243382357535106352307875344503736037838146195058744437695954021414795859146776591545494401109935654810772503967175528395344823084606557828681289689384614534165259471045306184655570366212320938191176810381233247253675736561304035755604547613371766377266971117183495978029379922544269328238014462785471209936042634321006067930688472340905417664961257818765871227138054411028447678272208307254218662463667140139208332516803107194312353439003733543362667688155625905758738529747773437738355179799412075295861926866856592393937944044411992374104665470412500729650562289210559394937378671958351698375401681664617904333164804654514551239786534043776844797858223960962567035174406052308516273142917789552042936119712189359417511822684797317199476896968574646542612093168137035545490473027842694285052774299830119108405852525490656936684918052060227862098426188943223273332962887985907514802843644810209721222062851531779152653379240571303754370370597347393652365911795290648972635555555224555386169027564729760620345978644195955284059662204269287015568072312327295604919727555511738117439498041178256210035809874869434916176191141295706845838552772863501841984663375127036529444439179207888054631776156250565779654136866796619380331130009197428721105633447629347130496591577215749135475277505222815477233978270120671561346966752804453952883111137252330053792614609357410427386312480186390768802945076995238398448614294191476796552668964049478665682961301301675438607090068292961653932904642971344179205976063902545223569955003052071195850888436123956828060826314788600212196350968420489139757361620582728000288149999846265315837340424306574514618190921607090999464130039578123880026534637749856602130498930866063860167711749535913793996985724202986141711750841749694602075413197419292673832233696943664475949535945764182503918416484065268129703655243164913157058869201706784764989192050345243177710382510270046152790744153335903760320635695814488343970457480747191673054881037020380739733012545080675386237181104881879417763684067705038190250759583527842546026758842178602262942258759036032893300473708351234243128370227522368019421280442334584092147812591553937623750349951252025035397409518550011784546409823614149011014385509097799760452725081702835606574395318910638350859635260229513451047445893832691237099494674629049061649152292459467031981572295275443336694369737587692027052974932948599484445311120001696102905319193242316698089865355152116152430880177196690349426332587516531945322075760326737735089096342377091494723463304853281714913663742781658034409201436443637441425875156889725905759765243559037733958553668812781413607074557559745834337002061889944349605480724879707723775757783637685477797660031287452066904181225452259669049728881890255242074528078789766062705701297442423605191625086793633902581662142837419236183835596389839562197072238370164172413015372794142720478835725712249198103805635092717683265524633642503935487435366214009638438506704846748273329440551876473106106359333538969800878455288880882758955653651575416672738952846733500282052735787205957746478395697144783863673824663593558975269844694518267167887273635864934818399661995116922325237131908258989790684856792379756950628129464604481007713651156385156554987043852085173926022404236851875777187118321674352074710183785603902974024102002135940276130313048350829959688693148574443720877611259682918744937065216856433203886927099820446716376366319501957660099023666608818680048958673949179266323712967806856317043428414258146940444748789412507270680282648847479528961522016841739598697004591313783325749705331757896415245432580622105659806570889155827539380090382025127737821128790944743435769808022587563440899915149346308117570878428464027551937639808867153736985463306927473302989228160716868505806448158298982405886146598699032059023965893915565575840169191025711877427271513432029157486196601246695745900462760630594646774548114419602536600284415427826762959333445514857637940237005116623163674563171581825468449292558236197212588593812550247928587066681046691326526742894535620510883580276188405574854937376159074089242727557916553354542070006329370831815974640003811308093052888435355773535898559497944446328484883408971205935215498298829189876847064787638520769047247066645816369514711901005020144329876805116217157416057484395140423548295613811506044306623318085817279115834644789870485547517440088915221097258138917056727586684466400405569873054936863405913311968464665816382681217100998412847671425263323194049631673095457966054927109350885466276364069186561794310343022042375220382772217953256525551904146485053285357535237996706188326965690379894418952087818808745146620799001529955625302605418936611702679188260831989450025708813052528968949777641124868829276075588145077731317588025395755322566729331468845113607860822372293902580486707922641593180424819040420206821539261419442811920518128113821528108707138765152324308993856330857983714084031464267010755656427539174983268434634064456155803691866791479798061632243905779666598936016240402809963846427106357628850537662456090881943230011663758479632310329538234572312801137496440939882446584456055239393711146324194901740423381065700955532841429577270781677779128815119265114237841584078799598123992951398684353191107306')

        if self.prec <= _mills_constant.ring.prec:
            return self(_mills_constant)
        else:
            from samson.math.general import next_prime
            nn   = 1
            p    = 2
            prev = 0
            A    = 1

            # Check for precision overflow
            while 'e' not in str(A-prev):
                prev = A
                A    = self(p)**(self(1)/(3**nn))
                nn  += 1
                p    = next_prime(round(A**3**nn))

            return A



    def characteristic(self) -> int:
        return 0


    def order(self) -> int:
        from samson.math.symbols import oo
        return oo


    def shorthand(self) -> str:
        return 'RR'


    def coerce(self, other: object) -> RealElement:
        """
        Attempts to coerce other into an element of the algebra.

        Parameters:
            other (object): Object to coerce.

        Returns:
            RealElement: Coerced element.
        """
        if hasattr(other, 'ring'):
            if other.ring == self:
                return other
            elif type(other.ring) == RealField:
                return self(other.val)

        else:
            try:
                return RealElement(self.ctx.mpf(other), self)
            except (ValueError, TypeError) as e:
                raise CoercionException(other) from e



    def element_at(self, x: int) -> RealElement:
        """
        Returns the `x`-th element of the set.

        Parameters:
            x (int): Element ordinality.

        Returns:
           RealElement: The `x`-th element.
        """
        return self(x)


    def __eq__(self, other: 'RealField') -> bool:
        return type(self) == type(other) and self.prec == other.prec

    def __hash__(self) -> int:
        return hash((self.prec, self.__class__))


    def random(self, size: object=None) -> object:
        """
        Generate a random element.

        Parameters:
            size (int/FieldElement): The maximum ordinality/element (non-inclusive).

        Returns:
            FieldElement: Random element of the algebra.
        """
        return self(self.ctx.rand())


RR = RealField()
