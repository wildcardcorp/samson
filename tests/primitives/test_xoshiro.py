from samson.prngs.xoshiro import Xoshiro256PlusPlus, Xoshiro128PlusPlus
from samson.core.iterative_prng import IterativePRNG
from samson.utilities.bytes import Bytes
import unittest


class XoshiroTestCase(unittest.TestCase):
    def _run_test(self, seed, variant, expected_outputs):
        xs = variant(seed)
        self.assertEqual([xs.generate() for _ in range(len(expected_outputs))], expected_outputs)




    # #include <stdint.h>
    # #include <stdio.h>
    # #include <inttypes.h>

    # // # /* This is xoshiro256++ 1.0, one of our all-purpose, rock-solid generators.
    # // #    It has excellent (sub-ns) speed, a state (256 bits) that is large
    # // #    enough for any parallel application, and it passes all tests we are
    # // #    aware of.

    # // #    For generating just floating-point numbers, xoshiro256+ is even faster.

    # // #    The state must be seeded so that it is not everywhere zero. If you have
    # // #    a 64-bit seed, we suggest to seed a splitmix64 generator and use its
    # // #    output to fill s. */

    # static inline uint64_t rotl(const uint64_t x, int k) {
    # 	return (x << k) | (x >> (64 - k));
    # }


    # // # static uint64_t s[4];

    # uint64_t xorshiro256pp(uint64_t s[static 4]) {
    # 	const uint64_t result = rotl(s[0] + s[3], 23) + s[0];

    # 	const uint64_t t = s[1] << 17;

    # 	s[2] ^= s[0];
    # 	s[3] ^= s[1];
    # 	s[1] ^= s[2];
    # 	s[0] ^= s[3];

    # 	s[2] ^= t;

    # 	s[3] = rotl(s[3], 45);

    # 	return result;
    # }


    # int main( int argc, const char* argv[] )
    # {
    # 	//printf( "\nHello World\n\n" );
    #     uint64_t state[4] = {3975919803735480771, 6494387224254674270, 7230579324998084747, 10036663469039342333};
    #     for(int i = 0; i < 1000; i++) {
    # 		printf("%"PRIu64"\n", xorshiro256pp(state));
    #     }
    # }

    def test_256_pp(self):
        variant = Xoshiro256PlusPlus
        seed    = [3975919803735480771, 6494387224254674270, 7230579324998084747, 10036663469039342333]
        outputs = [6233253967866451228, 9184633799240047338, 5210896891085130846, 8709771722502753176, 6895691035419896585, 15221729946066148172, 16371256452063286071, 9271524334909283112, 8997441822150357743, 16993265931771249184, 16817999445493384656, 65609980624271741, 1765703909646084592, 7715090682405177938, 10707366513891765889, 10151935155847683720, 8127051001112846122, 16935304201972548611, 14987741503099947991, 14900892883598935746, 4658052692499773836, 12969201088268033524, 7136731914632278090, 5752393630032662194, 2840107028777667465, 9081227158870652551, 17414183278410781264, 13296128302596026302, 10151040618614803154, 3208559515944937976, 1202445543058050015, 5401845929111021897, 17786237897677439086, 18390022975844725279, 9433995998749073537, 7116891826207449655, 14781698304098578405, 14883618053809589842, 16839469228884727788, 9997875664594867796, 9267064167259811428, 13072488701380989638, 9598811653270219175, 8409283400402841228, 11204969897769750006, 14937075923269977631, 12765669033864776676, 8231154376293473152, 1252921932225681660, 10846135822444038318, 5018335615998951644, 6821075898082018144, 6543409918872295093, 716043492583592368, 3315299216921316854, 694898303149370166, 9072878566101843701, 13525068700222720866, 3504183010343678825, 7249014252088415097, 8063270313766753292, 9208941800890196368, 9298594560536165134, 5865425080079446576, 777810132925126598, 1338167865331920328, 11259451985634989612, 10001594126702012819, 12649263192181450961, 7147163523328718477, 6260624843771132377, 4813742960866311614, 17663520000153362744, 2398082872909927565, 10042360832277024852, 2429680452355301602, 17774531446312192536, 12327164412614000912, 7180250398151763574, 13803617936882190093, 16088530394302496830, 8915943070812839619, 17920678174135005728, 12278135503882141993, 4712424182347683158, 10073597354679592025, 7357562405109568289, 17995703854878689521, 10731924483653239968, 13616485538226927461, 16881498094253621553, 376657681940709230, 10173794217507478206, 5336203389351289271, 1831345832268463941, 9117058806554792354, 8096718434339583564, 3578371266382355533, 6305644997512781713, 8856359866346923414, 10186919487163937982, 12969001704000098017, 13327875806820230583, 12634287606601447934, 3862399480670370284, 6919229006568450452, 3702866277046571598, 10048950283139200300, 5819638862365319485, 1312449539453289978, 16277603590509934039, 14649428310749748197, 4867471797264612860, 15248976266010024231, 3181547756752953968, 17734832296627918928, 60973698525591450, 12563992325895993865, 3523433434249580580, 5852022731351572108, 396206011723912608, 16425686312301176876, 15184234964316474148, 15278249759412302939, 6856936550784248891, 16663320789962230832, 14425149047441737962, 7864698768625701940, 5322651221114580837, 16864284810382807301, 6699134769281051059, 18130204943462303441, 9394380718563484653, 5457524020936458123, 3877800482082990916, 3671120642804903283, 17503159743330992302, 684229733042003277, 726280039801092916, 9646735822141494174, 9451210383337872552, 15794935716012170045, 2868765975053661851, 8428463309887331625, 12194462484565405296, 346941573142470437, 8820294975720163008, 7767950200713996514, 1890084865268234739, 9103718005006490288, 2512273573685561774, 7755626373837432472, 17992564072083675303, 12638175959123209249, 18044607902539813192, 16996163280242304779, 6808700270766601472, 3936575087155562885, 6027981289285908307, 17869284701488084825, 370314997471453033, 7605713395764692548, 8494624419831709624, 4672469727983686317, 8284046363719434650, 12446988789215752061, 12495045392603604692, 11386238185520147571, 8448951424861773069, 7086966397152094615, 11882936641267410662, 10774827132791068731, 12170150595219054550, 1238802896753723696, 8837811002024742971, 6862446185586217093, 10284339314056610607, 13840465439094196207, 438000705210797285, 8492896582734138338, 14801913060295011394, 17687189778031691413, 461915107838986072, 14168813408694555022, 5468531031039549377, 5340685008609870924, 1248518051471225487, 7741657177311362560, 372614639658276489, 8801404100619650582, 2055231377892086787, 7347634962628820986, 8680284778252653844, 5279912192746991226, 15907737570125273336, 16139552286721356644, 3172907501292808710, 12523792910555494936, 16035695975076181309, 12870988272895131836, 15509533978950708224, 7903429103504512987, 10777219360775226074, 7115766989391244556, 9778553438918180680, 12911474916175918632, 7579526268797266785, 12112996550555232101, 4490108335547935363, 9848414219929228408, 15694570771387665046, 1555675273493610649, 4859740574637885571, 8560513246344995094, 11214694226496410823, 16284469221596933397, 13024110859363564745, 13829320448096286265, 9834824402071564022, 14914608243057537528, 1091401320065681053, 2794354044190966372, 14679174215896648417, 13043201206624244636, 16530176806752190121, 17658557799458029534, 11725060288075361011, 1051976576479561929, 7545395755510694563, 4508872497780863278, 12152917109603834348, 14485993825199496899, 16051933280346883130, 4904408323998666936, 18033995073875284319, 5615712607388566246, 17043649684797608527, 7958638334391498696, 17898990973416454191, 13961784926511488609, 317149630262682958, 167924952061682216, 3617424131092914443, 8050785538182434539, 13065457504599708680, 16890266325112759518, 2723696547357907902, 17999568266019641751, 17405731498683122908, 4634079398174186188, 2965081294959639874, 825588056586602371, 15062049094482455479, 6376706551290637695, 13200937641361812448, 9289329063703036823, 10540974017238186393, 10604765908987021143, 15674409291769833692, 4394814824972132382, 5590916467304640313, 7197006805353706847, 9092880947800895751, 18220956984255603384, 14983689085571762933, 15793573225654802576, 9650973252788400923, 2604653759893837630, 15769108097731935110, 15166360489853855992, 7336788687583105530, 11529136010722734823, 5795281110657305090, 116085734202680241, 369306355106766089, 12371610290068191613, 6376997569518479066, 11485847345420489142, 13956915542970148737, 14276570981528806454, 9709554667867496668, 9395836321080296980, 9759890409428113667, 15189888798284395197, 15382464429177826385, 4508397914314522575, 8521646945193454145, 10622525333775972434, 10847752332055611859, 5760796982722321466, 15643115363322547325, 368749060051990639, 16067161599364937905, 17516172935617642215, 1969494731998014736, 18311427025465720762, 15791749886947349466, 9063529603078719124, 1839267540930607263, 5029630229208945600, 14598834898863794101, 11411306797292363010, 7799929830808966226, 14965621909967123846, 6076338866341994722, 17933438699300658332, 17342267821043719097, 5146719863040512301, 13839735822958888854, 3591613120622653704, 14022258845359175031, 3276508677514299525, 9739023719845971068, 6321212596592093835, 7376771375795985536, 6183000350618494656, 4844145112916614949, 2905464205556267078, 7809813984542631021, 3396237500378501486, 591927862576985566, 17873180570454387380, 16760008704928735920, 17389934960432973837, 17721328206100231338, 6037508697585768035, 10374718281353279151, 11494993174948952482, 618220726456853867, 16642069440962779555, 610434694164556014, 1337559997059825340, 6107429833517003128, 5037589062389763369, 9610970214236300735, 13576371267602022419, 4247930200897712573, 2944483856452278168, 11993658556530891304, 7242488058903692659, 6419895494917924793, 11023178100254757227, 705556635142117874, 5941903640450611825, 5531430735771894654, 3785104040715857017, 14897498506359912361, 2833850787311281075, 9971474112798405947, 14497963118825507184, 17230069227782288074, 11113642733528599180, 5436127429948381998, 6932024293972275322, 8757124330534628498, 15676545530706882445, 12662739097226187908, 4729042441071840517, 17130629777628361189, 17622052969167480570, 13690955449413779921, 18159546441667923644, 9170119708197543511, 15062922174926566968, 11749877887015540416, 4543963659053551229, 7876839480352845045, 2172086594597843639, 7885272483213507743, 12754327390574182394, 1998531732971473568, 1095202001009898811, 10573730071576993083, 12494366989062853356, 14301783065104879147, 7016139633685187008, 12092329831968305856, 4519661011480046387, 7989204409561901205, 3399151146045119142, 11014384323597927302, 17475864476728150760, 10621158113081618205, 14107452463823416745, 8599439342331453563, 12966668614868746477, 10090197195397789753, 3009061919479376347, 17611533855895229580, 11296729788799225710, 4554158934753451064, 16003465369168977392, 8724619575729222787, 12798972238285203671, 12553335287341063666, 15693988511054568078, 17966099981657934545, 2884561841851330301, 2199607527139637404, 5170962940096715005, 349404363249605249, 6263375290355088769, 8796494706725235256, 15276273207728690655, 15575775308843518987, 14580962528852142183, 13174013550738311061, 14010312932137440563, 16653324020486525739, 833168939360365605, 10094581804841386094, 8905329536817931318, 17553703724661586243, 16448699892938838096, 16979230239892300730, 14936657168499341917, 625110655917909862, 11215108053874311177, 13084906519033642517, 4454779162523484192, 994435231041350397, 5317241889798000699, 2563689837990359631, 12312346737735120125, 1262618987519458669, 8579580179180553063, 8679976335211318299, 11515494570908671732, 9779263419635653984, 1835352908527391129, 421070466419280955, 3980605842349310302, 14979011630113161326, 14304952470395695189, 17937276966060482593, 1506853042478464153, 4097055755422541081, 4638696894517364019, 7200417544178978770, 17842480060745111254, 8459225433988703943, 13046753178113369568, 3220681759781101248, 4793517340285815563, 6550917165574086349, 4233877165956363968, 11709168707208541730, 11442820583427863636, 10097918813234937630, 984400687242835878, 6778441346822982855, 4337543574729393755, 10299969501602159050, 8903156086233696485, 17080136762800738593, 4624139719200593359, 17375404086261403994, 3047142685551999759, 15597582403298424513, 4980469971339102979, 2018212884461017153, 526410945992852849, 16793933331314039547, 3192311182405578096, 15589521102996468401, 3273036119787595928, 8741295802166311601, 2494860688407169688, 464558019507359595, 14534705024564054077, 16071813906214910429, 11086701683853136265, 14470462186153711615, 9470972957869749211, 9604312240051198190, 339211697528979224, 8123326553914610607, 15255206863768832274, 9989193039765046188, 51544331436839142, 11494287507071733966, 5274308412288442187, 15953484563536316799, 11703016483499728499, 16710302005396901906, 16303725470237673771, 17835521604493543985, 16492818977476216621, 11408754957611749856, 9919314411876892214, 18109721240185914584, 18005923325175796487, 2115212775377497093, 17719546611785444887, 361266959182376440, 16777568548277396183, 14607165484925466165, 13814227399700939829, 1664095388779776332, 12831150410691083932, 6367102157600547894, 14583940447513699626, 7329756304681540941, 13201195778031891132, 6701770040451414610, 15902566921829506975, 10500898805841138757, 12846581052664625459, 1555613180184048273, 952656790773389148, 397109795972648805, 14207809247623933963, 3795511426190946386, 10286180586020174022, 7105286401714485891, 9918548350880673949, 3797773974208735356, 13505975760222040042, 811108657453577251, 11153075305781943210, 14632812592361982623, 2063353207253414774, 18392744266431628526, 8729413063137066292, 16470252152452489383, 10011458181448648304, 13009656449690008976, 16036116174961606288, 16750254214022498498, 6562259727319528557, 13033061997075521387, 8304023383599339006, 4531009077288555934, 17209572245883015851, 16479792894492032979, 10491599578557117250, 15227274417660231961, 4415716573540429146, 12064606469967243736, 18397105252764744544, 6012050741909865203, 1247039809274476576, 14921134419223220229, 952110106199350714, 16108917454322837129, 9193980313021996770, 2989013618029045224, 4019326296336097714, 11184281284159241064, 14000173183560747095, 4797428605814728685, 13623030907235287088, 16186318348034304296, 13513213300630881042, 887368731119510873, 6117191012277941177, 138132783684298097, 7711946294611311303, 18104129604277887379, 3891762397333424066, 14801897610250918663, 16452801733038715444, 9920445137008115153, 2873074297096178310, 6917399286787419367, 11016178349122043796, 11620537451324681089, 15668575310111650873, 7129442351379193494, 3880212554783329904, 7687221350773869169, 13742412376312276254, 6752156029382799322, 7886087863317107484, 12946526760416047858, 11806114187488410801, 3430251956936861345, 13147248359069156695, 1662603512063964683, 10019233894926732843, 1114133970446788517, 13671959971368351979, 2098330986848832526, 2534384382658567174, 3996950496309444635, 2244177001277151926, 6949496042553084611, 16308890302229926996, 2546770498259998875, 10193186356090364990, 7055524259501177094, 6249796675023538736, 11455120954480723383, 13987930520872588821, 8345962751080231037, 6488642269224712728, 13101892832962672366, 3381182932991945842, 2683059933477300372, 13035914139038969135, 7261707939778595235, 897315863035734102, 6729418084399886203, 6559138181936011730, 14330495026361103879, 5879283040791025285, 9868743441683508585, 4325332362326240655, 4165884803440275366, 16615315087358175102, 15375688474520033631, 750931430543082394, 16840617592004805191, 6808057501709521098, 13487453031391631098, 9307123403701282924, 7909432501232763631, 13823774013741398691, 4753847467128577649, 8355837564556802250, 13363915053640697460, 10575618243300894323, 7500129606303950895, 9596555867420563929, 409451700681335340, 18002936264989668365, 193771215929471338, 12419494902061850590, 4919324451757831697, 12945753025590891485, 5079455155233022313, 6945464105769643278, 12075658790344872344, 10859925250447410077, 16332117413646138830, 14506835712192288593, 12906331497312238625, 2711772642602630473, 12376111239084523177, 2278108728866048234, 7220731571352525185, 15899620559238887895, 6052578052348998691, 7472006692081777422, 2228855811355438582, 7470263719984957661, 14410677027114672414, 8965756204319818199, 6423801800991220326, 2336915358298049109, 332733651820853075, 9559052716923498709, 7389776178517442339, 3106627110567331907, 8193174798571378276, 11185479798266122897, 6255483790970711445, 6700442241814063845, 14096036925588840655, 12804038850606450811, 947441874532954521, 5128127032726112098, 13627100627586092632, 18108297790321016529, 5274375465568201941, 11829762559198588339, 12620926887447355206, 13993739941292869222, 2640042079639328625, 5993704351465603427, 12040013760040446685, 15810196745207308957, 14066390680766168144, 5461279369357392076, 7178216187747367209, 8320822120566656819, 9788315100895540305, 14737642256123752434, 8334457257865054277, 5352718155655040002, 9427756671684090386, 9872272747112086706, 2590269306177003294, 2783595891799182006, 7704051913120681292, 9389965973496820458, 87051205632861934, 9656524096289135030, 14427033894320934233, 1329889533627505983, 17285305551340908384, 9186903852753563583, 1380843168768820384, 2275853053113673474, 887638662295248068, 11067441555978497884, 17473218748855463904, 14850544872429458903, 16279503306123233805, 6896195521551203380, 16522101929531235150, 5335961366869765283, 1296993087886822423, 16378488300049529890, 4635450234680109664, 5714036392149290997, 13098498082303670717, 16513877738969975149, 14422984029609082468, 10343426746216657912, 2903699010734223678, 13213999011111752315, 2213876380294835234, 2187509046717148792, 18376338430533765217, 41259043470121033, 15273020389615443475, 6902408053833539736, 6893174413089333231, 7944070738473308777, 9185916138372627926, 15046532730624961138, 9387410503640333905, 15827109806373200894, 4360605036327295213, 6037707618871836511, 16492116245347662302, 5858912767264557207, 4842768242673047248, 275175554190094003, 3460535182896809861, 15407358723247919734, 8228629488906953976, 12809222324357483916, 3950975571649258338, 2342235449257447416, 8261039002209636220, 8453548007779842273, 9936191750071754798, 3374860441325570226, 18356960770536588258, 1086788501940783450, 4491604171142868173, 6605013438725290236, 13809485410399875190, 1915310267673785271, 9331653489876589715, 406428364974936067, 4493785660922848212, 15228656614655861151, 17497492940480206159, 3784817382978309168, 13704041607473915589, 23561373779252465, 10017277786156900742, 1454587016271119228, 9975022069362987568, 2003555318111556081, 8971482820694811597, 987442535502055703, 7487581864966088444, 17422397458533966624, 10052124225184142106, 2820013074566121496, 991265367218190745, 5515580213419086790, 2708612520000708181, 18139417232432752876, 16423307220801073108, 5949479801441565942, 17286584677270883975, 10741808523909586975, 15918182474178329206, 9560427995649132554, 14072229702795138440, 10505998121798619643, 8947294347868437878, 746499314943906793, 17870076993119814755, 3888778589956229588, 14415393989344373877, 3487379889207232977, 17508031769756362783, 7208596229035733318, 12002288386849127197, 1857633051392276751, 8364482912387261598, 15205636497661078489, 3143622624272978152, 4565408051378324161, 4800746739745956155, 6212501687661352318, 3135956524506318327, 8361519039716954134, 15650698317090022567, 9809256658332422255, 8861048391896946335, 11604391259299808160, 3281778799166523201, 536802700483669164, 9018263910830130374, 14748237935009763963, 7867240554801038790, 294574741008212196, 14922632486154067448, 2206868832587514255, 2614081119165385345, 9567649504881206789, 15708600161162524924, 6292030546992243349, 6420564072618764693, 13654883335620714027, 2503591258429584469, 7679196803828305821, 16622805191865958253, 14475359209710580521, 3136536883986123008, 4598500076934054344, 7786601925941047828, 5907462881306552502, 17979177488097416748, 15675874496888677849, 4072939276739884955, 13458746593932282029, 16074642746938430214, 5215812950880121887, 3970320076777407570, 10136580081602265848, 14966733517715928194, 5546739594193843054, 8816772256306171932, 5351545999637076799, 5940603782844514932, 10977385040987229537, 8673680812114329857, 7842922939411683736, 17929196611440285552, 13454703283090319836, 7132858157418223134, 4321886699908263834, 3044851117466535712, 9743060898151933772, 13570367309413618351, 17840301053641276731, 15297656232634694272, 2071814682632286531, 8006697758758770260, 8584900880042041847, 5768004726379147633, 11331807010728207420, 7908058630648464171, 5322533874547324815, 17253707789944227984, 11119766636147514587, 5022640931483646427, 3914223446784945272, 11603133250271087550, 609348211641089243, 7579262476634328985, 16714287607114033454, 10785437426585590236, 16956208732845549662, 13714817598086421799, 8135003823655347626, 6203701565531400514, 2621089804053325990, 7293757498380646789, 17679044187958924821, 14584432200124089490, 864391039991552753, 6162963982978199983, 10798308697674307643, 5432328621292687727, 7656956543285810484, 9487838065004012008, 2378952317265766729, 5956678383319713704, 4572736531184127778, 3647622045254088076, 11783230652493532251, 18185250410437757963, 11503716286483189169, 14458486831664618213, 14158414587190644478, 8535456205201969613, 10734617964081172692, 8922116315424364402, 10684501066907703422, 14411647705766763559, 12168850678625528522, 347930563721556371, 15263270182380529944, 15332508805595479233, 8948564127314875923, 3174625049764349997, 5582042264666400609, 1310380222706378606, 16303412979333609099, 11685106440415641395, 1975678719768606496, 2905453069343332490, 303568504312214585, 13705837683595648129, 15060680353478410853, 8584311646428321608, 16980729551754010318, 18174751875686639842, 10840979395094540896, 3474971857505797252, 14769700824520395164, 6126937231145000176, 7023373743119866845, 14406740933224841744, 8746861117615703912, 3178496392944422498, 2969005005684849924, 13097960533797940683, 12004851937216564054, 2492033763677465572, 8999332275619025014, 9886201116169594238, 3124206988322890731, 5262924577929060107, 11488274015755305265, 1401456007956661117, 2454438797516370711, 2505247768866088397, 9956407230561857359, 355315516174323762, 18344350820937870909, 5897131146248195528, 3692629247330039531, 871208533832028670, 15096589727299778152, 12859092235397206243, 3923816794728758730, 12722509340237358918, 17006483776285373444, 3200337530227075656, 6762570484851551119, 6271473844314842177, 4950243608391342968, 13580914966678689445, 16140176517960784728, 7061397574092657596, 2939195916535283663, 16051000539844059316, 1328948650179419283, 184929566075278300, 939574080413143703, 13698617713932800994, 16941116539537650407, 10013311263078524528, 12603405515524178588, 12908006809110667157, 10500380942430053101, 2757342892733676461, 17227721015077338282, 12807342415340719562, 1310584113942603806, 9149091679879005781, 8610360357252321486, 18067556381153118137, 102373779147157232, 16403843491326600323, 14820424432858311305, 11246215439225074843, 16427493473687178803, 8428006605709041542, 17312453538724293131, 15145764691438837245, 16370615331525787511, 3047458802011309056, 2860718913475584997, 13088554997269806624, 16125154315720266522, 5866092415177905495, 4227671589274470614, 7313469104629385288, 2208743201074059559, 6611921699465462509, 17972986492188535646, 11820144374842105377, 12447506409512202901, 13097832710932993306, 14578312550460263154, 9874219301338024175, 16471171953064896166, 7551510604320321299, 8146591982359447427, 12302221204290331394, 4575439952154191690, 11387308946238360615, 10786957585514918604, 7902668129051520565, 8230179842704820237, 8055671841820863473, 4616444555521511261, 1301554859962280854, 14809217800962599572]

        self._run_test(seed, variant, outputs)


    # def test_crack_256_pp(self):
    #     xs       = Xoshiro256PlusPlus([Bytes.random(8).int() for _ in range(4)])
    #     out      = [xs.generate() for _ in range(8)]
    #     other_xs = IterativePRNG.crack(Xoshiro256PlusPlus, out)

    #     self.assertEqual(xs.state, other_xs.state)



    # #include <stdint.h>
    # #include <stdio.h>
    # #include <inttypes.h>

    # /* This is xoshiro128++ 1.0, one of our 32-bit all-purpose, rock-solid
    #    generators. It has excellent speed, a state size (128 bits) that is
    #    large enough for mild parallelism, and it passes all tests we are aware
    #    of.

    #    For generating just single-precision (i.e., 32-bit) floating-point
    #    numbers, xoshiro128+ is even faster.

    #    The state must be seeded so that it is not everywhere zero. */


    # static inline uint32_t rotl(const uint32_t x, int k) {
    # 	return (x << k) | (x >> (32 - k));
    # }


    # uint32_t xorshiro128pp(uint64_t s[static 4]) {
    # 	const uint32_t result = rotl(s[0] + s[3], 7) + s[0];

    # 	const uint32_t t = s[1] << 9;

    # 	s[2] ^= s[0];
    # 	s[3] ^= s[1];
    # 	s[1] ^= s[2];
    # 	s[0] ^= s[3];

    # 	s[2] ^= t;

    # 	s[3] = rotl(s[3], 11);

    # 	return result;
    # }


    # int main( int argc, const char* argv[] )
    # {
    # 	//printf( "\nHello World\n\n" );
    #     uint64_t state[4] = {2975662432, 3202308313, 696070318, 2255356158};
    #     for(int i = 0; i < 1000; i++) {
    # 		printf("%"PRIu32"\n", xorshiro128pp(state));
    #     }
    # }

    def test_128_pp(self):
        variant = Xoshiro128PlusPlus
        seed    = [2975662432, 3202308313, 696070318, 2255356158]
        outputs = [2531143803, 3770015569, 1377928353, 1709953194, 1725375891, 2982697874, 358148492, 3336626130, 3708852918, 3225714008, 1262851043, 1528320091, 3312373231, 321203370, 2727044756, 710005268, 4271596629, 2556089715, 3955779976, 32926621, 3925878099, 2085884424, 1737091391, 551927694, 2806622148, 2270569521, 4268956337, 2247642531, 1262924564, 1321008179, 1299888738, 2332731840, 3452443280, 748025453, 2742855208, 2051308817, 3103604232, 144212142, 4226127084, 2053431159, 171048383, 3074009680, 2623689538, 2342198184, 280576227, 3243412895, 1384502465, 769722918, 2714180724, 4088018705, 1845472982, 1532373916, 2480926717, 2415449836, 2220603778, 699381406, 1534763703, 3725521096, 4228895495, 2993382514, 1349349276, 973769338, 1651858438, 15652459, 1489862431, 3862514593, 871931822, 246056491, 3152377981, 1253152660, 580873679, 3099015878, 2049168239, 161394870, 963768028, 2976992764, 88752494, 3307153879, 4159105965, 3109646826, 3580792728, 39553578, 1394099305, 4218316141, 2838324806, 3812662939, 3410544434, 1477206338, 816166215, 2542922137, 1129743251, 2238272045, 364853825, 114648792, 1529230369, 2556708087, 3592117916, 4235742987, 1169867009, 967068696, 3264976424, 755406578, 1448984708, 2571061111, 157583010, 194982038, 223778539, 2102350050, 2739870939, 1861589224, 2394319495, 912065521, 2122609895, 961410001, 1614345841, 2790833123, 1835985967, 1410665345, 2595873483, 2609574082, 1906664593, 2493657861, 3009072345, 3902179277, 2314023577, 2360508590, 897325852, 631566087, 3446903822, 1925503955, 668459416, 1543461547, 4199468583, 2351490216, 4284626777, 3754821397, 201912978, 2084627458, 3223630788, 2021150350, 1212923489, 3101915545, 1409352629, 1143109795, 2024248168, 3421084864, 456625738, 4118015816, 767714160, 3251625049, 962703463, 3521502973, 3627027334, 2743275308, 4253409168, 2867159935, 53573760, 3773126909, 1411211734, 849707314, 2875941397, 574075886, 1752803050, 2281967758, 219552846, 3268669638, 2896065793, 2576687300, 1933998493, 1117061933, 3639021728, 3628862136, 2845383386, 4118846174, 914250613, 1488956685, 644748004, 85444967, 3091162184, 3651781832, 1212864859, 490013748, 3684215670, 3415210737, 3590655136, 2270245551, 1411633117, 1944685017, 3496231163, 1536089241, 54377121, 2699990528, 3869315422, 4191783677, 4133382327, 1788967669, 4171740994, 4065382679, 3658686875, 3590844172, 3727434935, 4178766269, 3452910348, 1423231376, 262641965, 25599043, 2846804608, 3852524254, 3109456012, 713333180, 2097109442, 3611974128, 4219843223, 3218940264, 1531919305, 4055588512, 101419778, 86649673, 3481885844, 732206241, 845703065, 3536810722, 3108970142, 3512618747, 2146131641, 3121715004, 4239728440, 3841097683, 1524285913, 3446622895, 4096309499, 789582150, 2460471648, 2404535011, 1045015093, 4149354786, 3498238843, 1468151432, 2689799756, 3508503715, 2804511855, 1578965333, 3038867271, 106651190, 474356613, 2885682047, 2495547130, 2784053394, 1044733509, 2985149330, 2763745710, 24666463, 572819918, 3358005946, 3155946858, 3992074200, 2781284796, 687338831, 2859445339, 1332612880, 2145431124, 3258080250, 3344260801, 2610386488, 4253828960, 2320303038, 776072232, 1547143471, 969560966, 3140168248, 665778056, 3083266638, 2084193299, 2093156148, 1980844215, 3011464902, 3350889443, 1583923380, 1554662156, 1755327759, 4090049476, 2767872843, 891016481, 1942239828, 3408421031, 548367668, 1891760125, 3549933377, 2580352812, 2196526278, 2913214930, 1918831375, 3334251164, 1751097847, 3248370811, 344237124, 1402282332, 2965925775, 2903116471, 3484977133, 3288408070, 797024371, 2401935257, 3074861005, 3452660810, 117735771, 156669695, 388138954, 1464930868, 1777944402, 3225860622, 662505835, 2808729853, 1623106075, 4071223529, 4019924423, 794095132, 1929782266, 651997794, 3418161369, 89306792, 1230625475, 1851873482, 2275299933, 1004267131, 1039980846, 3669673053, 2335869455, 2335731762, 859875018, 2252129500, 2693866867, 1187637511, 2123872223, 2049013122, 1113910383, 2727412063, 1942949216, 2358305736, 3537707761, 249073670, 4010050765, 456673123, 587300804, 194203608, 3457748108, 3243167278, 2509576930, 669788085, 1319602578, 2328501842, 1268528618, 863796591, 3379023273, 648732391, 376694563, 1850657742, 674488491, 84964862, 3865325296, 2492514194, 1411774267, 3336808349, 4285001349, 3367457854, 2099739115, 982838424, 2172646134, 2185665243, 2733206714, 4200534211, 2232507041, 1398747967, 3274897352, 632960916, 3364026261, 2712695722, 2755320579, 4252321004, 3507366394, 2169977458, 4222573968, 1056016225, 1042776009, 2358023439, 2900663689, 1460203494, 3559798410, 10368644, 716273431, 3219140071, 3282564493, 3673390661, 3819562630, 4185599549, 29096150, 3871197567, 2552794841, 3703698001, 2620795469, 4144139784, 49763380, 2979791665, 4249617344, 3899948076, 2932841913, 4237583245, 3946569949, 2059827371, 3740143675, 3569332402, 300680690, 2385910052, 2583334957, 2676421902, 26293706, 2332392552, 3722193962, 1448044615, 2768976056, 2155967260, 3522496452, 3711743577, 3473411387, 4187045137, 2139729601, 903598459, 665003333, 2125973562, 1180567752, 1860381909, 931250295, 1611131023, 3836103449, 722473540, 2814230699, 1863050895, 223327854, 1562575532, 3629107672, 374538782, 1848397820, 2889538624, 331631253, 3238930094, 193915469, 1513225917, 1423835775, 2702855001, 4156651790, 185906581, 3179084351, 508540467, 2089820296, 2782842395, 3994713226, 2817717876, 3900715476, 2747205043, 3434018232, 2249864773, 4089876134, 4106218834, 3120962222, 2738048191, 873610674, 3858733068, 2454058301, 1697662383, 1248799390, 86054469, 2648016851, 426571336, 434470044, 76987611, 1822061209, 2890363629, 1197981782, 457146571, 3174456551, 2536466345, 531707467, 3557014193, 2052688631, 495948137, 1797263612, 3547127015, 4187017294, 2358029515, 1556838012, 1923035223, 3698663360, 3508941909, 230141876, 3784797686, 3315467776, 1062816892, 2036222893, 280058270, 2760995187, 852513750, 1817869000, 2754355170, 2862069224, 1294118942, 628600559, 3662705041, 128548334, 1201791126, 3790332522, 1904174023, 4097986155, 534259687, 3135075919, 2097882507, 368454531, 4267234089, 2143475381, 2476990669, 1154478585, 1354314665, 1653128992, 2527015075, 3120061613, 3730730836, 537642737, 3966873874, 3966806451, 953683003, 2254863748, 3188897433, 1484059980, 3145169673, 2295705037, 4189374584, 1354517473, 3682572969, 568288742, 1110040664, 1893182870, 462438166, 1667786978, 235744463, 3961216491, 1469739813, 2537892585, 3727181861, 597586281, 3398341794, 179295971, 188007125, 3982127425, 1898839913, 4144630522, 2368735648, 899905557, 1186360285, 3973036837, 1813408250, 613474929, 4119839163, 1621079254, 3222727439, 413767967, 3881558182, 3291978673, 2456553412, 2059726306, 250102772, 1911280034, 1770845886, 3709159208, 3774721053, 436685039, 3160034822, 4219429210, 2228964813, 1929059851, 2958060901, 2784398120, 3811263029, 808682334, 3644008666, 2214569339, 4232868149, 4068966851, 3230514579, 4218564749, 1142610806, 1503381411, 1316102677, 3145105363, 2934413871, 2612096489, 2696696893, 275815001, 2714027713, 2860348216, 2578665936, 3022321031, 1364899996, 3838084431, 1570215637, 3016944437, 846381587, 3665075829, 1513050346, 2891988328, 709609813, 1160653549, 946053728, 1039297923, 2576133491, 3171552757, 518126774, 1788151567, 2400887781, 7865254, 2549489849, 202560931, 3902975723, 622805266, 4155626301, 2233863984, 700725228, 3926111042, 4244943595, 952023922, 3602643415, 2265853377, 3056633196, 2767987852, 2684910836, 2667026707, 1353564669, 1577699391, 96871902, 2577102719, 4204181838, 1367369641, 3111070203, 1604871843, 3268769220, 2418794189, 2001397518, 2229596245, 2646873041, 1676213890, 179413679, 1641054611, 1094160675, 3062242349, 7709108, 3219593114, 1997885419, 655895505, 2149875971, 1206373055, 1739484903, 563031063, 4085755292, 627512266, 1800317587, 849959939, 886101373, 3231732417, 2457407682, 639452097, 4040883697, 3713943757, 3421219953, 4017380636, 1903950693, 2295106747, 913629494, 3510414921, 3970032064, 4123262913, 734496365, 3519834330, 3635130954, 3829536279, 363303595, 3425613960, 2073921748, 948234136, 2361423541, 1525304683, 824570507, 1497787233, 3678949469, 978260883, 76453356, 382491305, 1557255545, 3306609816, 3025479560, 3164559425, 3613990356, 1026939060, 1330879972, 2922561320, 1471834599, 1772208710, 3383945894, 2210811935, 487093790, 102915256, 3183276935, 1918639339, 2786232522, 2380328743, 4074379790, 4082847420, 2017965896, 2020201097, 425055735, 365056423, 3429684761, 1101407224, 396835824, 1645067901, 3007012871, 2220684132, 3169337799, 3188849020, 2981205904, 1997274975, 459592732, 2431678363, 1143896228, 3982360733, 895779179, 4109384525, 1888309356, 1735289733, 2669544781, 4033843533, 2953066856, 644646355, 149205354, 669269550, 1961630790, 1294635274, 2615145981, 2864635168, 4120743488, 2351467114, 3524097409, 3172860557, 1391055734, 3992810800, 3893220025, 824588745, 730812001, 80545217, 2583097622, 1037569768, 3281032292, 2490687337, 2962928066, 820562317, 1646319273, 2816882839, 900574689, 1821444788, 2628318541, 1986900601, 3284704566, 2569130461, 2414523587, 3462927716, 56795364, 4020784392, 3030384042, 2132838245, 2680646662, 363938085, 2196107546, 3077866958, 1801467933, 2082997219, 585174800, 4110375735, 1269680791, 2250938876, 3073304518, 643692288, 3232074112, 3529940799, 11052106, 2031348236, 2572644663, 2876401387, 2443039794, 2501116552, 1800430218, 3372411799, 3868867760, 1123236371, 3569419942, 4172183255, 1385553426, 2601612275, 550469823, 2751947111, 1238530367, 1438144696, 3239372998, 2509338885, 2776732897, 696187806, 2535489347, 3270487355, 2897440974, 2855469630, 951658832, 1697229367, 1026447760, 542173995, 648412321, 2789946502, 837587992, 2769650351, 375603228, 2855449516, 1799138722, 3212565652, 4206163479, 3719037308, 583576448, 4211926611, 591946624, 1002549302, 4068651654, 1382570059, 461632285, 700201108, 4258901474, 3437790301, 2564132099, 1412630438, 2779108657, 2780692075, 3151448524, 2906094066, 1538640945, 384702109, 766106338, 500660040, 2596776572, 1913479504, 125457799, 2251540692, 1387951352, 3199694827, 3882518456, 3774171007, 3415485769, 2231968374, 3215306232, 27593983, 4265280086, 979607231, 2000480660, 2124325434, 275852816, 2721510672, 609792276, 481855887, 4127519208, 4285855478, 3848784781, 2159724824, 1859575870, 4222594764, 1161715797, 2670846641, 3244666298, 1117374959, 3271958239, 997720935, 804968146, 3407642627, 4167713314, 2210343039, 1008523939, 3093350232, 3272882048, 615215791, 1535478648, 3550578681, 2193998988, 304940826, 2208832737, 2315060415, 1250375199, 553512916, 2409054176, 1858435259, 3602087676, 3946674826, 180767418, 1261294064, 1665194478, 1747315464, 3787278510, 1276419364, 3209470525, 2120860311, 2588300167, 587771994, 4110914866, 1380226265, 464004853, 1147180120, 2858670021, 2912799609, 2753895473, 3356429012, 395569069, 2337674104, 1965844897, 3304947022, 846609206, 3709624637, 2614334945, 4014316816, 3335256571, 2302109934, 1779751, 1629359319, 3084495092, 2105850127, 1282548121, 1569545446, 258704706, 1639635186, 2121661551, 2735795989, 1439469327, 1492581675, 1443605102, 3901531512, 546362963, 959857114, 1489949027, 3569055719, 2537398515, 3960093919, 1270461882, 3754270094, 3730781030, 803929544, 1311354029, 1750452602, 2240307992, 158383688, 3179160788, 4008106847, 1846775306, 4176051602, 3081822939, 3958305179, 856441181, 3714502201, 1534547037, 924018642, 773777859, 382743469, 2010230848, 4210193583, 1466664363, 4100958291, 227728725, 810134535, 180469955, 2607472125, 2937592741, 1196425102, 1978335093, 934369227, 4101858506, 167569017, 2735750222, 192697776, 1315600355, 626206783, 3674932222, 3724541949, 2065533985, 625943599, 3006066463, 3571143508, 1084121352, 1248699815, 2812132674, 1662737461, 609444388, 781115028]

        self._run_test(seed, variant, outputs)


    # def test_crack_128_pp(self):
    #     xs       = Xoshiro128PlusPlus([Bytes.random(8).int() for _ in range(4)])
    #     out      = [xs.generate() for _ in range(8)]
    #     other_xs = IterativePRNG.crack(Xoshiro128PlusPlus, out)

    #     self.assertEqual(xs.state, other_xs.state)