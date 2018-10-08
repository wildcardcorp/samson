from samson.stream_ciphers.snow3g import SNOW3G
from samson.utilities.bytes import Bytes
import unittest

KEYS = [[3226041728, 3992666375, 2289492798, 1473215541], [1711287105, 3801293945, 3809554487, 617826609], [2260982350, 4375978, 2598141984, 3165437523], [800974060, 4213426062, 758319217, 728743225], [478691556, 273863540, 1038665175, 3129899243], [3173667502, 2258146840, 2383015850, 3711979024], [1529433082, 2827559085, 877795441, 3172568462], [465292044, 4043658343, 1896154902, 89749742], [2367727624, 634854590, 1830300284, 329999565], [1754712691, 3826164079, 2721818902, 4066272772], [3805313030, 3340446611, 2220753511, 446362725], [3834554660, 2708929705, 3998930801, 2090770848], [3250118495, 3754557348, 1617824872, 3523211956], [2003554873, 1930009262, 774590986, 3459914049], [1698234153, 4257844611, 2663687485, 3636594849], [1298725324, 1032375834, 4262007636, 1548030688], [3445081018, 3206577860, 3276696724, 122668705], [204836582, 2901677653, 4235649166, 724948440], [4148176483, 1927676682, 263232675, 1480059886], [1139538199, 2255559395, 2020346176, 622974874], [1895034256, 3669159191, 4114676701, 1219063182], [1260444023, 3100319482, 2271677962, 806152959], [3142261755, 2057355656, 1526825058, 3254961854], [3574861345, 591879573, 3391123287, 3612702352], [2477800466, 3448459595, 4128930220, 2849082102], [397276745, 2184833712, 2437833545, 513013136], [47403247, 3644278717, 1182233689, 85001245], [1843421327, 1157328913, 2268793187, 1798959347], [1487650153, 454220135, 3177841060, 1008462805], [597544487, 3976905854, 3714293301, 1149154086], [3115384892, 1788182245, 918359215, 2492369163], [1887121326, 2649801418, 3694878429, 759925909], [3091150379, 2406861094, 3940240173, 3956350834], [632869106, 4241825481, 780113370, 3051435299], [1291062257, 1947165281, 3691211694, 3687109146], [2275021994, 1501065379, 671855220, 1374770872], [4186930182, 3610795610, 153997785, 2479428708], [767613501, 3748894837, 3639767072, 1900587647], [138398747, 2900887719, 2243336666, 3506866906], [3821110018, 794575149, 1335635227, 66476085], [952563686, 563030580, 1804412715, 3686890436], [2340775059, 436457523, 722307863, 3153444905], [158790028, 3329832880, 2433407082, 2549967136], [70480541, 2423298357, 2360785352, 2332782273], [927182094, 4263898587, 1665187369, 227174448], [2965590949, 1208095187, 1668556053, 872599658], [3457119899, 2261392603, 1734233489, 3994149304], [3355082763, 50813828, 2778133386, 1765096325], [2491171685, 1655733279, 2110527687, 3804955982], [180057106, 277751937, 3962674982, 2407627526]]
IVS = [[480085992, 1322008175, 2003298641, 3314258184], [1781688824, 1400311437, 1586113918, 310724660], [1438629571, 1301388173, 1934411455, 3390487056], [3796907914, 57842418, 3318885102, 1562628476], [1932072937, 2533992109, 4203236060, 995970538], [1800657934, 4022670852, 2540852208, 327462490], [31160931, 794599870, 1602607456, 3969854787], [3743503391, 3178169461, 4032802266, 112950439], [1574244424, 179527006, 1490232012, 2344545309], [37484170, 4270171305, 1343293852, 1984522526], [363414006, 3355240589, 2486246387, 1463380025], [2408029717, 1365708687, 2288714910, 1107487999], [3821173184, 580576759, 2082497365, 263386963], [3680823176, 2079764288, 1711731167, 1945417578], [2502526515, 3543777100, 1233003478, 856840185], [2023397005, 2895906883, 1582328516, 341109016], [3968897151, 1557629659, 1959526838, 2235789119], [1886240810, 274815052, 3682583186, 828947074], [2539805795, 1026614837, 2882460364, 150368042], [1249560088, 386207659, 2403273348, 3869689320], [3324376324, 1112721556, 1592660581, 2050170973], [787360512, 901859789, 1828797997, 1259276772], [315267055, 2717409853, 1464202164, 2484963406], [3800553810, 890977243, 2195081043, 1596296612], [3978805043, 4242937694, 4222366053, 2306935070], [923661940, 4245849524, 4157524007, 1529472400], [2086215219, 2296824868, 2187036008, 2081127027], [1793994550, 2840005380, 3434747223, 1946639618], [2083398180, 1976860605, 3323441377, 2663287484], [3143395400, 566953132, 2653420399, 1143801253], [1285101520, 3513097173, 2173862910, 260061660], [2817628628, 765885031, 1082478705, 3641179250], [3971312026, 202412984, 3239021807, 463219023], [3718953491, 3872800720, 4158835455, 3221188203], [1299210186, 4178723142, 776833858, 3779688206], [965658531, 1324193825, 214594957, 3067730017], [4066951601, 1546293889, 2205905666, 1604465895], [1183311009, 1763915780, 2566424776, 1968636726], [1874121350, 1997482734, 3279022217, 969907199], [3231752131, 1501341475, 26244788, 357341092], [3253662446, 1515219814, 1366001521, 2833809461], [1371823122, 46258304, 538274490, 1578440884], [2295864136, 2074260202, 845612642, 2990088528], [266377912, 3846690396, 3260157134, 2622530716], [1485844615, 3488940316, 2785177580, 622226085], [2335847707, 1298931700, 728927481, 1222409075], [4014721680, 3198994317, 142588162, 1207104931], [1916820145, 1723605534, 2220739516, 1019331247], [1071427056, 240672661, 3770863735, 2509437299], [3184299589, 403822928, 666567019, 1806492441]]
START_LOCS = [0, 642, 496, 715, 262, 470, 538, 263, 550, 170, 802, 929, 914, 705, 61, 840, 962, 658, 564, 952, 238, 876, 515, 788, 516, 910, 174, 936, 304, 92, 918, 716, 370, 276, 583, 726, 305, 494, 892, 732, 518, 203, 665, 158, 810, 886, 228, 281, 243, 507]

KNOWN_ANSWERS = [
    [3189771380, 182462577, 1631170258, 1207884560, 1600895644, 3415426004, 2989276359, 120290264, 1352638112, 1765782608, 2501404720, 286397109, 468269577, 1209934100, 317036712, 1760386235],
    [2531184381, 2728404276, 672683356, 2394011375, 3586727991, 699766858, 2738428321, 2841826786, 3923599630, 500542555, 3722026618, 1987700198, 2392009384, 453184976, 2737150722, 756766806],
    [3969680392, 1376154958, 3192132952, 616513801, 3689490358, 1418966333, 1142925270, 2342430517, 777753954, 3820782321, 4192346268, 2791909511, 2369354747, 3077569322, 625256074, 442557982],
    [3591097400, 744985320, 1754979712, 3745547174, 197149595, 4041596286, 69557426, 1640894306, 1006986895, 1839087582, 2199532369, 4239272911, 3700419102, 3294294299, 287631021, 1631766153],
    [2482623482, 1995484272, 3483488740, 1985818002, 2144155842, 3487405314, 500899198, 3759294812, 1765662373, 1391371875, 1408492468, 1020136167, 3031525064, 2999807021, 3445222350, 2326697440],
    [62093306, 1202697257, 379962138, 3224541402, 798812754, 3051816539, 4232362965, 3932080501, 1131924598, 701147005, 1073941814, 1919804602, 3458402456, 3385267818, 4287843, 2786767194],
    [3056795641, 2951130507, 2028187976, 3653330931, 2894849846, 1106896481, 914381039, 2926936452, 3738897063, 1902456130, 976221726, 345141515, 1165851144, 1976304364, 4134290027, 2409836341],
    [30703515, 3498198214, 3771542635, 2481652272, 3844238961, 3348298446, 2125648729, 3476682143, 3299770761, 1918478998, 3952493162, 2699279946, 7215907, 2262124865, 4212656032, 4265486326],
    [119728817, 2967102379, 2023709705, 2819152335, 45526786, 1885820499, 2710824485, 2534895725, 3372988411, 849576138, 2447971353, 3027483346, 2656896719, 3305370328, 1569721429, 1478448142],
    [3957711653, 4182780756, 2846279898, 4028285347, 4053497937, 3467048327, 1794076867, 1244676595, 856808341, 1110042265, 300624464, 2092211928, 1583108286, 1256304846, 2222069465, 4167249669],
    [1625660024, 456477359, 2608441941, 637421440, 3255172854, 2792769620, 1106498271, 1124375035, 2986555825, 4117643478, 3577488086, 1424925299, 901113046, 3621528179, 3323940914, 2294315422],
    [2803431351, 727884926, 4088275858, 2472955032, 2327276077, 4223843362, 3121374705, 1262373450, 3058453897, 1655246434, 2133990960, 925523835, 1754274559, 1260478238, 3261813781, 3485789844],
    [132056582, 2142072563, 1414162427, 3203238351, 3102039427, 4056571376, 2471624636, 3444017084, 2677560730, 1013322568, 2394424470, 4247977205, 831066557, 2798585584, 4136681497, 3283639062],
    [2804390335, 2129434878, 1545744417, 799771297, 590001469, 1228016770, 3414925586, 1359595697, 4078497741, 2552209740, 3797171811, 3208362188, 1200880250, 713954354, 3702943934, 887730532],
    [251250215, 3393207744, 365773983, 3926097072, 606183017, 868053873, 3049360271, 3166318510, 3704331837, 2428262073, 2293329026, 4123512584, 2514991409, 511174588, 3171343789, 1728724765],
    [2178128133, 3746147207, 1793937462, 2378859029, 3589710678, 880804114, 3272474041, 1592084483, 3944903970, 2459505539, 793684548, 2338311466, 2536333947, 3234679466, 1466985055, 2832484097],
    [1360998806, 3527146652, 2261389174, 1817415091, 3483683701, 483134863, 4147480000, 722403789, 3437924040, 2441631105, 1262129386, 3694160824, 2160872938, 3352098895, 1440320468, 3149221717],
    [143725594, 2623001659, 2627105129, 1257511091, 3465023765, 4285783287, 3268697767, 3249373957, 2646760981, 1307080514, 3441730334, 3309533723, 81641042, 2015401449, 1770722740, 2972285547],
    [4256075603, 98319776, 3410464471, 2042569665, 4137371476, 1487672149, 589020121, 995860585, 2167889251, 4022947795, 2509177785, 2713675236, 3010492136, 2122737266, 1324203044, 3541164622],
    [2086026777, 430813049, 4013934791, 2288216813, 3138929927, 3150814224, 1366960937, 1702903178, 2162394017, 1170811586, 357618455, 4093693132, 2301936242, 1032326942, 1071730183, 2934084917],
    [840954923, 2689690208, 3467665289, 3387998373, 260390079, 1509035586, 7725397, 3766533200, 1692318223, 3325833697, 3486293326, 4273792576, 1604745732, 1566139601, 1512913101, 1891002518],
    [2737558604, 1256472139, 2669802777, 3570007740, 1833490702, 1540672950, 2880129088, 3492122105, 2393151470, 113689474, 379208249, 1433793070, 2936870421, 3481219388, 98851492, 714574061],
    [2283638200, 316304333, 3483280544, 2393839439, 1118244427, 1256188928, 353159080, 367687008, 3653383611, 2646167570, 3711663483, 1163408460, 392852739, 1664262085, 2250975629, 3322735213],
    [321769245, 751210568, 1963890489, 1433974914, 1392208792, 1403646901, 1826961282, 3590065604, 3858651296, 3960198680, 1425279959, 2320955652, 2411194778, 1621680811, 3721219346, 2041100434],
    [1794514226, 283600357, 4207284974, 3383216565, 2844733197, 3067507169, 938317691, 4136847467, 1550882346, 454525705, 434538370, 2006550378, 393081201, 1545808744, 661730748, 1660528184],
    [2579990752, 2508329046, 724089939, 2705758133, 711665691, 434622287, 3443367551, 2391695258, 2928228628, 1501018816, 4148149046, 2543542917, 1445440807, 440252804, 206473135, 202260259],
    [70757234, 3276896630, 1853138669, 4215141747, 3817978513, 4198166012, 3151977992, 1387595335, 2343639637, 45648206, 2182470294, 816253208, 3501992575, 2821732142, 185927896, 799084878],
    [517653317, 899051311, 3993467170, 397359972, 3201605676, 3978640385, 3903979506, 3643226532, 224456732, 400799200, 2702676732, 1947480405, 2358584830, 1970377942, 1333270104, 134217674],
    [85330243, 4137127286, 3975271588, 4271271938, 3509878391, 1729895465, 931792415, 905926599, 1408869136, 751413103, 1779094405, 3932616736, 889773498, 1739980475, 1584897155, 2777945935],
    [3695035889, 1074576162, 2712678082, 338240066, 3004676343, 3244904844, 100605123, 2170331915, 822501932, 4153629442, 591847909, 2047510382, 995478381, 2366333323, 3085010271, 2303312834],
    [2168928579, 1918414589, 2279088586, 1059536051, 3283327185, 57911395, 2686381642, 2278199026, 4099237849, 2367196314, 218455389, 1284994621, 1129454034, 3352716225, 4277030943, 3136259199],
    [2461676055, 3706490094, 3566184969, 2371660110, 2727565479, 1914835183, 378812920, 1014017292, 4124229426, 3590665944, 4051739234, 2308232320, 3650245277, 1271316649, 3573234962, 3264432406],
    [519411296, 464122122, 2724826496, 524619182, 1489491776, 3795327462, 195930575, 2422855723, 1410678754, 819351154, 2589316164, 1412626668, 597801182, 2541623558, 682117303, 1272771529],
    [2713627224, 4075310085, 2728559656, 4086936473, 3364992686, 3540567899, 1245307860, 3760396229, 3718396382, 1711242190, 2734835696, 67640734, 1348028430, 2400500582, 2194638476, 1131782465],
    [3457529103, 397556677, 1536266703, 1756906595, 2598397362, 4105599337, 3340275974, 1261937776, 4129816692, 2322075918, 4039654519, 2645291666, 2321427180, 1870283407, 1337600732, 1065672684],
    [680796093, 1515201015, 66766293, 3795889544, 3268839354, 416410645, 1095866638, 1977921931, 526597132, 3270502861, 381477235, 4057316856, 537560656, 3363847522, 3767701046, 2525332021],
    [2949288285, 3882676091, 1815264661, 132013775, 793093285, 3023871090, 3569871175, 716970366, 2027998817, 2631920058, 345423601, 402576242, 1495823659, 449152448, 3465831180, 1790333493],
    [2925038241, 709209694, 1762187513, 1863501113, 534597456, 1298195614, 549304504, 1363758103, 3541282430, 3228924774, 3274342512, 1707305088, 1531910249, 487508402, 553133022, 1627027162],
    [298466908, 4232375219, 214044825, 2417609272, 3546228739, 2461163201, 3608725225, 1408414560, 1168349948, 779244394, 4018414348, 4016763575, 59683541, 1365569184, 1873617923, 166151084],
    [2052248604, 3861740352, 2808751833, 660021387, 856872989, 695061179, 2946332845, 2978591860, 1487904561, 738414045, 909523729, 873092392, 2384873882, 2876758003, 2630486007, 2798339192],
    [595013806, 2437038194, 3012136856, 2579862215, 364106537, 2450878495, 611447628, 3466729568, 2624665187, 1070991184, 1450365727, 338393457, 510378999, 1930067905, 1539057174, 2729315521],
    [3421428967, 1823918259, 4187493268, 1106755269, 1466644975, 3067284818, 3796085769, 417213701, 716288650, 589059582, 647071565, 2461730025, 4014865819, 3589749779, 1601437678, 2138217514],
    [3622988024, 2406351329, 2950361758, 887781007, 3914134693, 111787625, 1286477003, 2716324251, 438285934, 2816862019, 3551016884, 1881161144, 3559569117, 4193478750, 4245232592, 3524516568],
    [2781349217, 1978683335, 2928410846, 3200474682, 661611097, 2470584310, 2362848730, 2363532498, 3791676181, 566039954, 1841165258, 493693265, 3551016365, 1780530057, 3307402948, 1912962186],
    [3213526604, 2764482392, 427282762, 1307153300, 2446651631, 2029890717, 2387713819, 1937235241, 3559557174, 3185182916, 494330963, 3436627514, 525166281, 2985349053, 1231544162, 3341780409],
    [2523174151, 1148673807, 1629346939, 2779945746, 3825387577, 2599358677, 2842900201, 270716316, 198685684, 823236592, 844342981, 445504770, 1001744720, 4036663024, 1359852085, 595986371],
    [2428948040, 3175052321, 2375622402, 595393094, 4013675329, 3725809586, 2419780739, 946343888, 454249505, 68543751, 656291298, 3431712432, 408258817, 2587634171, 1683318714, 3791722464],
    [880667889, 2722557335, 3510059682, 1360830243, 1636288165, 351939320, 3828202667, 765456450, 3345090611, 932917664, 876385174, 193572164, 1340130034, 168256118, 3300282886, 1810260021],
    [2680836063, 4111567131, 2920991127, 1506531980, 1224098871, 1716926446, 2391849686, 2727596130, 3748748250, 3016029134, 2655071916, 1239741118, 1277255368, 2748694924, 3730892035, 2452420749],
    [1394874218, 1616857031, 895846321, 3853716566, 1893691146, 1568361043, 3274972121, 1255340408, 1725782869, 793396257, 834257687, 299286547, 405818010, 945243309, 2751684690, 152153105]
]


# These known answer tests were derived from inputting random keys, IVs, and stream start locations into the reference implementation.
class SNOW3GTestCase(unittest.TestCase):
    def test_run_gauntlet(self):
        for i in range(50):
            key = sum([Bytes(part).zfill(4)for part in KEYS[i]])
            iv = sum([Bytes(part).zfill(4) for part in IVS[i]])

            snow = SNOW3G(key, iv)
            snow.yield_state(START_LOCS[i])
            ciphertext = snow.yield_state(16)

            self.assertEqual([chunk.to_int() for chunk in ciphertext.chunk(4)], KNOWN_ANSWERS[i])