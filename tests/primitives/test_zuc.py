from samson.stream_ciphers.zuc import ZUC
from samson.utilities.bytes import Bytes
import unittest


# ZUC test vectors manually generated using sample code from ZUC specification.
class ZUCTestCase(unittest.TestCase):
    def _run_test(self, key, iv, expected_keystream):
        zuc = ZUC(key, iv)
        keystream = zuc.generate(256)

        self.assertEqual(keystream, expected_keystream)
    

    def test_vec0(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        iv                  = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0x27BEDE74018082DA87D4E5B69F18BF6632070E0F39B7B692B4673EDC3184A48E27636F4414510D62CC15CFE194EC4F6D4B8C8FCC630648BADF41B6F9D16A36CA203AB30D029278579E42AF6074B9A8F89011587199D29D46B4C4F1EC992995A7AE2957BC7EA2979211157FCCF0966D98B0D2804BD039FFEF98C3457692EB83C154902AC7FB0BDF22A68717906C663B042F303C72C4CC3F4A824324678EDDBC3640CAAA7B5F28307EE29FDA70746A7EC3843F4FE02C805238F5006D27EC5E46363EA1E2F7A9EE11CFBADBC27E5026A11999B7B43305E80055B993061435F9450A24937BFEDA989F9DA9B6369274A66E9ABF0CE0CA3DCD426366863DC2B417503E).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec1(self):
        key                 = Bytes(0x01000000000000000000000000000000).zfill(16)
        iv                  = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0x1436240F6662B0F9143E6893BE96565698E44AB1495DAAAC1C45CB4A96970DA5333B24E2A1581C0E9F7D47F6B9E010B870D9B7BE1F162411121B157C6E15DFC8FBE7D89DF524D2444EB2C01E9D0FB5C5A69BB2204553A9EEC9EB8D66F6C66170323165BB2C190202591650BEF8AE1328B96204C43134ED93916DE1E597AC0DB17B7C41C25D50412A60EDE425910AE312A34C7E132B55A77394299DA391993810ADEAA53D07173485BC2A6FC3B55497AFB7DDF0666C66B3D0AD9107A9F4FEA3D5AD66ED28D888686A7C14E1A37C95DE6E993CF1DB4FE32B19D04FCFFCAE3AD1A3F7872225C897384D2B3C96EC3DCDA6C50704A76763572E00711A56FB084D1DAB).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec2(self):
        key                 = Bytes(0x00000100000000000000000000000000).zfill(16)
        iv                  = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0x4D11E72C93A58FDB2EFF5D0F1F1B02B35B071CBFDE0A669A8A3CFE0E7FD2903BF5ADB48409A0206A13CAD016AB0B06D2D781163494521F6833281A5FCE64F1622BCE1C1DC58E91A73FFCD28D988878466AEC4D305768559B489D6D618EE259E41EB7B7159529376F885B8487F0379D52A7AC3BD49D79AAE827411AC6903482C38A4CF18E91E4D4415A0B636D9791A45773635DB8855D726E85C7E3A8E13EF262E416E1D553B5F8C540B52C7EB28A88547E9A29269F84E054466D78448362D17EEC2DF9F06CB72871C9F33435D4600483E952966F097493BDB7C70291E7F5A5F5B1C5CD2DB5C26E12DC6C361E9FEEFF8EFC86C92615C1D169268C6D63811DEC3C).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec3(self):
        key                 = Bytes(0x00000000010000000000000000000000).zfill(16)
        iv                  = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0x3A0948EC4F9366051BE324FB3E15A437447DB182B6EC45D55FDD2F88F2B6FB55CFB82951C872DC27AA2DA62633580CA515D29BE3C9963BC5DDECBF0E9C8DC952129839C11F1AE44DC3D17058A54A890108A0EC2276580458735C76C2070C16ED02883E136C900F708288E07E98E7B26F9E1F5048AE3425369146FB0D8B4F3B74726093D31B14C9D3838947993FA7E9E0CE0F19C518ECFF67B7B1BAF221E533DF914F7C507B37E5254E5D0BD7E3F6E15ED2CD0676F93D461E038C6A17C60160C950E86F359C7E0AE66092CB9BCD3E548CD8FB43DD72475EDA793F1D3B31329DD91DDF60F7D23013D2A3AB3FDFF491F472340C5D8A8B7BBBFBF3AD28E25133429A).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec4(self):
        key                 = Bytes(0x00000000000001000000000000000000).zfill(16)
        iv                  = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0xBDB2127667AC4B37AB7A8DEB34E37CB7ACD645AA33396AB23B66EE9BF1781A8112B40D1E84F14490D1B59AEA1F049BD076F1E049F931068E32F6AB42060DA8A660DC11EF3C95D45C04FE6AA97421021A7C896A1BDDF3C7BE8109F6D8E4E22553464837B6FDF3B885F95EA5A5384338DEB7B68BD594AD97C39E641C6267B4BAE2A9B08FE16FDEC9964FFDED5CE3A3CB34C9A13D1CFDE2BE67BF60AF4CF46B78AC0CD9DA2EDBBAD2C16D3233EB8CA99E3A557456A55661FC00BD2A8C1A52187263BA6A21EC3280251EABAADBE3D6675D5C8470E375EE8B923BE790EBAD82B4644FAD707F987CE9E0E29DEC56F8E3A70FFD3246F0B2782624F34EC205B222079AE0).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec5(self):
        key                 = Bytes(0x00000000000000000100000000000000).zfill(16)
        iv                  = Bytes(0x00000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0x4031935531A0CB1054A330DFB4F01D75AA53E9802B6C9A38EF2B0B993633809E41BC12ABFF11C475681ECB3757B3F9E3FF249B449BF34100A81FBFBFA409A59DE1198E88475733A7C1EBDA875EFF0E332E6FDC16BEE7CDD9372DF77470EA55DEFB5DC5848E2A278B81D963353A1CF7BEEB789FC29DB8B204A7FCF3F18B9418FDE55C8528E530D79F2284110F719B6797B928789A7232D68C1745D18B3729886872A801D3A6CD515354DD1063D30C4638993FC6F4DF942C8BCDF17D52D9CD91852FFFA3C73220C0B61753B2D62255CCFFCF86CD4048248C1722E0ABD448A2E6B7845BCDA112A1E1FC143944468A00220C2D6AF87160DE0D214CDC1AB153413ECA).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec6(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        iv                  = Bytes(0x01000000000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0xA405D270FFE7CD2A348C34B13B72856FA9ADD613ADC221D54B623F51624B3FECC3E60846A262F2EDF40FBA3C14B776033C93BAA112A0B95D78A385285240B920EC1FF18285F4A7FEFBC50E49A537E3C555237FE2E888D61F0AB679FD1E0A0C15AA9DECF0F890E121B6946F47820195779AFA6B54FAE0A487AD0B98FDBFFDE5DDC7D1252A77CE956AC1C06BA3BEFD42326229CBEBEFD504D689DB3B4E95B63CDCA6ACF5534001438A54B37755E221D8C25CD97C945E52038948D8D3493C50EDA61DD7BCC0A21C3C957DCF7C55F520C437694515CBAD1EFF7845C328D89AA0F9463A8BCE24BAB7139DCB71D872127EB08CDBFDE7DEB6CCC2FDA321D4C340644EAA).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec7(self):
        key                 = Bytes(0x00000000000000000000000000000000).zfill(16)
        iv                  = Bytes(0x00000100000000000000000000000000).zfill(16)
        expected_keystream  = Bytes(0xA2259021912F63E7A93FFB824BF56B711F7D6D82F3B31E5C30AB07233694B67F4CB9FC88C48E91133419984A55A8A77CA158909D56A66A5F4D597F71705DA7F97D532FB44E3A3C822655F49A322870FFFC4B1ECD94170409738F7696E2BA05BFDDE8559990908D7AC0FD52C270DA862BD0616AA6D3567E9F3C25C4E6072F319AAF8392D6426F752B768010620E317511C2C3C33E20C7EC577B336EA51AE5C658875D8AF749E3F743033CAB0A22346CDF28F99D4198CAA083E0597255ABE582DE2E6CBFD682317F69ABC901E22CFC5FB578408213BD5BC59EFAB2CFF89BF131B6A009E673A983CB4A219016022EFE4664679C4FDCBBD5ACE9869A2C3966302729).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec8(self):
        key                 = Bytes(0x25927A54A4370C522A9959F259734CC8).zfill(16)
        iv                  = Bytes(0x866DA78887840C683F7918DE7B4255FD).zfill(16)
        expected_keystream  = Bytes(0x40C8A257620685B9232E46B95E48DF90335FF44DDB6F3807B891BF5C8986D0BD3159F9EBE8EA99E16973D97D611F04409DD74EAF9BE4075BDB3AC5E011571D80EAA74B98850F063BB35A6C1D8427282944202B9D11DAA5D2F28F717980C172E74204E0B16561836722BED71D5F919F19B205B5EEF062A7C134B03584BAD69E64AA30167EA3CA15C3FF4FA77FDB0065AB2C7DA3D77224B5BD0FFF60E9FBAD3F3361C5475C12BB73EC6356D8B54C57BD5914F6CA61599797660DC6871FC54CE8778A3AD957EB82408AFC3F8516936E3BFE078736889362DDD97AA65691E184FE74C536F9E58D2934ED312F80FDB4023BF56136F49110A4FBD5E88DEC433A21).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec9(self):
        key                 = Bytes(0x6142B8BF183235C23204C23A93907FAF).zfill(16)
        iv                  = Bytes(0xFB17F5A69AA2BE6F66559DFBCC556DFE).zfill(16)
        expected_keystream  = Bytes(0xAFBB6287118F19CA3DBCE8E4189ED428D8D74F8E74EA1405200F04C898ED06BBC58D92960CAE798B25FF1B2E7D854C2B7F573F919A99246509D0E5F089F6E0CE4E108CD0102A90DD9F47667FF9C15D8E0D9668122D29F53C099456CDDD8288A8DD9506AD273FF8D7FA6D4CBB8663C9A74D2FA6D51660AEE2C9394C0C4D543F25351659F5B3E415D7C3CDF8B0C07F9DD3AA545A0CA6AD96097D8EA653397C9D4DA064F549FC642988E0961D8C610C2C71065481901BF910B7A70F3756EBFA2F3F41181AE7E2208FE78EED0274334CCB350F8EA673B1E0A29B965D3E1D0BC0DD93691301CA51044F970591CFC7A178B3EBF4FA06E5B12FD1739840DCCB76277B).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec10(self):
        key                 = Bytes(0xC7838A19E0FE5209AC49745E9BAFBE56).zfill(16)
        iv                  = Bytes(0x0D2D84CB829E7E629A3743B5257DDA62).zfill(16)
        expected_keystream  = Bytes(0x46B23F635A84906AC4078D3A24C66688E4D54C00F827DA6E8EACA86DFE2F9DDF7223158A3E4DB5C85C741FFAD1A258D48C0D4B56550A1836268EF30F862EE2E0A54A01BAF7BE7DFC90AF8AACBCA15166369C16626ABD11A785C2AAED0912EBDA587A636ACD0239B0120EB4E424BBFBB795313E5E65A286D4BE125E254C7FE747CE9E424F51B60260B2C6D6497A12D3C37FCACABDA3ADF562A777DF527506A0DDB2DEF154F78FF275919CA2A6A02790B72CA4AD0EAE6AE1F51459447DBEDCA2D41FBCD66CA76F23B81813D0EECD2B29CD31927979A9BE8AB77A8199CD96C6DAFBFFFA50038D40859ABA291E4B01573C09797C70D7A889F3C403682ACA13FE2B89).zfill(256)

        self._run_test(key, iv, expected_keystream)



    def test_vec11(self):
        key                 = Bytes(0xAB14C76125C05BF491A1E55020E82C6D).zfill(16)
        iv                  = Bytes(0x63ADFFEEB0BD12344AC0E99ADCF7369F).zfill(16)
        expected_keystream  = Bytes(0xADD3E2BE0548F1C6E8C9571150849C40DFB1B069A68A932C3C86B89B1F299DDC1C09839F91098003F6A9D23047946CDFEE170A3FEE05B0AFEEF1573FC9534C9AC2F0E9D3A28FDDB98723805229F0894FE029DF2FC6100D4A562549514672C5EB904099362EC431D4752193C89C900C3E20492B4EA73AD676B8A2999D9F6A58BD1E3C814E59B7E9BDE7A6841F52D0322C0AE2CC11DE0397883592E8C252B4CD445AD04C07520D10CD10FACE148D8728E09B3E09BCB3A98AA32F254B5D5E3CCB2CB63B01221D5C83901BA70B2E4BFD6627A2006E2C65AB3AA04953F92B27E7C9D6B56E9DE8175A46739852052B832880E1E592A6DCE126C502A809DF3E681FF475).zfill(256)

        self._run_test(key, iv, expected_keystream)