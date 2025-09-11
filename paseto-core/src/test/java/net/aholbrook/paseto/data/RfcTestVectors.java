package net.aholbrook.paseto.data;

import net.aholbrook.paseto.Version;
import net.aholbrook.paseto.keys.AsymmetricPublicKey;
import net.aholbrook.paseto.keys.AsymmetricSecretKey;
import net.aholbrook.paseto.keys.KeyPair;
import net.aholbrook.paseto.keys.SymmetricKey;
import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.utils.Hex;

public class RfcTestVectors {
	public static final byte[] RFC_TEST_KEY = Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e"
			+ "8f");
	public static final byte[] RFC_TEST_NONCE_1 = Hex.decode("000000000000000000000000000000000000000000000000");
	public static final byte[] RFC_TEST_NONCE_V1 = Hex.decode("26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8db"
			+ "be7f7f2");
	public static final byte[] RFC_TEST_NONCE_V2 = Hex.decode("45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b");
	public static final byte[] RFC_TEST_SK = Hex.decode("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a377"
			+ "41eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2");
	public static final byte[] RFC_TEST_PK = Hex.decode("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a"
			+ "2");
	public static final byte[] RFC_TEST_RSA_PRIVATE_KEY = Hex.decode(
			"308204BD020100300D06092A864886F70D0101010500048204A7308204A30201000282010100C9A4E04EDE77A61DE9E461E0C2"
					+ "8196C33E6145F597490034F0D08EC1ED0512000B5A8B3D1828CD14277BDB79C21F106D375A9DEF831287FB8DF3C24F21"
					+ "BC312A1783A78931A3860C379B6B3DA1747BD1BA063D4DD361E76A7C452D6FA098B6E060EFD26587D617F33CC8B05CBB"
					+ "96353ADD19C430C35D2F702104ED044D277B761BC606490194D4E57AB24350F17736320B9945EB205A479510B426139D"
					+ "7000A5546E508D9277A2F5136BE5F5B481BA66792293719119C0C08323793241FF400810B874984E6FC1D8A13826DD57"
					+ "A6A553284A0B5FB5C3F156E8759CA7F246D64282F033C889D67BF016EABFD605CE401B3678B979204EB17541286EFC66"
					+ "C73CA30203010001028201005DB68CB0DADF8C8A767B37A9F77BB68F82DC3E6147301C327E80CEF7FDA9CF95C9B108E9"
					+ "19E34C7C436562B911A8D23F8FEC435E5EF22BD493426859D279DDF78BFA19D0BF0B1A6F6F208214A086BC4CDA41B018"
					+ "0D5780EF9255AC2A26DF128EF13E43EFFFD3564A2B43B20347032635F72FD4683D437F9A831E00F170D21AA4144866EF"
					+ "6192542118D5E63E70E5E62F789CC67B279540FFFD24BDAB7DD1C45DB2E68896D5E76A711AA15BFECBD7260C6F11C551"
					+ "CC5687C594C239F500086808E53317C641FB45FF3CF87ED67628ABAC70A8BD19283C2B43C483856FEB3432DE3BD82273"
					+ "9AE5EC47AD45045B16FB19E3401DB17DB053E956154901E36023BA8102818100E73FC25EA0C57D9F0C5C23C039EBA2F3"
					+ "2E47343B6EDF4691F87397B010E7448F21B97B06343D3815F99747B9E4821AF4F1F1550E61383DE29493CD746096FE20"
					+ "0268F30ACE674EBCDA7EB210C3B9F289AA2A29FE888515ACF5CB48BA3908286BAB0D89E2F833A25CCFC3737923C14974"
					+ "BA266FD164AD5F381FE22F88F232972102818100DF39F0006DBD417E804C47C5A4654E728828AC70A7B5DE2789A582AB"
					+ "99DEE6C14BF84C0B795735CC3F728F56B17037A52020D9C426729D4EE40E7AD0705913D1B8C7FE00BC264DEFED74FD97"
					+ "55030EA0B56FBAE6FD7E7014867FAE635AD6B55984BD68FED2B1E6DBCCDACC89D6AF79BFB35DCA01481085BEA9B20A6D"
					+ "CE96CF430281806C5197500FEAB1FF102110B5F7EB82367A94EBC87314AECFAD1B281056BA9D8895F975C0E03354D426"
					+ "475057A8CBB0A8CFB3856DE8E81944CAE7B8B32C934D91DCCF20190DB9A24E1FE27CB2119C461969D5BA39F9E4ACD489"
					+ "85A11969A1829D7C50292861AE7DFD0F6CB3E828715F6107D8FD438DEF0FCD10523885E33D03410281802ED7417D5589"
					+ "B90C8A6F774009D71837004B48A3FB0D36A8A5418DC1E46FD98C061CFC180C46388BBB64969F626C61C0CC95181D08D4"
					+ "541E11CCD808950A9C160DE8296C8E0E9B9C14FFCF96C9C7F271D6A0B35F7521EAF2E3A63739B1FE0BDFD4F2C9ED6ED8"
					+ "D5D09993F0079C7D05D72C142A274AAFECE0AD4B26D513DCA17102818100D19C43C9CE6E2DE6E3044EC8AAE4096716C4"
					+ "514C9E9C31BF4A56EF6EC79FDC2E68EB3851B7AC0A7C26A5C3137F31940EECD85C2B40AB6A4997AE071BAC2C7645A68C"
					+ "14C91299BA6FD89B381377A85576CD0D07CB22A5316C48B954A3F603A8EB5845ED41FD5C1E91E0745D96904EB886E001"
					+ "6678E9D923F7F1CCF68BDD3F4232");
	public static final byte[] RFC_TEST_RSA_PUBLIC_KEY = Hex.decode(
			"30820122300D06092A864886F70D01010105000382010F003082010A0282010100C9A4E04EDE77A61DE9E461E0C28196C33E61"
					+ "45F597490034F0D08EC1ED0512000B5A8B3D1828CD14277BDB79C21F106D375A9DEF831287FB8DF3C24F21BC312A1783"
					+ "A78931A3860C379B6B3DA1747BD1BA063D4DD361E76A7C452D6FA098B6E060EFD26587D617F33CC8B05CBB96353ADD19"
					+ "C430C35D2F702104ED044D277B761BC606490194D4E57AB24350F17736320B9945EB205A479510B426139D7000A5546E"
					+ "508D9277A2F5136BE5F5B481BA66792293719119C0C08323793241FF400810B874984E6FC1D8A13826DD57A6A553284A"
					+ "0B5FB5C3F156E8759CA7F246D64282F033C889D67BF016EABFD605CE401B3678B979204EB17541286EFC66C73CA30203"
					+ "010001");

	public static final SymmetricKey RFC_TEST_V1_KEY = new SymmetricKey(RFC_TEST_KEY, Version.V1);
	public static final AsymmetricSecretKey RFC_TEST_V1_SK = new AsymmetricSecretKey(RFC_TEST_RSA_PRIVATE_KEY, Version.V1);
	public static final AsymmetricPublicKey RFC_TEST_V1_PK = new AsymmetricPublicKey(RFC_TEST_RSA_PUBLIC_KEY, Version.V1);

	public static final SymmetricKey RFC_TEST_V2_KEY = new SymmetricKey(RFC_TEST_KEY, Version.V2);
	public static final AsymmetricSecretKey RFC_TEST_V2_SK = new AsymmetricSecretKey(RFC_TEST_SK, Version.V2);
	public static final AsymmetricPublicKey RFC_TEST_V2_PK = new AsymmetricPublicKey(RFC_TEST_PK, Version.V2);

	// A.1.1.1.  Test Vector v1-E-1
	private static final RfcToken RFC_TEST_VECTOR_V1_E_1_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_E_1_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V1_E_1_TOKEN
			= "v1.local.WzhIh1MpbqVNXNt7-HbWvL-JwAym3Tomad9Pc2nl7wK87vGraUV"
			+ "vn2bs8BBNo7jbukCNrkVID0jCK2vr5bP18G78j1bOTbBcP9HZzqnraEdspcj"
			+ "d_PvrxDEhj9cS2MG5fmxtvuoHRp3M24HvxTtql9z26KTfPWxJN5bAJaAM6go"
			+ "s8fnfjJO8oKiqQMaiBP_Cqncmqw8";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_E_1
			= new TestVector<>(RFC_TEST_V1_KEY, RFC_TEST_NONCE_1, RFC_TEST_VECTOR_V1_E_1_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V1_E_1_FOOTER, RFC_TEST_VECTOR_V1_E_1_TOKEN);

	// A.1.1.2.  Test Vector v1-E-2
	private static final RfcToken RFC_TEST_VECTOR_V1_E_2_PAYLOAD
			= new RfcToken("this is a secret message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_E_2_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V1_E_2_TOKEN
			= "v1.local.w_NOpjgte4bX-2i1JAiTQzHoGUVOgc2yqKqsnYGmaPaCu_KWUkR"
			+ "GlCRnOvZZxeH4HTykY7AE_jkzSXAYBkQ1QnwvKS16uTXNfnmp8IRknY76I2m"
			+ "3S5qsM8klxWQQKFDuQHl8xXV0MwAoeFh9X6vbwIqrLlof3s4PMjRDwKsxYzk"
			+ "Mr1RvfDI8emoPoW83q4Q60_xpHaw";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_E_2
			= new TestVector<>(RFC_TEST_V1_KEY, RFC_TEST_NONCE_1, RFC_TEST_VECTOR_V1_E_2_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V1_E_2_FOOTER, RFC_TEST_VECTOR_V1_E_2_TOKEN);

	// A.1.1.3.  Test Vector v1-E-3
	private static final RfcToken RFC_TEST_VECTOR_V1_E_3_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_E_3_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V1_E_3_TOKEN
			= "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c"
			+ "v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs"
			+ "0aFc3ejjORmKP4KUM339W3syBYyjKIOeWnsFQB6Yef-1ov9rvqt7TmwONUHe"
			+ "JUYk4IK_JEdUeo_uFRqAIgHsiGCg";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_E_3
			= new TestVector<>(RFC_TEST_V1_KEY, RFC_TEST_NONCE_V1, RFC_TEST_VECTOR_V1_E_3_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V1_E_3_FOOTER, RFC_TEST_VECTOR_V1_E_3_TOKEN);

	// A.1.1.4.  Test Vector v1-E-4
	private static final RfcToken RFC_TEST_VECTOR_V1_E_4_PAYLOAD
			= new RfcToken("this is a secret message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_E_4_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V1_E_4_TOKEN
			= "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb"
			+ "pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq"
			+ "GNeeWXOyWWHoJQIe0d5nTdvejdt2Srz_5Q0QG4oiz1gB_wmv4U5pifedaZbH"
			+ "XUTWXchFEi0etJ4u6tqgxZSklcec";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_E_4
			= new TestVector<>(RFC_TEST_V1_KEY, RFC_TEST_NONCE_V1, RFC_TEST_VECTOR_V1_E_4_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V1_E_4_FOOTER, RFC_TEST_VECTOR_V1_E_4_TOKEN);

	// A.1.1.5.  Test Vector v1-E-5
	private static final RfcToken RFC_TEST_VECTOR_V1_E_5_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_E_5_FOOTER
			= new KeyId().setKeyId("UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo");
	private static final String RFC_TEST_VECTOR_V1_E_5_TOKEN
			= "v1.local.4VyfcVcFAOAbB8yEM1j1Ob7Iez5VZJy5kHNsQxmlrAwKUbOtq9c"
			+ "v39T2fC0MDWafX0nQJ4grFZzTdroMvU772RW-X1oTtoFBjsl_3YYHWnwgqzs"
			+ "0aFc3ejjORmKP4KUM339W3szA28OabR192eRqiyspQ6xPM35NMR-04-FhRJ"
			+ "ZEWiF0W5oWjPVtGPjeVjm2DI4YtJg.eyJraWQiOiJVYmtLOFk2aXY0R1poRn"
			+ "A2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_E_5
			= new TestVector<>(RFC_TEST_V1_KEY, RFC_TEST_NONCE_V1, RFC_TEST_VECTOR_V1_E_5_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V1_E_5_FOOTER, RFC_TEST_VECTOR_V1_E_5_TOKEN);

	// A.1.1.6.  Test Vector v1-E-6
	private static final RfcToken RFC_TEST_VECTOR_V1_E_6_PAYLOAD
			= new RfcToken("this is a secret message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_E_6_FOOTER
			= new KeyId().setKeyId("UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo");
	private static final String RFC_TEST_VECTOR_V1_E_6_TOKEN
			= "v1.local.IddlRQmpk6ojcD10z1EYdLexXvYiadtY0MrYQaRnq3dnqKIWcbb"
			+ "pOcgXdMIkm3_3gksirTj81bvWrWkQwcUHilt-tQo7LZK8I6HCK1V78B9YeEq"
			+ "GNeeWXOyWWHoJQIe0d5nTdvcT2vnER6NrJ7xIowvFba6J4qMlFhBnYSxHEq9"
			+ "v9NlzcKsz1zscdjcAiXnEuCHyRSc.eyJraWQiOiJVYmtLOFk2aXY0R1poRnA"
			+ "2VHgzSVdMV0xmTlhTRXZKY2RUM3pkUjY1WVp4byJ9";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_E_6
			= new TestVector<>(RFC_TEST_V1_KEY, RFC_TEST_NONCE_V1, RFC_TEST_VECTOR_V1_E_6_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V1_E_6_FOOTER, RFC_TEST_VECTOR_V1_E_6_TOKEN);

	// A.1.2.1.  Test Vector v1-S-1
	private static final RfcToken RFC_TEST_VECTOR_V1_S_1_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_S_1_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V1_S_1_TOKEN
			= "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw"
			+ "iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9cIZKahKeGM5k"
			+ "iAS_4D70Qbz9FIThZpxetJ6n6E6kXP_119SvQcnfCSfY_gG3D0Q2v7FEt"
			+ "m2Cmj04lE6YdgiZ0RwA41WuOjXq7zSnmmHK9xOSH6_2yVgt207h1_LphJ"
			+ "zVztmZzq05xxhZsV3nFPm2cCu8oPceWy-DBKjALuMZt_Xj6hWFFie96Sf"
			+ "Q6i85lOsTX8Kc6SQaG-3CgThrJJ6W9DC-YfQ3lZ4TJUoY3QNYdtEgAvp1"
			+ "QuWWK6xmIb8BwvkBPej5t88QUb7NcvZ15VyNw3qemQGn2ITSdpdDgwMtp"
			+ "flZOeYdtuxQr1DSGO2aQyZl7s0WYn1IjdQFx6VjSQ4yfw";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_S_1
			= new TestVector<>(RFC_TEST_V1_SK, RFC_TEST_V1_PK,
			RFC_TEST_VECTOR_V1_S_1_PAYLOAD, RfcToken.class, RFC_TEST_VECTOR_V1_S_1_FOOTER,
			RFC_TEST_VECTOR_V1_S_1_TOKEN);

	// A.1.2.2.  Test Vector v1-S-2
	private static final RfcToken RFC_TEST_VECTOR_V1_S_2_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V1_S_2_FOOTER
			= new KeyId().setKeyId("dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn");
	private static final String RFC_TEST_VECTOR_V1_S_2_TOKEN
			= "v1.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiw"
			+ "iZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9sBTIb0J_4mis"
			+ "AuYc4-6P5iR1rQighzktpXhJ8gtrrp2MqSSDkbb8q5WZh3FhUYuW_rg2X"
			+ "8aflDlTWKAqJkM3otjYwtmfwfOhRyykxRL2AfmIika_A-_MaLp9F0iw4S"
			+ "1JetQQDV8GUHjosd87TZ20lT2JQLhxKjBNJSwWue8ucGhTgJcpOhXcthq"
			+ "az7a2yudGyd0layzeWziBhdQpoBR6ryTdtIQX54hP59k3XCIxuYbB9qJM"
			+ "pixiPAEKBcjHT74sA-uukug9VgKO7heWHwJL4Rl9ad21xyNwaxAnwAJ7C"
			+ "0fN5oGv8Rl0dF11b3tRmsmbDoIokIM0Dba29x_T3YzOyg.eyJraWQiOiJ"
			+ "kWWtJU3lseFFlZWNFY0hFTGZ6Rjg4VVpyd2JMb2xOaUNkcHpVSEd3OVVx"
			+ "biJ9";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V1_S_2
			= new TestVector<>(RFC_TEST_V1_SK, RFC_TEST_V1_PK,
			RFC_TEST_VECTOR_V1_S_2_PAYLOAD, RfcToken.class, RFC_TEST_VECTOR_V1_S_2_FOOTER,
			RFC_TEST_VECTOR_V1_S_2_TOKEN);


	// A.2.1.1.  Test Vector v2-E-1
	private static final RfcToken RFC_TEST_VECTOR_V2_E_1_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_E_1_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V2_E_1_TOKEN
			= "v2.local.97TTOvgwIxNGvV80XKiGZg_kD3tsXM_-qB4dZGHOeN1cTkgQ4Pn"
			+ "W8888l802W8d9AvEGnoNBY3BnqHORy8a5cC8aKpbA0En8XELw2yDk2f1sVOD"
			+ "yfnDbi6rEGMY3pSfCbLWMM2oHJxvlEl2XbQ";
	public static TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_E_1
			= new TestVector<>(RFC_TEST_V2_KEY, RFC_TEST_NONCE_1, RFC_TEST_VECTOR_V2_E_1_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V2_E_1_FOOTER, RFC_TEST_VECTOR_V2_E_1_TOKEN);

	// A.2.1.2.  Test Vector v2-E-2
	private static final RfcToken RFC_TEST_VECTOR_V2_E_2_PAYLOAD
			= new RfcToken("this is a secret message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_E_2_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V2_E_2_TOKEN
			= "v2.local.CH50H-HM5tzdK4kOmQ8KbIvrzJfjYUGuu5Vy9ARSFHy9owVDMYg"
			+ "3-8rwtJZQjN9ABHb2njzFkvpr5cOYuRyt7CRXnHt42L5yZ7siD-4l-FoNsC7"
			+ "J2OlvLlIwlG06mzQVunrFNb7Z3_CHM0PK5w";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_E_2
			= new TestVector<>(RFC_TEST_V2_KEY, RFC_TEST_NONCE_1, RFC_TEST_VECTOR_V2_E_2_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V2_E_2_FOOTER, RFC_TEST_VECTOR_V2_E_2_TOKEN);

	// A.2.1.3.  Test Vector v2-E-3
	private static final RfcToken RFC_TEST_VECTOR_V2_E_3_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_E_3_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V2_E_3_TOKEN
			= "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb"
			+ "jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6"
			+ "Qclw3qTKIIl5-O5xRBN076fSDPo5xUCPpBA";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_E_3
			= new TestVector<>(RFC_TEST_V2_KEY, RFC_TEST_NONCE_V2, RFC_TEST_VECTOR_V2_E_3_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V2_E_3_FOOTER, RFC_TEST_VECTOR_V2_E_3_TOKEN);

	// A.2.1.4.  Test Vector v2-E-4
	private static final RfcToken RFC_TEST_VECTOR_V2_E_4_PAYLOAD
			= new RfcToken("this is a secret message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_E_4_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V2_E_4_TOKEN
			= "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7"
			+ "cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr"
			+ "Iu3B6h232h62DPbIxtjGvNRAwsLK7LcV8oQ";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_E_4
			= new TestVector<>(RFC_TEST_V2_KEY, RFC_TEST_NONCE_V2, RFC_TEST_VECTOR_V2_E_4_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V2_E_4_FOOTER, RFC_TEST_VECTOR_V2_E_4_TOKEN);

	// A.2.1.5.  Test Vector v2-E-5
	private static final RfcToken RFC_TEST_VECTOR_V2_E_5_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_E_5_FOOTER
			= new KeyId().setKeyId("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN");
	private static final String RFC_TEST_VECTOR_V2_E_5_TOKEN
			= "v2.local.5K4SCXNhItIhyNuVIZcwrdtaDKiyF81-eWHScuE0idiVqCo72bb"
			+ "jo07W05mqQkhLZdVbxEa5I_u5sgVk1QLkcWEcOSlLHwNpCkvmGGlbCdNExn6"
			+ "Qclw3qTKIIl5-zSLIrxZqOLwcFLYbVK1SrQ.eyJraWQiOiJ6VmhNaVBCUDlm"
			+ "UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_E_5
			= new TestVector<>(RFC_TEST_V2_KEY, RFC_TEST_NONCE_V2, RFC_TEST_VECTOR_V2_E_5_PAYLOAD,
			RfcToken.class, RFC_TEST_VECTOR_V2_E_5_FOOTER, RFC_TEST_VECTOR_V2_E_5_TOKEN);

	// A.2.1.6.  Test Vector v2-E-6
	private static final RfcToken RFC_TEST_VECTOR_V2_E_6_PAYLOAD
			= new RfcToken("this is a secret message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_E_6_FOOTER
			= new KeyId().setKeyId("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN");
	private static final String RFC_TEST_VECTOR_V2_E_6_TOKEN
			= "v2.local.pvFdDeNtXxknVPsbBCZF6MGedVhPm40SneExdClOxa9HNR8wFv7"
			+ "cu1cB0B4WxDdT6oUc2toyLR6jA6sc-EUM5ll1EkeY47yYk6q8m1RCpqTIzUr"
			+ "Iu3B6h232h62DnMXKdHn_Smp6L_NfaEnZ-A.eyJraWQiOiJ6VmhNaVBCUDlm"
			+ "UmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_E_6
			= new TestVector<>(RFC_TEST_V2_KEY, RFC_TEST_NONCE_V2,
			RFC_TEST_VECTOR_V2_E_6_PAYLOAD, RfcToken.class, RFC_TEST_VECTOR_V2_E_6_FOOTER,
			RFC_TEST_VECTOR_V2_E_6_TOKEN);

	// A.2.2.1.  Test Vector v2-S-1
	private static final RfcToken RFC_TEST_VECTOR_V2_S_1_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_S_1_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V2_S_1_TOKEN
			= "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi"
			+ "wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9HQr8URrGnt"
			+ "Tu7Dz9J2IF23d1M7-9lH9xiqdGyJNvzp4angPW5Esc7C5huy_M8I8_Dj"
			+ "JK2ZXC2SUYuOFM-Q_5Cw";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_S_1
			= new TestVector<>(RFC_TEST_V2_SK, RFC_TEST_V2_PK,
			RFC_TEST_VECTOR_V2_S_1_PAYLOAD, RfcToken.class, RFC_TEST_VECTOR_V2_S_1_FOOTER,
			RFC_TEST_VECTOR_V2_S_1_TOKEN);

	// A.2.2.2.  Test Vector v2-S-2
	private static final RfcToken RFC_TEST_VECTOR_V2_S_2_PAYLOAD
			= new RfcToken("this is a signed message", "2019-01-01T00:00:00+00:00");
	private static final KeyId RFC_TEST_VECTOR_V2_S_2_FOOTER
			= new KeyId().setKeyId("zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN");
	private static final String RFC_TEST_VECTOR_V2_S_2_TOKEN
			= "v2.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIi"
			+ "wiZXhwIjoiMjAxOS0wMS0wMVQwMDowMDowMCswMDowMCJ9flsZsx_gYC"
			+ "R0N_Ec2QxJFFpvQAs7h9HtKwbVK2n1MJ3Rz-hwe8KUqjnd8FAnIJZ601"
			+ "tp7lGkguU63oGbomhoBw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q"
			+ "3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	public static final TestVector<RfcToken, KeyId> RFC_TEST_VECTOR_V2_S_2
			= new TestVector<>(RFC_TEST_V2_SK, RFC_TEST_V2_PK,
			RFC_TEST_VECTOR_V2_S_2_PAYLOAD, RfcToken.class, RFC_TEST_VECTOR_V2_S_2_FOOTER,
			RFC_TEST_VECTOR_V2_S_2_TOKEN);

	// 4-E-1
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_1_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_1_PAYLOAD
			= new RfcToken("this is a secret message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_1_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V4_E_1_TOKEN
			= "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AX"
			+ "e7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7OpBnwJOAbY9V7WU6abu74"
			+ "MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQg";
	private static final byte[] RFC_TEST_VECTOR_V4_E_1_NONCE = Hex.decode(
			"0000000000000000000000000000000000000000000000000000000000000000"
	);
	private static final String RFC_TEST_VECTOR_V4_E_1_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_1 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_1_KEY,
			RFC_TEST_VECTOR_V4_E_1_NONCE,
			RFC_TEST_VECTOR_V4_E_1_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_1_FOOTER,
			RFC_TEST_VECTOR_V4_E_1_TOKEN,
			RFC_TEST_VECTOR_V4_E_1_IMPLICIT_ASSERTION
	);

	// 4-E-2
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_2_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_2_PAYLOAD
			= new RfcToken("this is a hidden message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_2_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V4_E_2_TOKEN
			= "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvS2csCgglvpk5HC0e8kApeaqMfGo_7"
			+ "OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XIemu9chy3WVKvRBfg6t8wwYHK0ArLxxfZP73W_vfwt5A";
	private static final byte[] RFC_TEST_VECTOR_V4_E_2_NONCE = Hex.decode(
			"0000000000000000000000000000000000000000000000000000000000000000"
	);
	private static final String RFC_TEST_VECTOR_V4_E_2_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_2 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_2_KEY,
			RFC_TEST_VECTOR_V4_E_2_NONCE,
			RFC_TEST_VECTOR_V4_E_2_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_2_FOOTER,
			RFC_TEST_VECTOR_V4_E_2_TOKEN,
			RFC_TEST_VECTOR_V4_E_2_IMPLICIT_ASSERTION
	);

	// 4-E-3
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_3_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_3_PAYLOAD
			= new RfcToken("this is a secret message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_3_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V4_E_3_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0KW9"
			+ "ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6-tyebyWG6Ov7kKvBdkrrAJ837lKP3iDag2hzUPHuMKA";
	private static final byte[] RFC_TEST_VECTOR_V4_E_3_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_3_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_3 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_3_KEY,
			RFC_TEST_VECTOR_V4_E_3_NONCE,
			RFC_TEST_VECTOR_V4_E_3_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_3_FOOTER,
			RFC_TEST_VECTOR_V4_E_3_TOKEN,
			RFC_TEST_VECTOR_V4_E_3_IMPLICIT_ASSERTION
	);

	// 4-E-4
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_4_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_4_PAYLOAD
			= new RfcToken("this is a hidden message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_4_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V4_E_4_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0"
			+ "KW9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4gt6TiLm55vIH8c_lGxxZpE3AWlH4WTR0v45nsWoU3gQ";
	private static final byte[] RFC_TEST_VECTOR_V4_E_4_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_4_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_4 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_4_KEY,
			RFC_TEST_VECTOR_V4_E_4_NONCE,
			RFC_TEST_VECTOR_V4_E_4_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_4_FOOTER,
			RFC_TEST_VECTOR_V4_E_4_TOKEN,
			RFC_TEST_VECTOR_V4_E_4_IMPLICIT_ASSERTION
	);

	// 4-E-5
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_5_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_5_PAYLOAD
			= new RfcToken("this is a secret message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_5_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_E_5_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0K"
			+ "W9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final byte[] RFC_TEST_VECTOR_V4_E_5_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_5_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_5 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_5_KEY,
			RFC_TEST_VECTOR_V4_E_5_NONCE,
			RFC_TEST_VECTOR_V4_E_5_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_5_FOOTER,
			RFC_TEST_VECTOR_V4_E_5_TOKEN,
			RFC_TEST_VECTOR_V4_E_5_IMPLICIT_ASSERTION
	);

	// 4-E-6
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_6_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_6_PAYLOAD
			= new RfcToken("this is a hidden message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_6_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_E_6_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0K"
			+ "W9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6pWSA5HX2wjb3P-xLQg5K5feUCX4P2fpVK3ZLWFbMSxQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final byte[] RFC_TEST_VECTOR_V4_E_6_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_6_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_6 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_6_KEY,
			RFC_TEST_VECTOR_V4_E_6_NONCE,
			RFC_TEST_VECTOR_V4_E_6_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_6_FOOTER,
			RFC_TEST_VECTOR_V4_E_6_TOKEN,
			RFC_TEST_VECTOR_V4_E_6_IMPLICIT_ASSERTION
	);

	// 4-E-7
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_7_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_7_PAYLOAD
			= new RfcToken("this is a secret message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_7_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_E_7_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0K"
			+ "W9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t40KCCWLA7GYL9KFHzKlwY9_RnIfRrMQpueydLEAZGGcA.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final byte[] RFC_TEST_VECTOR_V4_E_7_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_7_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-E-7\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_7 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_7_KEY,
			RFC_TEST_VECTOR_V4_E_7_NONCE,
			RFC_TEST_VECTOR_V4_E_7_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_7_FOOTER,
			RFC_TEST_VECTOR_V4_E_7_TOKEN,
			RFC_TEST_VECTOR_V4_E_7_IMPLICIT_ASSERTION
	);

	// 4-E-8
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_8_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_8_PAYLOAD
			= new RfcToken("this is a hidden message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_8_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_E_8_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0K"
			+ "W9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t5uvqQbMGlLLNYBc7A6_x7oqnpUK5WLvj24eE4DVPDZjw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final byte[] RFC_TEST_VECTOR_V4_E_8_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_8_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-E-8\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_8 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_8_KEY,
			RFC_TEST_VECTOR_V4_E_8_NONCE,
			RFC_TEST_VECTOR_V4_E_8_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_8_FOOTER,
			RFC_TEST_VECTOR_V4_E_8_TOKEN,
			RFC_TEST_VECTOR_V4_E_8_IMPLICIT_ASSERTION
	);

	// 4-E-9
	private static final SymmetricKey RFC_TEST_VECTOR_V4_E_9_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_E_9_PAYLOAD
			= new RfcToken("this is a hidden message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_E_9_FOOTER
			= "arbitrary-string-that-isn't-json";
	private static final String RFC_TEST_VECTOR_V4_E_9_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WiA8rd3wgFSNb_UdJPXjpzm0K"
			+ "W9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t6tybdlmnMwcDMw0YxA_gFSE_IUWl78aMtOepFYSWYfQA.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
	private static final byte[] RFC_TEST_VECTOR_V4_E_9_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_E_9_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-E-9\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_E_9 = new TestVector<>(
			RFC_TEST_VECTOR_V4_E_9_KEY,
			RFC_TEST_VECTOR_V4_E_9_NONCE,
			RFC_TEST_VECTOR_V4_E_9_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_E_9_FOOTER,
			RFC_TEST_VECTOR_V4_E_9_TOKEN,
			RFC_TEST_VECTOR_V4_E_9_IMPLICIT_ASSERTION
	);

	// 4-S-1
	private static final AsymmetricSecretKey RFC_TEST_VECTOR_V4_S_1_SECRET_KEY = new AsymmetricSecretKey(
			Hex.decode("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final AsymmetricPublicKey RFC_TEST_VECTOR_V4_S_1_PUBLIC_KEY = new AsymmetricPublicKey(
			Hex.decode("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_S_1_PAYLOAD
			= new RfcToken("this is a signed message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_S_1_FOOTER = "";
	private static final String RFC_TEST_VECTOR_V4_S_1_TOKEN =
			"v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9bg"
					+ "_XBBzds8lTZShVlwwKSgeKpLT3yukTw6JUz3W4h_ExsQV-P0V54zemZDcAxFaSeef1QlXEFtkqxT1ciiQEDA";
	private static final String RFC_TEST_VECTOR_V4_S_1_IMPLICIT_ASSERTION = "";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_S_1 = new TestVector<>(
			RFC_TEST_VECTOR_V4_S_1_SECRET_KEY,
			RFC_TEST_VECTOR_V4_S_1_PUBLIC_KEY,
			RFC_TEST_VECTOR_V4_S_1_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_S_1_FOOTER,
			RFC_TEST_VECTOR_V4_S_1_TOKEN,
			RFC_TEST_VECTOR_V4_S_1_IMPLICIT_ASSERTION
	);

	// 4-S-2
	private static final AsymmetricSecretKey RFC_TEST_VECTOR_V4_S_2_SECRET_KEY = new AsymmetricSecretKey(
			Hex.decode("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final AsymmetricPublicKey RFC_TEST_VECTOR_V4_S_2_PUBLIC_KEY = new AsymmetricPublicKey(
			Hex.decode("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_S_2_PAYLOAD
			= new RfcToken("this is a signed message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_S_2_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_S_2_TOKEN =
			"v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9v3"
					+ "Jt8mx_TdM2ceTGoqwrh4yDFn0XsHvvV_D0DtwQxVrJEBMl0F2caAdgnpKlt4p7xBnx1HcO-SPo8FPp214HDw.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final String RFC_TEST_VECTOR_V4_S_2_IMPLICIT_ASSERTION = "";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_S_2 = new TestVector<>(
			RFC_TEST_VECTOR_V4_S_2_SECRET_KEY,
			RFC_TEST_VECTOR_V4_S_2_PUBLIC_KEY,
			RFC_TEST_VECTOR_V4_S_2_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_S_2_FOOTER,
			RFC_TEST_VECTOR_V4_S_2_TOKEN,
			RFC_TEST_VECTOR_V4_S_2_IMPLICIT_ASSERTION
	);

	// 4-S-3
	private static final AsymmetricSecretKey RFC_TEST_VECTOR_V4_S_3_SECRET_KEY = new AsymmetricSecretKey(
			Hex.decode("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final AsymmetricPublicKey RFC_TEST_VECTOR_V4_S_3_PUBLIC_KEY = new AsymmetricPublicKey(
			Hex.decode("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_S_3_PAYLOAD
			= new RfcToken("this is a signed message", "2022-01-01T00:00:00+00:00");
	private static final String RFC_TEST_VECTOR_V4_S_3_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_S_3_TOKEN =
			"v4.public.eyJkYXRhIjoidGhpcyBpcyBhIHNpZ25lZCBtZXNzYWdlIiwiZXhwIjoiMjAyMi0wMS0wMVQwMDowMDowMCswMDowMCJ9NP"
					+ "WciuD3d0o5eXJXG5pJy-DiVEoyPYWs1YSTwWHNJq6DZD3je5gf-0M4JR9ipdUSJbIovzmBECeaWmaqcaP0DQ.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final String RFC_TEST_VECTOR_V4_S_3_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-S-3\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_S_3 = new TestVector<>(
			RFC_TEST_VECTOR_V4_S_3_SECRET_KEY,
			RFC_TEST_VECTOR_V4_S_3_PUBLIC_KEY,
			RFC_TEST_VECTOR_V4_S_3_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_S_3_FOOTER,
			RFC_TEST_VECTOR_V4_S_3_TOKEN,
			RFC_TEST_VECTOR_V4_S_3_IMPLICIT_ASSERTION
	);

	// 4-F-1
	private static final SymmetricKey RFC_TEST_VECTOR_V4_F_1_KEY = null;
	private static final RfcToken RFC_TEST_VECTOR_V4_F_1_PAYLOAD = null;
	private static final String RFC_TEST_VECTOR_V4_F_1_FOOTER
			= "arbitrary-string-that-isn't-json";
	private static final String RFC_TEST_VECTOR_V4_F_1_TOKEN
			= "v4.local.vngXfCISbnKgiP6VWGuOSlYrFYU300fy9ijW33rznDYgxHNPwWluAY2Bgb0z54CUs6aYYkIJ-bOOOmJHPuX_34Agt_IPlN"
			+ "dGDpRdGNnBz2MpWJvB3cttheEc1uyCEYltj7wBQQYX.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
	private static final byte[] RFC_TEST_VECTOR_V4_F_1_NONCE = null;
	private static final String RFC_TEST_VECTOR_V4_F_1_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-F-1\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_F_1 = new TestVector<>(
			RFC_TEST_VECTOR_V4_F_1_KEY,
			RFC_TEST_VECTOR_V4_F_1_NONCE,
			RFC_TEST_VECTOR_V4_F_1_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_F_1_FOOTER,
			RFC_TEST_VECTOR_V4_F_1_TOKEN,
			RFC_TEST_VECTOR_V4_F_1_IMPLICIT_ASSERTION
	);

	// 4-F-2
	private static final AsymmetricSecretKey RFC_TEST_VECTOR_V4_F_2_SECRET_KEY = new AsymmetricSecretKey(
			Hex.decode("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final AsymmetricPublicKey RFC_TEST_VECTOR_V4_F_2_PUBLIC_KEY = new AsymmetricPublicKey(
			Hex.decode("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_F_2_PAYLOAD = null;
	private static final String RFC_TEST_VECTOR_V4_F_2_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_F_2_TOKEN
			= "v4.public.eyJpbnZhbGlkIjoidGhpcyBzaG91bGQgbmV2ZXIgZGVjb2RlIn22Sp4gjCaUw0c7EH84ZSm_jN_Qr41MrgLNu5LIBCzUr1"
			+ "pn3Z-Wukg9h3ceplWigpoHaTLcwxj0NsI1vjTh67YB.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final String RFC_TEST_VECTOR_V4_F_2_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-F-2\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_F_2 = new TestVector<>(
			RFC_TEST_VECTOR_V4_F_2_SECRET_KEY,
			RFC_TEST_VECTOR_V4_F_2_PUBLIC_KEY,
			RFC_TEST_VECTOR_V4_F_2_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_F_2_FOOTER,
			RFC_TEST_VECTOR_V4_F_2_TOKEN,
			RFC_TEST_VECTOR_V4_F_2_IMPLICIT_ASSERTION
	);

	// 4-F-3
	private static final SymmetricKey RFC_TEST_VECTOR_V4_F_3_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V3
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_F_3_PAYLOAD = null;
	private static final String RFC_TEST_VECTOR_V4_F_3_FOOTER
			= "arbitrary-string-that-isn't-json";
	private static final String RFC_TEST_VECTOR_V4_F_3_TOKEN
			= "v3.local.23e_2PiqpQBPvRFKzB0zHhjmxK3sKo2grFZRRLM-U7L0a8uHxuF9RlVz3Ic6WmdUUWTxCaYycwWV1yM8gKbZB2JhygDM"
			+ "KvHQ7eBf8GtF0r3K0Q_gF1PXOxcOgztak1eD1dPe9rLVMSgR0nHJXeIGYVuVrVoLWQ.YXJiaXRyYXJ5LXN0cmluZy10aGF0LWlzbid0LWpzb24";
	private static final byte[] RFC_TEST_VECTOR_V4_F_3_NONCE = Hex.decode(
			"26f7553354482a1d91d4784627854b8da6b8042a7966523c2b404e8dbbe7f7f2"
	);
	private static final String RFC_TEST_VECTOR_V4_F_3_IMPLICIT_ASSERTION
			= "{\"test-vector\":\"4-F-3\"}";
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_F_3 = new TestVector<>(
			RFC_TEST_VECTOR_V4_F_3_KEY,
			RFC_TEST_VECTOR_V4_F_3_NONCE,
			RFC_TEST_VECTOR_V4_F_3_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_F_3_FOOTER,
			RFC_TEST_VECTOR_V4_F_3_TOKEN,
			RFC_TEST_VECTOR_V4_F_3_IMPLICIT_ASSERTION
	);

	// 4-F-4
	private static final SymmetricKey RFC_TEST_VECTOR_V4_F_4_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_F_4_PAYLOAD = null;
	private static final String RFC_TEST_VECTOR_V4_F_4_FOOTER = null;
	private static final String RFC_TEST_VECTOR_V4_F_4_TOKEN
			= "v4.local.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAr68PS4AXe7If_ZgesdkUMvSwscFlAl1pk5HC0e8kApeaqMfGo_7"
			+ "OpBnwJOAbY9V7WU6abu74MmcUE8YWAiaArVI8XJ5hOb_4v9RmDkneN0S92dx0OW4pgy7omxgf3S8c3LlQh";
	private static final byte[] RFC_TEST_VECTOR_V4_F_4_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_F_4_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_F_4 = new TestVector<>(
			RFC_TEST_VECTOR_V4_F_4_KEY,
			RFC_TEST_VECTOR_V4_F_4_NONCE,
			RFC_TEST_VECTOR_V4_F_4_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_F_4_FOOTER,
			RFC_TEST_VECTOR_V4_F_4_TOKEN,
			RFC_TEST_VECTOR_V4_F_4_IMPLICIT_ASSERTION
	);

	// 4-F-5
	private static final SymmetricKey RFC_TEST_VECTOR_V4_F_5_KEY = new SymmetricKey(
			Hex.decode("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f"),
			Version.V4
	);
	private static final RfcToken RFC_TEST_VECTOR_V4_F_5_PAYLOAD = null;
	private static final String RFC_TEST_VECTOR_V4_F_5_FOOTER
			= "{\"kid\":\"zVhMiPBP9fRf2snEcT7gFTioeA9COcNy9DfgL1W60haN\"}";
	private static final String RFC_TEST_VECTOR_V4_F_5_TOKEN
			= "v4.local.32VIErrEkmY4JVILovbmfPXKW9wT1OdQepjMTC_MOtjA4kiqw7_tcaOM5GNEcnTxl60WkwMsYXw6FSNb_UdJPXjpzm0K"
			+ "W9ojM5f4O2mRvE2IcweP-PRdoHjd5-RHCiExR1IK6t4x-RMNXtQNbz7FvFZ_G-lFpk5RG3EOrwDL6CgDqcerSQ==.eyJraWQiOiJ6VmhNaVBCUDlmUmYyc25FY1Q3Z0ZUaW9lQTlDT2NOeTlEZmdMMVc2MGhhTiJ9";
	private static final byte[] RFC_TEST_VECTOR_V4_F_5_NONCE = Hex.decode(
			"df654812bac492663825520ba2f6e67cf5ca5bdc13d4e7507a98cc4c2fcc3ad8"
	);
	private static final String RFC_TEST_VECTOR_V4_F_5_IMPLICIT_ASSERTION = null;
	public static TestVector<RfcToken, String> RFC_TEST_VECTOR_V4_F_5 = new TestVector<>(
			RFC_TEST_VECTOR_V4_F_5_KEY,
			RFC_TEST_VECTOR_V4_F_5_NONCE,
			RFC_TEST_VECTOR_V4_F_5_PAYLOAD,
			RfcToken.class,
			RFC_TEST_VECTOR_V4_F_5_FOOTER,
			RFC_TEST_VECTOR_V4_F_5_TOKEN,
			RFC_TEST_VECTOR_V4_F_5_IMPLICIT_ASSERTION
	);

}
