package net.aholbrook.paseto.test.common.data;

import net.aholbrook.paseto.service.KeyId;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.common.utils.Hex;

public class TokenTestVectors {
	// q9Rq3FfaAyN8JWyVJhphybm9DaFNLVt2
	public static byte[] TEST_KEY = Hex.decode("713952713346666141794e384a5779564a68706879626d394461464e4c567432");
	// SmpF7Y5DeSJFJxjMrnDSwnUv
	public static byte[] TEST_NONCE = Hex.decode("536d70463759354465534a464a786a4d726e4453776e5576");

	public static byte[] TEST_SK = Hex.decode("452c1969ed4806c8d48ee4c670df980183f6796633787b15a03f09cb24eebe7c432"
			+ "fa82fc615a23192c7cb24cd3dfc4897c6e113db87dced7604d34d06c5b68d");

	public static byte[] TEST_PK = Hex.decode("432fa82fc615a23192c7cb24cd3dfc4897c6e113db87dced7604d34d06c5b68d");

	// paseto-base/test_v1_rsa
	public static byte[] TEST_RSA_PRIVATE_KEY = Hex.decode(
			"308204bd020100300d06092a864886f70d0101010500048204a7308204a30201000282010100b282b532724e9646349947452b"
					+ "64b0ff1597f8428161785011e43a1187a90466c420271626909b865f2fdd1d4635a025b5a34394a2fa4bcfa963886cd0"
					+ "308b4911b2a702c89aa38ebd80dec7b367226ab504ec29487037d509db7e9f6bb09a83cdd2f20ac4d664ba6df7e5b7a1"
					+ "bb08e47297781b19e1cc1a50c4ef11059ff451e72d817804028332552de50fb0d5878a12f3d559007bbb85613a7f6117"
					+ "d9945bc26266ca12a75d1bda713ce03f85ce59e26c12c022a3554b752a8e15cf25972532b5052ab294ecee2ac80916eb"
					+ "372328153fb1c88edc8409af5bd42a3b11eaf8cca70cc62a8a4770f5ef2617b6dc77c01ceb6b8cfaa2a3979a2cb70595"
					+ "1e0c9502030100010282010011d961f6d659274b83cce3c475cf4ea762e85c29823855c863d19740d378c1f8e899726f"
					+ "1392180afa8f95a36cb6c5f99f4ce0e006dfd21ec4883046f91631872fded636400abe59f276e54fc08f8a70730337fd"
					+ "f4c14bc3e0857306cbc4cfde680134b480f4130455249972a0184c8e532af41679a30b3e825efeac8c0c6f686a5e0998"
					+ "bd30c8599f5ea577862720092f75a8222380352aefe1751651a862a59350a6b04d51483a4b027e9474a497f678dda1e9"
					+ "6ed03a5ce8d9677d937ad7b9ded79728fbe7726a654c0e8cda03cd7415219b4823ab4ea8a9fdb83216592831b93e2fe2"
					+ "bf4a61e061c90498aa2fb4815cceb2811998fe361f2356ff248187e102818100d5ec46ec6994de56c7524caab59d00cf"
					+ "71bdef72731d0bfe802d732de99ed1458712d0230f0692a84e8e2eca34f701e273eaa9054bd50fcbc1269c277c38da14"
					+ "0452e8351f34b94f6feff4514f22bf020851d16100bce4e41b81d1e5843b58f7821ace26deb5a062f72bce5f37cbec11"
					+ "72e2ef277434c77b6d86e6233edaf64d02818100d59f4d1c45f2729052e58642da3942dbef094ced032dfbb3379b21d9"
					+ "ecb02ecb25eed258e1bc27a3faa5c6c0de55450f99c961a3ff049b0254f4942c52ac8b80e351be8d9e4c25f3fbb71386"
					+ "7ef32aafda4fcc91a1999cb9ced38e3fed4967457bc64ab23c82ff786ca3eb2b1fec9dec6a5a65330239d4ccdb4b4b6a"
					+ "626ca36902818100aef06c0785482292e0a962dcef6c176f8d5a7fe81e4f10b1ed6c3d96bc480e67475091393a5e6bac"
					+ "8ba1268e61c5e59aa4a4afd80eed8bdf5a73129c0fb00656fc3a387ec8a83b2ac5257bacca8465a369de4ed57edefa67"
					+ "b83eefc13be3b49ba39ffc1a39625a68d42cd4b57551a41998d41033398ab7df2df0755f3955a2b90281803d83b9f8c2"
					+ "4ba6a1d8bd2f8460c2cc75f8c77cd7636b0268014332e4463c15bd7a16e38ba4b541d4fe806e536bb2b24863c891cd5f"
					+ "ca3bb8d82df5dd2d91723a933b1edc3911447c95a78a7fd85ebd941611949efb21f8f7a88f530f258d55a7b494cd3db6"
					+ "1f22e1d2a7013951e01939d30664cde37e33c12a04ec9a9ded1ac10281802a56a5dac634a14a693354f000c6d0d812a6"
					+ "b12378fdc8d1d6a242d85286631ed66a9cb8679663313a629e1ce7391b3506313414c88b3f4d8ea2dc3a0f974ba01a34"
					+ "ef4280d4abd5ed55dd645f775a6d3085f0d4d2477327a4ff810a4f88a39adc1040900e9de1441578d42fd9977ef23069"
					+ "161a882c59403e87bda25de0a98c");

	// paseto-base/test_v1_rsa.pub
	public static byte[] TEST_RSA_PUBLIC_KEY = Hex.decode(
			"30820122300d06092a864886f70d01010105000382010f003082010a0282010100b282b532724e9646349947452b64b0ff1597"
					+ "f8428161785011e43a1187a90466c420271626909b865f2fdd1d4635a025b5a34394a2fa4bcfa963886cd0308b4911b2"
					+ "a702c89aa38ebd80dec7b367226ab504ec29487037d509db7e9f6bb09a83cdd2f20ac4d664ba6df7e5b7a1bb08e47297"
					+ "781b19e1cc1a50c4ef11059ff451e72d817804028332552de50fb0d5878a12f3d559007bbb85613a7f6117d9945bc262"
					+ "66ca12a75d1bda713ce03f85ce59e26c12c022a3554b752a8e15cf25972532b5052ab294ecee2ac80916eb372328153f"
					+ "b1c88edc8409af5bd42a3b11eaf8cca70cc62a8a4770f5ef2617b6dc77c01ceb6b8cfaa2a3979a2cb705951e0c950203"
					+ "010001");

	public final static Token TOKEN_1 = new Token()
			.setIssuer("paragonie.com")
			.setSubject("test")
			.setAudience("pie-hosted.com")
			.setExpiration(2177452800L) // 2039-01-01T00:00:00+00:00
			.setNotBefore(2153692800L) // 2038-04-01T00:00:00+00:00
			.setIssuedAt(2152396800L) // 2038-03-17T00:00:00+00:00
			.setTokenId("87IFSGFgPNtQNNuw0AtuLttP");
	private final static KeyId TOKEN_1_FOOTER = new KeyId().setKeyId("key-1");
	public final static String TOKEN_1_STRING = "{\"exp\":\"2039-01-01T00:00:00+00:00\",\"iss\":\"paragonie.com\","
			+ "\"sub\":\"test\",\"aud\":\"pie-hosted.com\",\"jti\":\"87IFSGFgPNtQNNuw0AtuLttP\","
			+ "\"nbf\":\"2038-04-01T00:00:00+00:00\",\"iat\":\"2038-03-17T00:00:00+00:00\"}";
	private final static String TOKEN_1_V1_LOCAL
			= "v1.local.m6N_QKd4XTRmXT-q2VJbh2A4QqVy2Cp26f3kx837_wsZI16E44Fpz1ha_ze2T2obkEfp--ZbCRCc5GFJxiHk-X99BGUrQXc"
			+ "-S1Zu5TUVBqPMh5dcLqhD41AccpGKGKI0DPGgLSrf0euLlJIhwDsxR2WdPRCRMa46hZ9aUZw9We2gFjM12cfH9qDc4dFq7AMyEsYvUML"
			+ "VDV5xuapW12-C3m1AgDQaeQUUC0Lcl6f-UGrR0VCszpZtzfw1aNSofS7yHkGE0G6ENZ1WgdzdWiXQn97qi18YD756_Vsv5VJVuVOBFXs"
			+ "mcluDcDhVh11010OWK858NNN4u1z8UORAv1e3Gzuz5ZdcX3-GmQQv7OuVv6UAEg";
	private final static String TOKEN_1_V1_LOCAL_WITH_FOOTER
			= "v1.local.m6N_QKd4XTRmXT-q2VJbh2A4QqVy2Cp26f3kx837_wsZI16E44Fpz1ha_ze2T2obkEfp--ZbCRCc5GFJxiHk-X99BGUrQXc"
			+ "-S1Zu5TUVBqPMh5dcLqhD41AccpGKGKI0DPGgLSrf0euLlJIhwDsxR2WdPRCRMa46hZ9aUZw9We2gFjM12cfH9qDc4dFq7AMyEsYvUML"
			+ "VDV5xuapW12-C3m1AgDQaeQUUC0Lcl6f-UGrR0VCszpZtzfw1aNSofS7yHkGE0G6ENZ1WgdzdWiXQn97qi18YD756_Vsv5VJVuVOBFQN"
			+ "tZ4EF_vCbxUlY87KndoN-ilJDQDd-WK4yqAVHcVW3uYNGgD1OZLw9Ases7jUqAw.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_1_V1_PUBLIC
			= "v1.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaXNzIjoicGFyYWdvbmllLmNvbSIsInN1YiI6InRlc3QiLC"
			+ "JhdWQiOiJwaWUtaG9zdGVkLmNvbSIsIm5iZiI6IjIwMzgtMDQtMDFUMDA6MDA6MDArMDA6MDAiLCJpYXQiOiIyMDM4LTAzLTE3VDAwOj"
			+ "AwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIn0OUAoUC1JXZRCAk3RGxnpVdH1fB0nN5_wBa9Z7F0aBVA"
			+ "dKBQCUkB5OwNcUNlE7R_MR1D1seWFgj0xTSIBQHEFhatBpBpO2QUT16FR0VdxG-coTLReCN5d_TvYzSsKCA2I1H9UXlQBfJIfNXJHeQ9"
			+ "tnZZKXhkq93Jxg6tStBTpL1vFpvvzcxTgacLUobGllKetDn9mdtbq_SOQ2fM840T0BXeGaEFrWYDO9WPf8t9aAGKYwV1lh7tYTl9B5Zt"
			+ "GVzdPJdljvsyCKTTwRxhvWDL3e6Jy02H_1cZjOkoH8fLpqmeyEQA5-swzVwTaaGpgYGU_gZWMgofFWjQeQ-BTaL6VA";
	private final static String TOKEN_1_V1_PUBLIC_WITH_FOOTER
			= "v1.public.eyJleHAiOiIyMDM5LTAxLTAxVDAwOjAwOjAwKzAwOjAwIiwiaXNzIjoicGFyYWdvbmllLmNvbSIsInN1YiI6InRlc3QiLC"
			+ "JhdWQiOiJwaWUtaG9zdGVkLmNvbSIsIm5iZiI6IjIwMzgtMDQtMDFUMDA6MDA6MDArMDA6MDAiLCJpYXQiOiIyMDM4LTAzLTE3VDAwOj"
			+ "AwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIn1DMRW-gRvx5db1UFNWzxZVJDZjVD4cmkSWPsdAnXzzjo"
			+ "Yn1JccSIWllUz5mKvvCoYMoJbY3iXORq2M3Unct9C9GaTM2eGp6c9C5vSZ7OIMFU3crZ3y_6k2XGx_qcLbQSs2jPtfi5mKIT0qIIVkDy"
			+ "78lDG3muQP4ox3f0zJpqhZnRaU4gA9Ht4n4-yUm8jZMw85R2NOJ2a7nMlZPtuUPtAcOeWzr0EaHLFrqNhtvwakT-kATj_DWHaUgP8mUj"
			+ "Dj_dH0mxLV9xyDeV14aUg92Jh-ddMxE7dNVoBZxWQ2qwoV0UEUgzTu6Eg-m1etuFMb9HopeYRBJrLvB0loyxo5boHi.eyJraWQiOiJrZ"
			+ "XktMSJ9";
	private final static String TOKEN_1_V2_LOCAL
			= "v2.local.3kYO_Lnf8Ff8l-R5MDUE6OHeS5TrBjl4Hc3Z8bJDMDzuOCjFHpzkjB135N7hcYs6RmwknxD5ziidhQKexbVxYYFAOW6QSQb"
			+ "v9Mdrd4KSRKXIXMfAIB_QFVKPb2-u3NREHsBAgooPVv5qezQJEObCgEpRuUizbJhmx4BbJ2yZ_GRpnOZpwfPdViC7hWULo19K2uhnVX2"
			+ "72pzIKQY5BJBTfExlsFuYF0zb_a3t5rFds_AOz4Ax9hLcpl6qHE-bubfleg2DPY0OqYKvHXgmBjnygVK7t_h7QRwASmbGPGaucITuq29"
			+ "DaygqjvEB";
	private final static String TOKEN_1_V2_LOCAL_WITH_FOOTER
			= "v2.local.3kYO_Lnf8Ff8l-R5MDUE6OHeS5TrBjl4Hc3Z8bJDMDzuOCjFHpzkjB135N7hcYs6RmwknxD5ziidhQKexbVxYYFAOW6QSQb"
			+ "v9Mdrd4KSRKXIXMfAIB_QFVKPb2-u3NREHsBAgooPVv5qezQJEObCgEpRuUizbJhmx4BbJ2yZ_GRpnOZpwfPdViC7hWULo19K2uhnVX2"
			+ "72pzIKQY5BJBTfExlsFuYF0zb_a3t5rFds_AOz4Ax9hLcpl6qHE-bubfleg2DPY0OqYKvHXgmBjnygVK7t_h7QRwASmamxVzMUpRu-PG"
			+ "4eB9bBWeP.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_1_V2_PUBLIC
			= "v2.public.eyJpc3MiOiJwYXJhZ29uaWUuY29tIiwic3ViIjoidGVzdCIsImF1ZCI6InBpZS1ob3N0ZWQuY29tIiwiZXhwIjoiMjAzOS"
			+ "0wMS0wMVQwMDowMDowMCswMDowMCIsIm5iZiI6IjIwMzgtMDQtMDFUMDA6MDA6MDArMDA6MDAiLCJpYXQiOiIyMDM4LTAzLTE3VDAwOj"
			+ "AwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIn3esDcxyrLvjdUVc4qJJdDlePpvR6meN9eQYbHCigSL8j"
			+ "kJi6fTfeyzL2kRBfwuIro50vE3iqrQVIHhXTA_mNIK";
	private final static String TOKEN_1_V2_PUBLIC_WITH_FOOTER
			= "v2.public.eyJpc3MiOiJwYXJhZ29uaWUuY29tIiwic3ViIjoidGVzdCIsImF1ZCI6InBpZS1ob3N0ZWQuY29tIiwiZXhwIjoiMjAzOS"
			+ "0wMS0wMVQwMDowMDowMCswMDowMCIsIm5iZiI6IjIwMzgtMDQtMDFUMDA6MDA6MDArMDA6MDAiLCJpYXQiOiIyMDM4LTAzLTE3VDAwOj"
			+ "AwOjAwKzAwOjAwIiwianRpIjoiODdJRlNHRmdQTnRRTk51dzBBdHVMdHRQIn2xoKvT1qvd3J2tLSWXepCJl7TJNiPBobAfU8OQtsU9qF"
			+ "o_K0TZVmdOB-mDFAbv6VXsgercqOAoIK0o3Fa-JA8D.eyJraWQiOiJrZXktMSJ9";
	public final static TestVector<Token, Void> TV_1_V1_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_1,
			Token.class, null, TOKEN_1_V1_LOCAL);
	public final static TestVector<Token, KeyId> TV_1_V1_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY, TEST_NONCE,
			TOKEN_1, Token.class, TOKEN_1_FOOTER, TOKEN_1_V1_LOCAL_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_1_V1_PUBLIC = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_1, Token.class, null, TOKEN_1_V1_PUBLIC);
	public final static TestVector<Token, KeyId> TV_1_V1_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_1, Token.class, TOKEN_1_FOOTER, TOKEN_1_V1_PUBLIC_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_1_V2_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_1,
			Token.class, null, TOKEN_1_V2_LOCAL);
	public final static TestVector<Token, KeyId> TV_1_V2_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY, TEST_NONCE,
			TOKEN_1, Token.class, TOKEN_1_FOOTER, TOKEN_1_V2_LOCAL_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_1_V2_PUBLIC = new TestVector<>(TEST_SK, TEST_PK,
			TOKEN_1, Token.class, null, TOKEN_1_V2_PUBLIC);
	public final static TestVector<Token, KeyId> TV_1_V2_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_SK,
			TEST_PK, TOKEN_1, Token.class, TOKEN_1_FOOTER, TOKEN_1_V2_PUBLIC_WITH_FOOTER);

	public final static CustomToken TOKEN_2 = (CustomToken) new CustomToken()
			.setUserId(100L)
			.setIssuer("auth.example.com")
			.setSubject("user-auth")
			.setAudience("internal-service.example.com")
			.setExpiration(1514827424L) // 2018-01-01T17:23:44+00:00
			.setIssuedAt(1514827124L) // 2018-01-01T17:18:44+00:00
			.setNotBefore(1514827124L); // 2018-01-01T17:18:44+00:00
	private final static KeyId TOKEN_2_FOOTER = new KeyId().setKeyId("key-1");
	public final static String TOKEN_2_STRING = "{\"userId\":100,\"exp\":\"2018-01-01T17:23:44+00:00\","
			+ "\"sub\":\"user-auth\",\"iss\":\"auth.example.com\",\"aud\":\"internal-service.example.com\","
			+ "\"jti\":null,\"nbf\":\"2018-01-01T17:18:44+00:00\",\"iat\":\"2018-01-01T17:18:44+00:00\"}";
	private final static String TOKEN_2_V1_LOCAL
			= "v1.local.2zcmnEIlVH-rWQmYTJ2DcF3sJfxJhEiNYWDpo1eb80-ZOZkJPx0D-i23j2xgjl8VXrbgJuOLUiw6FHLk2-HyEcOqie0IVc1"
			+ "B0CaT-KeHLNLAyBiMRhXoEdPTgMePsNDdhMcH0ot1P3f0_FK6umi5sdDEgvAucH9DoH0emaqHQwMvUxPmc5Gte-dCaxVja6wHKO-E7k_"
			+ "KMKexeDruCajQwVsIr3YjqZ_UeSUMteHbx5SF8y-yfqVwGgB0_OgQN1Wg68EyQJd39zCjO03yNdHqsskFWpCN32rTvG37UEmGvu1EtgK"
			+ "WKhU8hWQckeYjelgDTtLpb6YLo2TNGqqNrZhNfNO2IbbNo3VB7qzHAel58r7nOINF";
	private final static String TOKEN_2_V1_LOCAL_WITH_FOOTER
			= "v1.local.2zcmnEIlVH-rWQmYTJ2DcF3sJfxJhEiNYWDpo1eb80-ZOZkJPx0D-i23j2xgjl8VXrbgJuOLUiw6FHLk2-HyEcOqie0IVc1"
			+ "B0CaT-KeHLNLAyBiMRhXoEdPTgMePsNDdhMcH0ot1P3f0_FK6umi5sdDEgvAucH9DoH0emaqHQwMvUxPmc5Gte-dCaxVja6wHKO-E7k_"
			+ "KMKexeDruCajQwVsIr3YjqZ_UeSUMteHbx5SF8y-yfqVwGgB0_OgQN1Wg68EyQJd39zCjO03yNdHqsskFWpCN32rTvG37UEmGvu1EtgK"
			+ "W1Fl_wOwLlgCuBc3fykE7QoVnCpVh1My5cMtn9NgQtkKSGtgOUrDaf8eOYYiJAAf_.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_2_V1_PUBLIC
			= "v1.public.eyJ1c2VySWQiOjEwMCwiZXhwIjoiMjAxOC0wMS0wMVQxNzoyMzo0NCswMDowMCIsImlzcyI6ImF1dGguZXhhbXBsZS5jb2"
			+ "0iLCJzdWIiOiJ1c2VyLWF1dGgiLCJhdWQiOiJpbnRlcm5hbC1zZXJ2aWNlLmV4YW1wbGUuY29tIiwibmJmIjoiMjAxOC0wMS0wMVQxNz"
			+ "oxODo0NCswMDowMCIsImlhdCI6IjIwMTgtMDEtMDFUMTc6MTg6NDQrMDA6MDAifTk_6iNDYl4u-G-1vlfDlLbcLjBb-eyn76TJsovnVd"
			+ "aFHcjKMd7z-KH7pkE-VXSwof-F08gvVTstNqDEXbJsNsylqQ3XxvDmgBGY8S6Jtz8EC9baYumITHfKUjPTi9yVBQiH-cre03565Ioe9B"
			+ "fsksWDP6mPHpDAibI9FDVTponvJ2FYA4p4UKHxQW2vaIzPZSIb9qvy5Vs5sv9u_skuMliD1mir_vgLYK_7YjncHqq5TyNgwwO6Xnx7qZ"
			+ "9ADS-ut9tje89NzFZzGBeW_vQTcgJCoE_r82YawXwLforxpnv1VV0HaLxFWzCx5WJc02udWeVOmhmpPBCAQyuV5JsQFlM";
	private final static String TOKEN_2_V1_PUBLIC_WITH_FOOTER
			= "v1.public.eyJ1c2VySWQiOjEwMCwiZXhwIjoiMjAxOC0wMS0wMVQxNzoyMzo0NCswMDowMCIsImlzcyI6ImF1dGguZXhhbXBsZS5jb2"
			+ "0iLCJzdWIiOiJ1c2VyLWF1dGgiLCJhdWQiOiJpbnRlcm5hbC1zZXJ2aWNlLmV4YW1wbGUuY29tIiwibmJmIjoiMjAxOC0wMS0wMVQxNz"
			+ "oxODo0NCswMDowMCIsImlhdCI6IjIwMTgtMDEtMDFUMTc6MTg6NDQrMDA6MDAifZHKYq5llXY3dUuAaUvc9IOcqsoJIDqs8ygrwAHiNs"
			+ "2GDsvozdEGz-07CKOk7mB3LHQdJuk5SGCwBlEwVbg-db15JT4cVPJkJVxGqFCZ_M1kjIasiVmoyJqrI-hF4SYDhsb6qVf6ymmWYZX5jz"
			+ "R8T-ekAVz8OGEHNQiHtlGR2RZRwhIfG1t5lyQtiniD8gMFd3bM6Wa6fuNQeXqjn-GC53w9JZGUyNZNLgWd5ouGJlWfU8Ar2m5E5HeLxa"
			+ "pLlXL5gb002ELnTgPxxoT_N6EAslXh1tAmH2fVOT729veD2R8uXgXMCiG2Q0JT_aJl9PpAwhmbm4KUQ1mpVa9sS5ro5X4.eyJraWQiOi"
			+ "JrZXktMSJ9";
	private final static String TOKEN_2_V2_LOCAL
			= "v2.local.IPFGEb8RR5ZS7ib_Ps3pz0wzaZG_PT8pj5FyFsAt2Hiewy1QqdS1Ycvfu2B5qU8lRC0J0n_-9JgSH47w9nxDA3-z2jj_X9i"
			+ "4idrEmkqpLkezliXY1bFLbFvX4gwTuSSDG4ehkSyB5mRQgf6dCTDm6o7EmqOpv0JA8T3Zk7winDAxBlpYGw9MagXtYWI_oEDqbNdMZW0"
			+ "RkExD6C8a7eUDSSJnZLfnAXBs2hrRZTo_hxAWKy93yf4UyuyjvsHHC78nZE2klytdF--fMJpvQMAZk83AdRgoc8o4AqEJCK8kFIK0-Hx"
			+ "yNqO0ga-fKho";
	private final static String TOKEN_2_V2_LOCAL_WITH_FOOTER
			= "v2.local.IPFGEb8RR5ZS7ib_Ps3pz0wzaZG_PT8pj5FyFsAt2Hiewy1QqdS1Ycvfu2B5qU8lRC0J0n_-9JgSH47w9nxDA3-z2jj_X9i"
			+ "4idrEmkqpLkezliXY1bFLbFvX4gwTuSSDG4ehkSyB5mRQgf6dCTDm6o7EmqOpv0JA8T3Zk7winDAxBlpYGw9MagXtYWI_oEDqbNdMZW0"
			+ "RkExD6C8a7eUDSSJnZLfnAXBs2hrRZTo_hxAWKy93yf4UyuyjvsHHC78nZE2klytdF--fMJpvQMAZk83AdRgoc8o4AqEJCCigVA1x3ET"
			+ "iwsiQATxQUVc.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_2_V2_PUBLIC
			= "v2.public.eyJ1c2VySWQiOjEwMCwiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXItYXV0aCIsImF1ZCI6ImludGVybm"
			+ "FsLXNlcnZpY2UuZXhhbXBsZS5jb20iLCJleHAiOiIyMDE4LTAxLTAxVDE3OjIzOjQ0KzAwOjAwIiwibmJmIjoiMjAxOC0wMS0wMVQxNz"
			+ "oxODo0NCswMDowMCIsImlhdCI6IjIwMTgtMDEtMDFUMTc6MTg6NDQrMDA6MDAifRBsAS1UCK6Omo4W46DKYhdOZQoQ1GWT_1TGWquuQZ"
			+ "a-qpK9g-v6Z59YM0wfSrXHmWq_qCxfv2IksBAkdu7M8AU";
	private final static String TOKEN_2_V2_PUBLIC_WITH_FOOTER
			= "v2.public.eyJ1c2VySWQiOjEwMCwiaXNzIjoiYXV0aC5leGFtcGxlLmNvbSIsInN1YiI6InVzZXItYXV0aCIsImF1ZCI6ImludGVybm"
			+ "FsLXNlcnZpY2UuZXhhbXBsZS5jb20iLCJleHAiOiIyMDE4LTAxLTAxVDE3OjIzOjQ0KzAwOjAwIiwibmJmIjoiMjAxOC0wMS0wMVQxNz"
			+ "oxODo0NCswMDowMCIsImlhdCI6IjIwMTgtMDEtMDFUMTc6MTg6NDQrMDA6MDAifWn4VQZkCN2AhWGRcGpGDbj6p4ms8zDeauxMbdSOUW"
			+ "f6aFNIIRhD-K7nLx-FFFDOr1_8MmhaSOZbVCh_tR4euA4.eyJraWQiOiJrZXktMSJ9";
	public final static TestVector<CustomToken, Void> TV_2_V1_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_2,
			CustomToken.class, null, TOKEN_2_V1_LOCAL);
	public final static TestVector<CustomToken, KeyId> TV_2_V1_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY,
			TEST_NONCE, TOKEN_2, CustomToken.class, TOKEN_2_FOOTER, TOKEN_2_V1_LOCAL_WITH_FOOTER);
	public final static TestVector<CustomToken, Void> TV_2_V1_PUBLIC = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_2, CustomToken.class, null, TOKEN_2_V1_PUBLIC);
	public final static TestVector<CustomToken, KeyId> TV_2_V1_PUBLIC_WITH_FOOTER = new TestVector<>(
			TEST_RSA_PRIVATE_KEY, TEST_RSA_PUBLIC_KEY, TOKEN_2, CustomToken.class, TOKEN_2_FOOTER,
			TOKEN_2_V1_PUBLIC_WITH_FOOTER);
	public final static TestVector<CustomToken, Void> TV_2_V2_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_2,
			CustomToken.class, null, TOKEN_2_V2_LOCAL);
	public final static TestVector<CustomToken, KeyId> TV_2_V2_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY,
			TEST_NONCE, TOKEN_2, CustomToken.class, TOKEN_2_FOOTER, TOKEN_2_V2_LOCAL_WITH_FOOTER);
	public final static TestVector<CustomToken, Void> TV_2_V2_PUBLIC = new TestVector<>(TEST_SK,
			TEST_PK, TOKEN_2, CustomToken.class, null, TOKEN_2_V2_PUBLIC);
	public final static TestVector<CustomToken, KeyId> TV_2_V2_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_SK,
			TEST_PK, TOKEN_2, CustomToken.class, TOKEN_2_FOOTER, TOKEN_2_V2_PUBLIC_WITH_FOOTER);

	// Minimal token, only iss and exp set.
	public final static Token TOKEN_3 = new Token()
			.setExpiration(1514827424L) // 2018-01-01T17:23:44+00:00
			.setIssuedAt(1514827124L); // 2018-01-01T17:18:44+00:00
	private final static KeyId TOKEN_3_FOOTER = new KeyId().setKeyId("key-2");
	public final static String TOKEN_3_STRING
			= "";
	private final static String TOKEN_3_V1_LOCAL
			= "v1.local.wpuFMg8zTfqtfL2wiGv9aDSg3TFH6r-viT6sbfY6Kxm3v4YM5gkmqybuFKIEXj5i-uIlW4hnZi0OXSAr1r5XEBG-p6gSuYp"
			+ "2YeD7Q-wGFPW862hH4XpI4Lityp_3toa_HZ4GsgkQLiFFw7JNxCKqOvaj-KYQ2_0Kitu7N6PiGziA0L-Yz0KpBPe9ihHc-ShrdpDelh"
			+ "E";
	private final static String TOKEN_3_V1_LOCAL_WITH_FOOTER
			= "v1.local.wpuFMg8zTfqtfL2wiGv9aDSg3TFH6r-viT6sbfY6Kxm3v4YM5gkmqybuFKIEXj5i-uIlW4hnZi0OXSAr1r5XEBG-p6gSuYp"
			+ "2YeD7Q-wGFPW862hH4XpI4Lityp_3toa_HZ4Gsgk0C7QFJRO_zyNgClnog8ItJ2HJt-5aJN8HjfyX7fPJQiebQirEwb8B4x2sD3RVoU0"
			+ ".eyJraWQiOiJrZXktMiJ9";
	private final static String TOKEN_3_V1_PUBLIC
			= "v1.public.eyJleHAiOiIyMDE4LTAxLTAxVDE3OjIzOjQ0KzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQxNzoxODo0NCswMDowMCJ9l3"
			+ "B_DToj3-jCi-agwSyb2cyjZALQP43qVSDbTofKwaZRN_a9xv-XaemGIrdYt6MaVk7IqUUkvOiaCpJgjqiR4f53UbrnPLCiworEiRSxY2"
			+ "T2mUOZhf99c2BcQ6fmEkSU8aTtjgQxDLWdHzUtsaxqun-jlCQsQnX27UoIe9iiCHD5CxznR2yEGbq2UhvIZouzFOAVJKxl-G9mMPVqs1"
			+ "mmfSRGYS39rgGmljW7y964nZ3B40NkXMgD10_eK2RNg2WeTbfrKGSkyArgOoZLembGUd2F-YCms4yqyqtH7Prf7EMVLNR8ISloWHptoL"
			+ "lYoxd319ed8VMluDz-uqSzoVUBpA";
	private final static String TOKEN_3_V1_PUBLIC_WITH_FOOTER
			= "v1.public.eyJleHAiOiIyMDE4LTAxLTAxVDE3OjIzOjQ0KzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQxNzoxODo0NCswMDowMCJ9eI"
			+ "lEjS5-0-Kl0lHBLrGdFI59wEVkoqLalmSqcJxrWAC6vW5OoN8KPCUBR73P689i30IDsNc7gDNyTTiKJJPefwoPjhCAkXV5Wa_UN40sUG"
			+ "LUGw_jTd9BVZ5hbSsRP_zljm7RGjnh32mOjQZ4I3q-RPbsiL7qoW5SD8pSkjC_-DTsDtMO7yie3YALPnu7X_-M8QZYN0akkwQZ2I6iVC"
			+ "IMWT5nrCjsYtOIzK7ZYrLgEpksuYjCdtk0ZjLfhbiwsBL2L9jKj2VHqNeby9veNmQruWqB48dbczq11QbXIPcAABecWGa7Ayn1-u4XDE"
			+ "lt4IoKDBIt2GrA0lB67fKn4pAI-g.eyJraWQiOiJrZXktMiJ9";
	private final static String TOKEN_3_V2_LOCAL
			= "v2.local.s_IagepBKqxJs4l6e47StVzIDI4P_b2BX1Wqtr-IyyhkUrguLTQT2p7X4bWATXdWQazJtwOQnGm7GHRX90UZFtH505NP0kd"
			+ "5SuE_cyfeSOzFGgG4aFPPxHaQXZeZGPmSKMaF1wsW5jfraa9H5Q";
	private final static String TOKEN_3_V2_LOCAL_WITH_FOOTER
			= "v2.local.s_IagepBKqxJs4l6e47StVzIDI4P_b2BX1Wqtr-IyyhkUrguLTQT2p7X4bWATXdWQazJtwOQnGm7GHRX90UZFtH505NP0kd"
			+ "5SuE_cyfeSOzFGgG4aFPPxHaQXZeZNyYXhSZz9IhSwoIl7jQamw.eyJraWQiOiJrZXktMiJ9";
	private final static String TOKEN_3_V2_PUBLIC
			= "v2.public.eyJleHAiOiIyMDE4LTAxLTAxVDE3OjIzOjQ0KzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQxNzoxODo0NCswMDowMCJ9du"
			+ "vMylS5Zt48Mlu9206iswmp3pNarZya1JHuM4sI8yIOSlB6_LtukHaDjMCfN1jzKqp13jyoVqcIHm1H7RyiBw";
	private final static String TOKEN_3_V2_PUBLIC_WITH_FOOTER
			= "v2.public.eyJleHAiOiIyMDE4LTAxLTAxVDE3OjIzOjQ0KzAwOjAwIiwiaWF0IjoiMjAxOC0wMS0wMVQxNzoxODo0NCswMDowMCJ9gc"
			+ "TyYa__QR6HuqU5Kcbl1cmXZDCEGdFy2xCO4MFnP8teHUfLs_vcY3Dfq3KjgfSAYXxEktCwpxhk3eQwg14yCQ.eyJraWQiOiJrZXktMiJ"
			+ "9";
	public final static TestVector<Token, Void> TV_3_V1_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_3,
			Token.class, null, TOKEN_3_V1_LOCAL);
	public final static TestVector<Token, KeyId> TV_3_V1_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY, TEST_NONCE,
			TOKEN_3, Token.class, TOKEN_3_FOOTER, TOKEN_3_V1_LOCAL_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_3_V1_PUBLIC = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_3, Token.class, null, TOKEN_3_V1_PUBLIC);
	public final static TestVector<Token, KeyId> TV_3_V1_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_3, Token.class, TOKEN_3_FOOTER, TOKEN_3_V1_PUBLIC_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_3_V2_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_3,
			Token.class, null, TOKEN_3_V2_LOCAL);
	public final static TestVector<Token, KeyId> TV_3_V2_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY, TEST_NONCE,
			TOKEN_3, Token.class, TOKEN_3_FOOTER, TOKEN_3_V2_LOCAL_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_3_V2_PUBLIC = new TestVector<>(TEST_SK, TEST_PK,
			TOKEN_3, Token.class, null, TOKEN_3_V2_PUBLIC);
	public final static TestVector<Token, KeyId> TV_3_V2_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_SK,
			TEST_PK, TOKEN_3, Token.class, TOKEN_3_FOOTER, TOKEN_3_V2_PUBLIC_WITH_FOOTER);

	// Empty token
	public final static Token TOKEN_4 = new Token();
	private final static KeyId TOKEN_4_FOOTER = new KeyId().setKeyId("key-1");
	private final static String TOKEN_4_V1_LOCAL
			= "v1.local.--TLHXMWiZYc9aTQma_NiYLMqRDN69tSdiqpU6V-dsNeDhIDqBxyneNGy4bSvNHeNkca_39GwyZdxUx0sOQ8EOQUEAhSrnd"
			+ "EuX2JDwQFsWUUMw";
	private final static String TOKEN_4_V1_LOCAL_WITH_FOOTER
			= "v1.local.--TLHXMWiZYc9aTQma_NiYLMqRDN69tSdiqpU6V-dsNeDhph1Ij5pSdhLuRhJlpQSPuQh4U_fRBFAmZU5ZhfhTnBsrHvR-q"
			+ "8Gs8GnoUO1hr9lA.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_4_V1_PUBLIC
			= "v1.public.e30hJtxCLP0n-WZyvdSqYApXpdaTVFNoYiFRy-GLDM7tSTQM5rl-xCRVyCAgF1xZ1a-2EzVSkZongX2hE9e55VowPse8jI"
			+ "GvT9oYNx0Xmu5OyNMBCV1LpO45lDqi5Ulw4wq-UEmlewq4cf8ERVI1UbfrysPC8Ie-6sh1v77sbEajzlOydJMq2KB4qWG-W0qFL0nJ6p"
			+ "4hNRHPQajokFgdNsCdJW9fZ9JGSXPkkRnBX8hl4qm_prKVMLsx-9YwpLnEagW7ZM73RdaEY65aOCL5uuUGCkhLcOTBywdknEv3Vytdpg"
			+ "cRKpaIzvpE_KMwuK-UnSeNhYhruXbbeChE9qPIfzMh";
	private final static String TOKEN_4_V1_PUBLIC_WITH_FOOTER
			= "v1.public.e31S5itjTRTcxHALKCdpUxyMNr15pEMxZZiDYiulJStAa_n7MtEJbqddYHsuZyGz7PlpYuTYfmiH_dziAj7FPwQ4d_tTcS"
			+ "sTq8cT6IUpA5et7W55iVSUoGUoRSBMEM5CepNq4yc0KR4ryvPv2KQ2RQHF9BnCbH8LyHyiTGO_6UHRHeLZrlaCUyJG3AUrFJPQ6Oehbe"
			+ "6vMBTfHqPL-f6j4ldvS7ki9gHL_iN3EMoy2-v6bNkRpoYDLATZbwsje1aR7Vhk2v_Aiop2pAoqO8VWs6U4KVSN5gukUW2-6h97btmdfM"
			+ "5DZkpYhQVHGdqsOFCBB5txZSNjDtpfCo-oGAHkBIA2.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_4_V2_LOCAL
			= "v2.local.iX9JhHZ4_OW6GHqAbSPP23VAGg5RnEeuGgVksnbXKVHrlWaTU18JRP9I";
	private final static String TOKEN_4_V2_LOCAL_WITH_FOOTER
			= "v2.local.iX9JhHZ4_OW6GHqAbSPP23VAGg5RnEeuGgWaTY-bgw1FO-EuJhIaUJp2.eyJraWQiOiJrZXktMSJ9";
	private final static String TOKEN_4_V2_PUBLIC
			= "v2.public.e31M63YrD2PTNGHzBHHeLhYooCXgT2KxLBmPdFSlLr-7poFIEaxqGD7w2XCwcdJkSjagz2o7Gtwh9VYTRHGtYMEM";
	private final static String TOKEN_4_V2_PUBLIC_WITH_FOOTER
			= "v2.public.e30RItbv4bN4XIzyLFapaMll5aOnuqcmttzAH4-pFf8vHrK8COU0EeGwlt-1tfR3OkUxTyoQdlE2dlOtbLxlbrEO.eyJra"
			+ "WQiOiJrZXktMSJ9";
	public final static TestVector<Token, Void> TV_4_V1_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_4,
			Token.class, null, TOKEN_4_V1_LOCAL);
	public final static TestVector<Token, KeyId> TV_4_V1_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY, TEST_NONCE,
			TOKEN_4, Token.class, TOKEN_4_FOOTER, TOKEN_4_V1_LOCAL_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_4_V1_PUBLIC = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_4, Token.class, null, TOKEN_4_V1_PUBLIC);
	public final static TestVector<Token, KeyId> TV_4_V1_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_RSA_PRIVATE_KEY,
			TEST_RSA_PUBLIC_KEY, TOKEN_4, Token.class, TOKEN_4_FOOTER, TOKEN_4_V1_PUBLIC_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_4_V2_LOCAL = new TestVector<>(TEST_KEY, TEST_NONCE, TOKEN_4,
			Token.class, null, TOKEN_4_V2_LOCAL);
	public final static TestVector<Token, KeyId> TV_4_V2_LOCAL_WITH_FOOTER = new TestVector<>(TEST_KEY, TEST_NONCE,
			TOKEN_4, Token.class, TOKEN_4_FOOTER, TOKEN_4_V2_LOCAL_WITH_FOOTER);
	public final static TestVector<Token, Void> TV_4_V2_PUBLIC = new TestVector<>(TEST_SK, TEST_PK,
			TOKEN_4, Token.class, null, TOKEN_4_V2_PUBLIC);
	public final static TestVector<Token, KeyId> TV_4_V2_PUBLIC_WITH_FOOTER = new TestVector<>(TEST_SK,
			TEST_PK, TOKEN_4, Token.class, TOKEN_4_FOOTER, TOKEN_4_V2_PUBLIC_WITH_FOOTER);
}
