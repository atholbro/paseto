package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.PasetoV1ServiceTestBase;
import net.aholbrook.paseto.test.crypto.TestNonceGenerator;
import net.aholbrook.paseto.test.data.RfcToken;

public class PasetoV1ServiceTest extends PasetoV1ServiceTestBase {
	@Override
	protected TokenService<RfcToken> createRfcLocal(byte[] nonce) {
		Paseto.Builder<RfcToken> pasetoBuilder = PasetoBuilders.V1.<RfcToken>paseto()
				.withTestingNonceGenerator(new TestNonceGenerator(nonce));

		return PasetoBuilders.V1.localService(pasetoBuilder, localKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	@Override
	protected TokenService<RfcToken> createRfcPublic() {
		return PasetoBuilders.V1.publicService(publicKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}
}
