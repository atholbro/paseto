package net.aholbrook.paseto.meta;

import net.aholbrook.paseto.Paseto;
import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.service.TokenService;
import net.aholbrook.paseto.test.PasetoV2ServiceTestBase;
import net.aholbrook.paseto.test.crypto.TestNonceGenerator;
import net.aholbrook.paseto.test.data.RfcToken;

public class PasetoV2ServiceTest extends PasetoV2ServiceTestBase {
	@Override
	protected TokenService<RfcToken> createRfcLocal(byte[] nonce) {
		Paseto.Builder<RfcToken> pasetoBuilder = PasetoBuilders.V2.<RfcToken>paseto()
				.withTestingNonceGenerator(new TestNonceGenerator(nonce));

		return PasetoBuilders.V2.localService(pasetoBuilder, localKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}

	@Override
	protected TokenService<RfcToken> createRfcPublic() {
		return PasetoBuilders.V2.publicService(publicKeyProvider(), RfcToken.class)
				.checkClaims(new Claim[] {})
				.build();
	}
}
