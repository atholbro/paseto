package net.aholbrook.paseto.test;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.exception.verification.rules.ExpiredTokenException;
import net.aholbrook.paseto.exception.verification.rules.MultipleRuleException;
import net.aholbrook.paseto.exception.verification.rules.NotYetValidTokenException;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import net.aholbrook.paseto.verification.PasetoVerification;
import net.aholbrook.paseto.verification.rules.CurrentlyValid;
import net.aholbrook.paseto.verification.rules.IssuedInPast;
import net.aholbrook.paseto.verification.rules.Rule;
import org.junit.Assert;
import org.junit.Test;

import java.time.OffsetDateTime;

public abstract class TokenVerificationTestBase {
	protected abstract EncodingProvider getEncodingProvider();

	private void standardVerification(Token token, OffsetDateTime time) {
		Rule[] rules = new Rule[] {
				new IssuedInPast(time, IssuedInPast.DEFAULT_ALLOWABLE_DRIFT),
				new CurrentlyValid(time, CurrentlyValid.DEFAULT_ALLOWABLE_DRIFT)
		};

		PasetoVerification.verify(token, rules);
	}

	@Test
	public void token1_verificationValid() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getNotBefore().plusSeconds(5);

		standardVerification(token, time);
	}

	@Test
	public void token1_verificationValid2() {
		Token token = TokenTestVectors.TOKEN_1;
		// check directly at expiry time, should still be considered valid
		OffsetDateTime time = token.getExpiration();

		standardVerification(token, time);
	}

	@Test(expected = ExpiredTokenException.class)
	public void token_verification_expired1() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getExpiration().plusDays(1);

		standardVerification(token, time);
	}

	@Test(expected = ExpiredTokenException.class)
	public void token_verification_expired2() {
		Token token = TokenTestVectors.TOKEN_1;
		// check 1 second after expiry time, should be invalid
		OffsetDateTime time = token.getExpiration().plusSeconds(1);

		standardVerification(token, time);
	}

	@Test
	public void token_verification_expired3() {
		Token token = TokenTestVectors.TOKEN_1;
		// check exact expiry time, should pass
		OffsetDateTime time = token.getExpiration();

		standardVerification(token, time);
	}

	@Test
	public void token_verification_expired4() {
		Token token = TokenTestVectors.TOKEN_1;
		// check expiry time - 1 second, should pass
		OffsetDateTime time = token.getExpiration().minusSeconds(1);

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_issuedAt1() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = token.getIssuedAt();

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_issuedAt2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = token.getIssuedAt().plusSeconds(1);

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_issuedAt3() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = token.getIssuedAt().plusSeconds(1);

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_issuedAt4() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = token.getIssuedAt().minusSeconds(1);

		standardVerification(token, time);
	}

	@Test(expected = MultipleRuleException.class)
	public void token_verification_issuedAt5() {
		Token token = TokenTestVectors.TOKEN_1;
		// -2 seconds, should fail
		OffsetDateTime time = token.getIssuedAt().minusSeconds(2);

		standardVerification(token, time);
	}

	@Test
	public void token_verification_notBefore1() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = token.getNotBefore();

		standardVerification(token, time);
	}

	@Test
	public void token_verification_notBefore2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = token.getNotBefore().plusSeconds(1);

		standardVerification(token, time);
	}

	@Test
	public void token_verification_notBefore3() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = token.getNotBefore().plusSeconds(1);

		standardVerification(token, time);
	}

	@Test
	public void token_verification_notBefore4() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = token.getNotBefore().minusSeconds(1);

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_notBefore5() {
		Token token = TokenTestVectors.TOKEN_1;
		// -2 seconds, should fail
		OffsetDateTime time = token.getNotBefore().minusSeconds(2);

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_notBefore6() {
		Token token = TokenTestVectors.TOKEN_1;
		// issue time, should fail for this token
		OffsetDateTime time = token.getIssuedAt();

		standardVerification(token, time);
	}

	@Test(expected = NotYetValidTokenException.class)
	public void token_verification_notBefore7() {
		Token token = TokenTestVectors.TOKEN_1;
		// issue time - 1 sec, should fail for this token
		OffsetDateTime time = token.getIssuedAt().minusSeconds(1);

		standardVerification(token, time);
	}
}