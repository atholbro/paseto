package net.aholbrook.paseto.test;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.encoding.base.EncodingProvider;
import net.aholbrook.paseto.exception.verification.rules.ExpiredTokenException;
import net.aholbrook.paseto.exception.verification.rules.IncorrectAudienceException;
import net.aholbrook.paseto.exception.verification.rules.IncorrectIssuerException;
import net.aholbrook.paseto.exception.verification.rules.IncorrectSubjectException;
import net.aholbrook.paseto.exception.verification.rules.IssuedInFutureException;
import net.aholbrook.paseto.exception.verification.rules.MissingClaimException;
import net.aholbrook.paseto.exception.verification.rules.MultipleRuleException;
import net.aholbrook.paseto.exception.verification.rules.NotYetValidTokenException;
import net.aholbrook.paseto.test.data.TokenTestVectors;
import net.aholbrook.paseto.verification.PasetoVerification;
import net.aholbrook.paseto.verification.rules.CurrentlyValid;
import net.aholbrook.paseto.verification.rules.ForAudience;
import net.aholbrook.paseto.verification.rules.IssuedBy;
import net.aholbrook.paseto.verification.rules.IssuedInPast;
import net.aholbrook.paseto.verification.rules.Rule;
import net.aholbrook.paseto.verification.rules.WithSubject;
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

	// Check a token for expiry 5 seconds after it becomes valid. This should pass for the given token.
	@Test
	public void tokenVerification_valid() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getNotBefore().plusSeconds(5);

		standardVerification(token, time);
	}

	// Check a token for expiry at the exact time it expires. This should pass.
	@Test
	public void tokenVerification_valid_atExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		// check directly at expiry time, should still be considered valid
		OffsetDateTime time = token.getExpiration();

		standardVerification(token, time);
	}

	// Check a token for expiry 1 day after it expires. This should fail and the test should pass with an expected
	// ExpiredTokenException.
	@Test(expected = ExpiredTokenException.class)
	public void tokenVerification_expired_afterExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = token.getExpiration().plusDays(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 1 second after it expires. This should fail and the test should pass with an expected
	// ExpiredTokenException.
	@Test(expected = ExpiredTokenException.class)
	public void tokenVerification_expired_afterExpiry2() {
		Token token = TokenTestVectors.TOKEN_1;
		// check 1 second after expiry time, should be invalid
		OffsetDateTime time = token.getExpiration().plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 1 second before it expires. This should pass.
	@Test
	public void tokenVerification_expired_beforeExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		// check expiry time - 1 second, should pass
		OffsetDateTime time = token.getExpiration().minusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry which has no expiry time set. This should fail with a thrown MissingClaimException.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_expired_missing() {
		Token token = TokenTestVectors.TOKEN_4;
		PasetoVerification.verify(token, new Rule[] { new CurrentlyValid()});
	}

	// Check a token for "issued in the future" at the exact time the token was issued. This should pass.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = token.getIssuedAt();

		standardVerification(token, time);
	}

	// Check a token for "issued in the future" 1 second after it was issued. This should pass.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt_afterIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = token.getIssuedAt().plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for "issued in the future" 2 seconds after it was issued. This should pass.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt_afterIssued2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = token.getIssuedAt().plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for "issued in the future" 1 second before it was issued. This should pass due to allowable clock
	// drift and throw a NotYetValidTokenException, which is expected. We're testing for the lack of a
	// IssuedInFutureException here.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt_beforeIssuedGrace() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = token.getIssuedAt().minusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for "issued in the future" 2 seconds before it was issued. This should fail and throw a
	// MultipleRuleException which contains both a IssuedInFutureException and a NotYetValidTokenException.
	@Test
	public void tokenVerification_issuedAt_beforeIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// -2 seconds, should fail
		OffsetDateTime time = token.getIssuedAt().minusSeconds(2);

		try {
			standardVerification(token, time);
		} catch (MultipleRuleException mre) {
			Assert.assertEquals(mre.getExceptions().size(), 2);
			Assert.assertEquals(mre.getExceptions().get(0).getClass(), IssuedInFutureException.class);
			Assert.assertEquals(mre.getExceptions().get(1).getClass(), NotYetValidTokenException.class);
			return;
		}

		Assert.fail("Required MultipleRuleException not thrown.");
	}

	// Check a token for "issued in the future" which has no issued time set. This should fail with a thrown
	// MissingClaimException.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_issuedAt_missing() {
		Token token = TokenTestVectors.TOKEN_4;
		PasetoVerification.verify(token, new Rule[] { new CurrentlyValid()});
	}

	// Check a token for expiry at the exact time it becomes valid. This should pass.
	@Test
	public void tokenVerification_notBefore_atValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = token.getNotBefore();

		standardVerification(token, time);
	}

	// Check a token for expiry 1 second after it becomes valid. This should pass.
	@Test
	public void tokenVerification_notBefore_afterValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = token.getNotBefore().plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 2 seconds after it becomes valid. This should pass.
	@Test
	public void tokenVerification_notBefore_afterValid2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = token.getNotBefore().plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 1 seconds before it becomes valid (Not Before). This should pass due to the default
	// clock drift allowance and produce a passing test.
	@Test
	public void tokenVerification_notBefore_beforeValidGrace() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = token.getNotBefore().minusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 2 seconds before it becomes valid (Not Before). This should fail and produce a passing
	// test due to the expected exception.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_notBefore_beforeValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// -2 seconds, should fail
		OffsetDateTime time = token.getNotBefore().minusSeconds(2);

		standardVerification(token, time);
	}

	// Check a token for expiry at the exact time it was issued. This should fail and produce a passing test due to the
	// expected exception.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_notBefore_atIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// issue time, should fail for this token
		OffsetDateTime time = token.getIssuedAt();

		standardVerification(token, time);
	}

	// Check a token for expiry 1 second before it was issued. This should fail and produce a passing test due to the
	// expected exception.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_notBefore_beforeIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// issue time - 1 sec, should fail for this token
		OffsetDateTime time = token.getIssuedAt().minusSeconds(1);

		standardVerification(token, time);
	}

	// Check for issuer with a match, should pass.
	@Test
	public void tokenVerification_issuer() {
		Token token = TokenTestVectors.TOKEN_1;
		String issuer = TokenTestVectors.TOKEN_1.getIssuer();
		PasetoVerification.verify(token, new Rule[] { new IssuedBy(issuer)});
	}

	// Check for issuer with a mismatch, should fail with expected IncorrectIssuerException thrown.
	@Test(expected = IncorrectIssuerException.class)
	public void tokenVerification_issuer_mismatch() {
		Token token = TokenTestVectors.TOKEN_1;
		// wrong issuer, should fail
		String issuer = TokenTestVectors.TOKEN_1.getSubject(); // getSubject() on intentional
		PasetoVerification.verify(token, new Rule[] { new IssuedBy(issuer)});
	}

	// Check issuer on a token without an issuer, should fail with expected MissingClaimException thrown.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_issuer_missing() {
		Token token = TokenTestVectors.TOKEN_3;
		String issuer = TokenTestVectors.TOKEN_2.getIssuer();
		PasetoVerification.verify(token, new Rule[] { new IssuedBy(issuer)});
	}

	// Check for audience with a match, should pass.
	@Test
	public void tokenVerification_audience() {
		Token token = TokenTestVectors.TOKEN_1;
		String audience = TokenTestVectors.TOKEN_1.getAudience();
		PasetoVerification.verify(token, new Rule[] { new ForAudience(audience)});
	}

	// Check for audience with a mismatch, should fail with expected IncorrectAudienceException thrown.
	@Test(expected = IncorrectAudienceException.class)
	public void tokenVerification_audience_mismatch() {
		Token token = TokenTestVectors.TOKEN_1;
		// wrong audience, should fail
		String audience = TokenTestVectors.TOKEN_1.getIssuer(); // getIssuer() on intentional
		PasetoVerification.verify(token, new Rule[] { new ForAudience(audience)});
	}

	// Check audience on a token without an audience, should fail with expected MissingClaimException thrown.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_audience_missing() {
		Token token = TokenTestVectors.TOKEN_3;
		String audience = TokenTestVectors.TOKEN_1.getAudience();
		PasetoVerification.verify(token, new Rule[] { new IssuedBy(audience)});
	}

	// Check for subject with a match, should pass.
	@Test
	public void tokenVerification_subject() {
		Token token = TokenTestVectors.TOKEN_1;
		String subject = TokenTestVectors.TOKEN_1.getSubject();
		PasetoVerification.verify(token, new Rule[] { new WithSubject(subject)});
	}

	// Check for subject with a mismatch, should fail with expected IncorrectSubjectException thrown.
	@Test(expected = IncorrectSubjectException.class)
	public void tokenVerification_subject_mismatch() {
		Token token = TokenTestVectors.TOKEN_1;
		// wrong subject, should fail
		String subject = TokenTestVectors.TOKEN_1.getAudience(); // getAudience() is intentional
		PasetoVerification.verify(token, new Rule[] { new WithSubject(subject)});
	}

	// Check subject on a token without a subject, should fail with expected MissingClaimException thrown.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_subject_missing() {
		Token token = TokenTestVectors.TOKEN_3;
		String subject = TokenTestVectors.TOKEN_1.getSubject();
		PasetoVerification.verify(token, new Rule[] { new WithSubject(subject)});
	}
}