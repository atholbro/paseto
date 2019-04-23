package net.aholbrook.paseto.test.common;

import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;
import net.aholbrook.paseto.claims.CurrentlyValid;
import net.aholbrook.paseto.claims.ForAudience;
import net.aholbrook.paseto.claims.IssuedBy;
import net.aholbrook.paseto.claims.IssuedInPast;
import net.aholbrook.paseto.claims.VerificationContext;
import net.aholbrook.paseto.claims.WithSubject;
import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.IncorrectAudienceException;
import net.aholbrook.paseto.exception.claims.IncorrectIssuerException;
import net.aholbrook.paseto.exception.claims.IncorrectSubjectException;
import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.exception.claims.MultipleClaimException;
import net.aholbrook.paseto.exception.claims.NotYetValidTokenException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.test.common.data.TokenTestVectors;
import net.aholbrook.paseto.test.common.utils.AssertUtils;
import net.aholbrook.paseto.time.Clock;
import net.aholbrook.paseto.time.OffsetDateTime;
import org.junit.Assert;
import org.junit.Test;

import java.util.Set;

public class ClaimVerificationTest {
	private VerificationContext defaultVerification(Token token) {
		return Claims.verify(token);
	}

	private VerificationContext standardVerification(Token token, OffsetDateTime time) {
		Claim[] claims = new Claim[] {
				new IssuedInPast(time, IssuedInPast.DEFAULT_ALLOWABLE_DRIFT),
				new CurrentlyValid(time, CurrentlyValid.DEFAULT_ALLOWABLE_DRIFT)
		};

		return Claims.verify(token, claims);
	}

	@Test
	public void tokenVerification_default() {
		Token token = new Token()
				.setIssuedAt(OffsetDateTime.now(Clock.systemUTC()).toEpochSecond())
				.setExpiration(OffsetDateTime.now(Clock.systemUTC()).plusSeconds(5).toEpochSecond());
		defaultVerification(token);
	}

	// Check a token for expiry 5 seconds after it becomes valid. This should pass for the given token.
	@Test
	public void tokenVerification_valid() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore()).plusSeconds(5);

		standardVerification(token, time);
	}

	// Check a token for expiry at the exact time it expires. This should pass.
	@Test
	public void tokenVerification_valid_atExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		// check directly at expiry time, should still be considered valid
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getExpiration());

		standardVerification(token, time);
	}

	// Check a token for expiry 1 day after it expires. This should fail and the test should pass with an expected
	// ExpiredTokenException.
	@Test(expected = ExpiredTokenException.class)
	public void tokenVerification_expired_afterExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getExpiration()).plusDays(1);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for expiry 1 second after it expires. This should fail and the test should pass with an expected
	// ExpiredTokenException.
	@Test(expected = ExpiredTokenException.class)
	public void tokenVerification_expired_afterExpiry2() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getExpiration()).plusSeconds(1);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for expiry 1 second before it expires. This should pass.
	@Test
	public void tokenVerification_expired_beforeExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		// check expiry time - 1 second, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getExpiration()).minusSeconds(1);
		standardVerification(token, time);
	}

	// Check a token for expiry which has no expiry time set. This should fail with a thrown MissingClaimException.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_expired_missing() {
		Token token = TokenTestVectors.TOKEN_4;
		AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[] {new CurrentlyValid()}),
				CurrentlyValid.NAME, token, Token.CLAIM_EXPIRATION);
	}

	@Test
	public void tokenVerification_expired_name() {
		Assert.assertEquals("claim name", CurrentlyValid.NAME, new CurrentlyValid().name());
	}

	// Check a token for "issued in the future" at the exact time the token was issued. This should pass.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt());
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for "issued in the future" 1 second after it was issued. This should pass.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt_afterIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt()).plusSeconds(1);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for "issued in the future" 2 seconds after it was issued. This should pass.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt_afterIssued2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt()).plusSeconds(1);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for "issued in the future" 1 second before it was issued. This should pass due to allowable clock
	// drift and throw a NotYetValidTokenException, which is expected. We're testing for the lack of a
	// IssuedInFutureException here.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_issuedAt_beforeIssuedGrace() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt()).minusSeconds(1);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for "issued in the future" 2 seconds before it was issued. This should fail and throw a
	// MultipleClaimException which contains both a IssuedInFutureException and a NotYetValidTokenException.
	@Test(expected = MultipleClaimException.class)
	public void tokenVerification_issuedAt_beforeIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// -2 seconds, should fail
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt()).minusSeconds(2);
		AssertUtils.assertMultiClaimException(() -> standardVerification(token, time),
				new Class[] {IssuedInFutureException.class, NotYetValidTokenException.class});
	}

	// Check a token for "issued in the future" which has no issued time set. This should fail with a thrown
	// MissingClaimException.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_issuedAt_missing() {
		Token token = TokenTestVectors.TOKEN_4;
		AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[] {new IssuedInPast()}),
				IssuedInPast.NAME, token, Token.CLAIM_ISSUED_AT);
	}

	// Check a token for expiry at the exact time it becomes valid. This should pass.
	@Test
	public void tokenVerification_notBefore_atValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore());

		standardVerification(token, time);
	}

	@Test
	public void tokenVerification_issuedAt_name() {
		Assert.assertEquals("claim name", IssuedInPast.NAME, new IssuedInPast().name());
	}

	// Check a token for expiry 1 second after it becomes valid. This should pass.
	@Test
	public void tokenVerification_notBefore_afterValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore()).plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 2 seconds after it becomes valid. This should pass.
	@Test
	public void tokenVerification_notBefore_afterValid2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore()).plusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 1 seconds before it becomes valid (Not Before). This should pass due to the default
	// clock drift allowance and produce a passing test.
	@Test
	public void tokenVerification_notBefore_beforeValidGrace() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore()).minusSeconds(1);

		standardVerification(token, time);
	}

	// Check a token for expiry 2 seconds before it becomes valid (Not Before). This should fail and produce a passing
	// test due to the expected exception.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_notBefore_beforeValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// -2 seconds, should fail
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore()).minusSeconds(2);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for expiry at the exact time it was issued. This should fail and produce a passing test due to the
	// expected exception.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_notBefore_atIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// issue time, should fail for this token
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt());
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check a token for expiry 1 second before it was issued. This should fail and produce a passing test due to the
	// expected exception.
	@Test(expected = NotYetValidTokenException.class)
	public void tokenVerification_notBefore_beforeIssued() {
		Token token = TokenTestVectors.TOKEN_1;
		// issue time - 1 sec, should fail for this token
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getIssuedAt()).minusSeconds(1);
		AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
	}

	// Check for issuer with a match, should pass.
	@Test
	public void tokenVerification_issuer() {
		Token token = TokenTestVectors.TOKEN_1;
		String issuer = TokenTestVectors.TOKEN_1.getIssuer();
		Claims.verify(token, new Claim[] {new IssuedBy(issuer)});
	}

	// Check for issuer with a mismatch, should fail with expected IncorrectIssuerException thrown.
	@Test(expected = IncorrectIssuerException.class)
	public void tokenVerification_issuer_mismatch() {
		Token token = TokenTestVectors.TOKEN_1;
		String issuer = TokenTestVectors.TOKEN_1.getSubject(); // getSubject() on intentional
		AssertUtils.assertClaimException(() -> Claims.verify(token, new Claim[] {new IssuedBy(issuer)}),
				(e) -> {
					Assert.assertEquals(issuer, ((IncorrectIssuerException) e).getExpected());
					Assert.assertEquals(token.getIssuer(), ((IncorrectIssuerException) e).getIssuer());
				},
				IssuedBy.NAME, token);
	}

	// Check issuer on a token without an issuer, should fail with expected MissingClaimException thrown.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_issuer_missing() {
		Token token = TokenTestVectors.TOKEN_3;
		String issuer = TokenTestVectors.TOKEN_2.getIssuer();
		AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[] {new IssuedBy(issuer)}),
				IssuedBy.NAME, token, Token.CLAIM_ISSUER);
	}

	// Make sure the claim name is correct.
	@Test
	public void tokenVerification_issuer_name() {
		Assert.assertEquals("claim name", IssuedBy.NAME, new IssuedBy(null).name());
	}

	// Check for audience with a match, should pass.
	@Test
	public void tokenVerification_audience() {
		Token token = TokenTestVectors.TOKEN_1;
		String audience = TokenTestVectors.TOKEN_1.getAudience();
		Claims.verify(token, new Claim[] {new ForAudience(audience)});
	}

	// Check for audience with a mismatch, should fail with expected IncorrectAudienceException thrown.
	@Test(expected = IncorrectAudienceException.class)
	public void tokenVerification_audience_mismatch() {
		Token token = TokenTestVectors.TOKEN_1;
		String audience = TokenTestVectors.TOKEN_1.getIssuer(); // getIssuer() on intentional
		AssertUtils.assertClaimException(() -> Claims.verify(token, new Claim[] {new ForAudience(audience)}),
				(e) -> {
					Assert.assertEquals(audience, ((IncorrectAudienceException) e).getExpected());
					Assert.assertEquals(token.getAudience(), ((IncorrectAudienceException) e).getAudience());
				},
				ForAudience.NAME, token);
	}

	// Check audience on a token without an audience, should fail with expected MissingClaimException thrown.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_audience_missing() {
		Token token = TokenTestVectors.TOKEN_3;
		String audience = TokenTestVectors.TOKEN_1.getAudience();
		AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[] {new ForAudience(audience)}),
				ForAudience.NAME, token, Token.CLAIM_AUDIENCE);
	}

	// Make sure the claim name is correct.
	@Test
	public void tokenVerification_audience_name() {
		Assert.assertEquals("claim name", ForAudience.NAME, new ForAudience(null).name());
	}

	// Check for subject with a match, should pass.
	@Test
	public void tokenVerification_subject() {
		Token token = TokenTestVectors.TOKEN_1;
		String subject = TokenTestVectors.TOKEN_1.getSubject();
		Claims.verify(token, new Claim[] {new WithSubject(subject)});
	}

	// Check for subject with a mismatch, should fail with expected IncorrectSubjectException thrown.
	@Test(expected = IncorrectSubjectException.class)
	public void tokenVerification_subject_mismatch() {
		Token token = TokenTestVectors.TOKEN_1;
		String subject = TokenTestVectors.TOKEN_1.getAudience(); // getAudience() is intentional

		AssertUtils.assertClaimException(() -> Claims.verify(token, new Claim[] {new WithSubject(subject)}),
				(e) -> {
					Assert.assertEquals(subject, ((IncorrectSubjectException) e).getExpected());
					Assert.assertEquals(token.getSubject(), ((IncorrectSubjectException) e).getSubject());
				},
				WithSubject.NAME, token);
	}

	// Check subject on a token without a subject, should fail with expected MissingClaimException thrown.
	@Test(expected = MissingClaimException.class)
	public void tokenVerification_subject_missing() {
		Token token = TokenTestVectors.TOKEN_3;
		String subject = TokenTestVectors.TOKEN_1.getSubject();
		AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[] {new WithSubject(subject)}),
				WithSubject.NAME, token, Token.CLAIM_SUBJECT);
	}

	// Make sure the claim name is correct.
	@Test
	public void tokenVerification_subject_name() {
		Assert.assertEquals("claim name", WithSubject.NAME, new WithSubject(null).name());
	}

	// Check verification context
	@Test
	public void tokenVerificationContext() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = OffsetDateTime.ofEpochSecond(token.getNotBefore()).plusSeconds(5);

		VerificationContext context = standardVerification(token, time);
		Assert.assertTrue(context.hasClaim(IssuedInPast.NAME));
		Assert.assertTrue(context.hasClaim(CurrentlyValid.NAME));

		Set<String> names = context.getVerifiedClaims();
		Assert.assertTrue(names.contains(IssuedInPast.NAME));
		Assert.assertTrue(names.contains(CurrentlyValid.NAME));

		Assert.assertEquals(token, context.getToken());

		Assert.assertFalse(context.hasClaim(null));
		Assert.assertFalse(context.hasClaim(""));
	}

	// Check message format of MultipleClaimException
	@Test(expected = MultipleClaimException.class)
	public void multipleClaimException_message() {
		Token token = TokenTestVectors.TOKEN_2;
		MultipleClaimException mce = new MultipleClaimException(token);
		mce.add(new IncorrectAudienceException("correct", "wrong", ForAudience.NAME, token));
		mce.add(new IncorrectIssuerException("correct", "wrong", IssuedBy.NAME, token));

		String message = mce.getMessage();

		Assert.assertEquals("Multiple verification errors: FOR_AUDIENCE: Token audience is \"wrong\", "
				+ "required: \"correct\"\nISSUED_BY: Token issued by \"wrong\", required: \"correct\"", message);

		throw mce;
	}
}