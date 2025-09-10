package net.aholbrook.paseto;

import net.aholbrook.paseto.claims.Claim;
import net.aholbrook.paseto.claims.Claims;
import net.aholbrook.paseto.claims.CurrentlyValid;
import net.aholbrook.paseto.claims.ForAudience;
import net.aholbrook.paseto.claims.IssuedBy;
import net.aholbrook.paseto.claims.IssuedInPast;
import net.aholbrook.paseto.claims.VerificationContext;
import net.aholbrook.paseto.claims.WithSubject;
import net.aholbrook.paseto.data.TokenTestVectors;
import net.aholbrook.paseto.exception.claims.ExpiredTokenException;
import net.aholbrook.paseto.exception.claims.IncorrectAudienceException;
import net.aholbrook.paseto.exception.claims.IncorrectIssuerException;
import net.aholbrook.paseto.exception.claims.IncorrectSubjectException;
import net.aholbrook.paseto.exception.claims.IssuedInFutureException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.exception.claims.MultipleClaimException;
import net.aholbrook.paseto.exception.claims.NotYetValidTokenException;
import net.aholbrook.paseto.service.Token;
import net.aholbrook.paseto.utils.AssertUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Set;

@DisplayName("Claim Verifications")
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
	@DisplayName("Default claim verifications work on a current & valid token.")
	public void tokenVerification_default() {
		Token token = new Token()
				.setIssuedAt(OffsetDateTime.now(Clock.systemUTC()).toEpochSecond())
				.setExpiration(OffsetDateTime.now(Clock.systemUTC()).plusSeconds(5).toEpochSecond());
		defaultVerification(token);
	}

	@Test
	@DisplayName("Verify that a token is valid 5 seconds after it becomes valid.")
	public void tokenVerification_valid() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC).plusSeconds(5);

		standardVerification(token, time);
	}

	@Test
	@DisplayName("Verify that a token is valid at the exact time it expires.")
	public void tokenVerification_valid_atExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		// check directly at expiry time, should still be considered valid
		OffsetDateTime time = Instant.ofEpochSecond(token.getExpiration()).atOffset(ZoneOffset.UTC);

		standardVerification(token, time);
	}

	@Test
	@DisplayName("Verify that a token is invalid 1 day after it expires.")
	public void tokenVerification_expired_afterExpiry() {
		Assertions.assertThrows(ExpiredTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			OffsetDateTime time = Instant.ofEpochSecond(token.getExpiration()).atOffset(ZoneOffset.UTC).plusDays(1);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("Verify that a token is invalid 1 second after it expires.")
	public void tokenVerification_expired_afterExpiry2() {
		Assertions.assertThrows(ExpiredTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			OffsetDateTime time = Instant.ofEpochSecond(token.getExpiration()).atOffset(ZoneOffset.UTC).plusSeconds(1);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("Verify that a token is valid 1 second before it expires.")
	public void tokenVerification_expired_beforeExpiry() {
		Token token = TokenTestVectors.TOKEN_1;
		// check expiry time - 1 second, should pass
		OffsetDateTime time = Instant.ofEpochSecond(token.getExpiration()).atOffset(ZoneOffset.UTC).minusSeconds(1);
		standardVerification(token, time);
	}

	@Test
	@DisplayName("Checking a token for expiration when no expiry time is set results in a MissingClaimException.")
	public void tokenVerification_expired_missing() {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_4;
			AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[]{new CurrentlyValid()}),
					CurrentlyValid.NAME, token, Token.CLAIM_EXPIRATION);
		});
	}

	@Test
	@DisplayName("CurrentlyValid claim name is correct.")
	public void tokenVerification_expired_name() {
		Assertions.assertEquals(CurrentlyValid.NAME, new CurrentlyValid().name(), "claim name");
	}

	@Test
	@DisplayName("[issuedAt] verify that a token is valid at the exact time it was issued.")
	public void tokenVerification_issuedAt() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// exactly the time defined in the vector, should pass
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("[issuedAt] verify that a token is valid 1 second after it was issued.")
	public void tokenVerification_issuedAt_afterIssued() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// +1 second, should pass
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC).plusSeconds(1);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("[issuedAt] verify that a token is valid 2 seconds after it was issued.")
	// TODO seems redundant
	public void tokenVerification_issuedAt_afterIssued2() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// +2 seconds, should pass
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC).plusSeconds(1);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("[issuedAt] verify that a token is valid 1 second before it was issued if allowable clock drift is set at 1 second.")
	public void tokenVerification_issuedAt_beforeIssuedGrace() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// -1 second, should pass (due to allowableDrift)
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC).minusSeconds(1);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("[issuedAt] verify that a token is invalid 2 seconds before it was issued if allowable clock drift is set at 1 second.")
	public void tokenVerification_issuedAt_beforeIssued() {
		Assertions.assertThrows(MultipleClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// -2 seconds, should fail
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC).minusSeconds(2);
			AssertUtils.assertMultiClaimException(() -> standardVerification(token, time),
					new Class[]{IssuedInFutureException.class, NotYetValidTokenException.class});
		});
	}

	@Test
	@DisplayName("[issuedAt] checking a token for issued in the future when no issued time is set results in a MissingClaimException.")
	public void tokenVerification_issuedAt_missing() {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_4;
			AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[]{new IssuedInPast()}),
					IssuedInPast.NAME, token, Token.CLAIM_ISSUED_AT);
		});
	}

	@Test
	@DisplayName("[issuedAt] verify that a token is valid at the exact time it expires.")
	public void tokenVerification_notBefore_atValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// exactly the time defined in the vector, should pass
		OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC);

		standardVerification(token, time);
	}

	@Test
	@DisplayName("IssuedInPast claim name is correct.")
	public void tokenVerification_issuedAt_name() {
		Assertions.assertEquals(IssuedInPast.NAME, new IssuedInPast().name(), "claim name");
	}

	@Test
	@DisplayName("[notBefore] verify that a token is valid 1 second after it was issued.")
	public void tokenVerification_notBefore_afterValid() {
		Token token = TokenTestVectors.TOKEN_1;
		// +1 second, should pass
		OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC).plusSeconds(1);

		standardVerification(token, time);
	}

	@Test
	@DisplayName("[notBefore] verify that a token is valid 2 seconds after it was issued.")
	public void tokenVerification_notBefore_afterValid2() {
		Token token = TokenTestVectors.TOKEN_1;
		// +2 seconds, should pass
		OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC).plusSeconds(1);

		standardVerification(token, time);
	}

	@Test
	@DisplayName("[notBefore] verify that a token is valid 1 second before it was issued if allowable clock drift is set at 1 second.")
	public void tokenVerification_notBefore_beforeValidGrace() {
		Token token = TokenTestVectors.TOKEN_1;
		// -1 second, should pass (due to allowableDrift)
		OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC).minusSeconds(1);

		standardVerification(token, time);
	}

	@Test
	@DisplayName("[notBefore] verify that a token is invalid (not before) 2 seconds before it was issued if allowable clock drift is set at 1 second.")
	public void tokenVerification_notBefore_beforeValid() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// -2 seconds, should fail
			OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC).minusSeconds(2);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("[notBefore] verify that a token is invalid at the exact time it was issued.")
	public void tokenVerification_notBefore_atIssued() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// issue time, should fail for this token
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	@Test
	@DisplayName("[notBefore] verify that a token is invalid 1 second before it was issued.")
	public void tokenVerification_notBefore_beforeIssued() {
		Assertions.assertThrows(NotYetValidTokenException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			// issue time - 1 sec, should fail for this token
			OffsetDateTime time = Instant.ofEpochSecond(token.getIssuedAt()).atOffset(ZoneOffset.UTC).minusSeconds(1);
			AssertUtils.assertClaimException(() -> standardVerification(token, time), null, CurrentlyValid.NAME, token);
		});
	}

	// Check for issuer with a match, should pass.
	@Test
	@DisplayName("[issuer] issuer claim validation works with correct data.")
	public void tokenVerification_issuer() {
		Token token = TokenTestVectors.TOKEN_1;
		String issuer = TokenTestVectors.TOKEN_1.getIssuer();
		Claims.verify(token, new Claim[] {new IssuedBy(issuer)});
	}

	@Test
	@DisplayName("[issuer] issuer mismatch results in IncorrectIssuerException.")
	public void tokenVerification_issuer_mismatch() {
		Assertions.assertThrows(IncorrectIssuerException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			String issuer = TokenTestVectors.TOKEN_1.getSubject(); // getSubject() on intentional
			AssertUtils.assertClaimException(() -> Claims.verify(token, new Claim[]{new IssuedBy(issuer)}),
					(e) -> {
						Assertions.assertEquals(issuer, ((IncorrectIssuerException) e).getExpected());
						Assertions.assertEquals(token.getIssuer(), ((IncorrectIssuerException) e).getIssuer());
					},
					IssuedBy.NAME, token);
		});
	}

	@Test
	@DisplayName("[issuer] checking for an issuer on a token without an issuer results in a MissingClaimException.")
	public void tokenVerification_issuer_missing() {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_3;
			String issuer = TokenTestVectors.TOKEN_2.getIssuer();
			AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[]{new IssuedBy(issuer)}),
					IssuedBy.NAME, token, Token.CLAIM_ISSUER);
		});
	}

	@Test
	@DisplayName("IssuedBy claim name is correct.")
	public void tokenVerification_issuer_name() {
		Assertions.assertEquals(IssuedBy.NAME, new IssuedBy(null).name(), "claim name");
	}

	@Test
	@DisplayName("[audience] audience claim validation works with correct data.")
	public void tokenVerification_audience() {
		Token token = TokenTestVectors.TOKEN_1;
		String audience = TokenTestVectors.TOKEN_1.getAudience();
		Claims.verify(token, new Claim[] {new ForAudience(audience)});
	}

	@Test
	@DisplayName("[audience] audience mismatch results in IncorrectAudienceException.")
	public void tokenVerification_audience_mismatch() {
		Assertions.assertThrows(IncorrectAudienceException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			String audience = TokenTestVectors.TOKEN_1.getIssuer(); // getIssuer() on intentional
			AssertUtils.assertClaimException(() -> Claims.verify(token, new Claim[]{new ForAudience(audience)}),
					(e) -> {
						Assertions.assertEquals(audience, ((IncorrectAudienceException) e).getExpected());
						Assertions.assertEquals(token.getAudience(), ((IncorrectAudienceException) e).getAudience());
					},
					ForAudience.NAME, token);
		});
	}

	@Test
	@DisplayName("[audience] checking for an audience on a token without an audience results in a MissingClaimException.")
	public void tokenVerification_audience_missing() {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_3;
			String audience = TokenTestVectors.TOKEN_1.getAudience();
			AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[]{new ForAudience(audience)}),
					ForAudience.NAME, token, Token.CLAIM_AUDIENCE);
		});
	}

	// Make sure the claim name is correct.
	@Test
	@DisplayName("ForAudience claim name is correct.")
	public void tokenVerification_audience_name() {
		Assertions.assertEquals(ForAudience.NAME, new ForAudience(null).name(), "claim name");
	}

	// Check for subject with a match, should pass.
	@Test
	@DisplayName("[subject] subject claim validation works with correct data.")
	public void tokenVerification_subject() {
		Token token = TokenTestVectors.TOKEN_1;
		String subject = TokenTestVectors.TOKEN_1.getSubject();
		Claims.verify(token, new Claim[] {new WithSubject(subject)});
	}

	@Test
	@DisplayName("[subject] subject mismatch results in IncorrectSubjectException.")
	public void tokenVerification_subject_mismatch() {
		Assertions.assertThrows(IncorrectSubjectException.class, () -> {
			Token token = TokenTestVectors.TOKEN_1;
			String subject = TokenTestVectors.TOKEN_1.getAudience(); // getAudience() is intentional

			AssertUtils.assertClaimException(() -> Claims.verify(token, new Claim[]{new WithSubject(subject)}),
					(e) -> {
						Assertions.assertEquals(subject, ((IncorrectSubjectException) e).getExpected());
						Assertions.assertEquals(token.getSubject(), ((IncorrectSubjectException) e).getSubject());
					},
					WithSubject.NAME, token);
		});
	}

	@Test
	@DisplayName("[subject] checking for a subject on a token without a subject results in a MissingClaimException.")
	public void tokenVerification_subject_missing() {
		Assertions.assertThrows(MissingClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_3;
			String subject = TokenTestVectors.TOKEN_1.getSubject();
			AssertUtils.assertMissingClaimException(() -> Claims.verify(token, new Claim[]{new WithSubject(subject)}),
					WithSubject.NAME, token, Token.CLAIM_SUBJECT);
		});
	}

	// Make sure the claim name is correct.
	@Test
	@DisplayName("WithSubject claim name is correct.")
	public void tokenVerification_subject_name() {
		Assertions.assertEquals(WithSubject.NAME, new WithSubject(null).name(), "claim name");
	}

	@Test
	@DisplayName("Token Verification Context")
	public void tokenVerificationContext() {
		Token token = TokenTestVectors.TOKEN_1;
		OffsetDateTime time = Instant.ofEpochSecond(token.getNotBefore()).atOffset(ZoneOffset.UTC).plusSeconds(5);

		VerificationContext context = standardVerification(token, time);
		Assertions.assertTrue(context.hasClaim(IssuedInPast.NAME));
		Assertions.assertTrue(context.hasClaim(CurrentlyValid.NAME));

		Set<String> names = context.getVerifiedClaims();
		Assertions.assertTrue(names.contains(IssuedInPast.NAME));
		Assertions.assertTrue(names.contains(CurrentlyValid.NAME));

		Assertions.assertEquals(token, context.getToken());

		Assertions.assertFalse(context.hasClaim(null));
		Assertions.assertFalse(context.hasClaim(""));
	}

	// Check message format of MultipleClaimException
	@Test
	@DisplayName("Verify that MultipleClaimException message format is correct.")
	public void multipleClaimException_message() {
		Assertions.assertThrows(MultipleClaimException.class, () -> {
			Token token = TokenTestVectors.TOKEN_2;
			MultipleClaimException mce = new MultipleClaimException(token);
			mce.add(new IncorrectAudienceException("correct", "wrong", ForAudience.NAME, token));
			mce.add(new IncorrectIssuerException("correct", "wrong", IssuedBy.NAME, token));

			String message = mce.getMessage();

			Assertions.assertEquals("Multiple verification errors: FOR_AUDIENCE: Token audience is \"wrong\", "
					+ "required: \"correct\"\nISSUED_BY: Token issued by \"wrong\", required: \"correct\"", message);

			throw mce;
		});
	}
}
