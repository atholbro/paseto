package net.aholbrook.paseto.utils;

import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoParseException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.exception.claims.ClaimException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.exception.claims.MultipleClaimException;
import net.aholbrook.paseto.service.Token;
import org.junit.jupiter.api.Assertions;

import java.util.function.Consumer;

public class AssertUtils {
	public static void assertEquals(byte[] expected, byte[] actual) {
		Assertions.assertNotNull(actual, "result not null");
		Assertions.assertEquals(expected.length, actual.length, "result length");
		for (int i = 0; i < actual.length; ++i) {
			Assertions.assertEquals(expected[i], actual[i], "array index " + i);
		}
	}

	public static void assertEquals(short[] expected, byte[] actual) {
		Assertions.assertNotNull(actual, "result not null");
		Assertions.assertEquals(expected.length, actual.length, "result length");
		for (int i = 0; i < actual.length; ++i) {
			Assertions.assertEquals((byte) expected[i], actual[i], "array index " + i);
		}
	}

	public static void assertNotEquals(byte[] expected, byte[] actual) {
		Assertions.assertNotNull(actual, "result not null");
		Assertions.assertEquals(expected.length, actual.length, "result length");
		boolean match = true;
		for (int i = 0; i < actual.length; ++i) {
			if (expected[i] != actual[i]) {
				match = false;
				break;
			}
		}

		Assertions.assertFalse(match, "arrays match");
	}

	public static void assertByteArrayRangeException(Runnable r, String arg, int len, int lower, int upper) {
		try {
			r.run();
		} catch (ByteArrayRangeException e) {
			Assertions.assertEquals(arg, e.getArg(), "arg");
			Assertions.assertEquals(len, e.getLen(), "len");
			Assertions.assertEquals(lower, e.getMinBound(), "minBound");
			Assertions.assertEquals(upper, e.getMaxBound(), "maxBound");
			throw e;
		}
	}

	public static void assertByteArrayLengthException(Runnable r, String arg, int len, int required,
			boolean exact) {
		try {
			r.run();
		} catch (ByteArrayLengthException e) {
			Assertions.assertEquals(arg, e.getArg());
			Assertions.assertEquals(len, e.getLen());
			Assertions.assertEquals(required, e.getRequired());
			Assertions.assertEquals(exact, e.isExact());
			throw e;
		}
	}

	public static void assertInvalidHeaderException(Runnable r, String given, String expected) {
		try {
			r.run();
		} catch (InvalidHeaderException e) {
			Assertions.assertEquals(given, e.getGiven(), "given");
			Assertions.assertEquals(expected, e.getExpected(), "expected");
			throw e;
		}
	}

	public static void assertInvalidFooterException(Runnable r, String given, String expected) {
		try {
			r.run();
		} catch (InvalidFooterException e) {
			Assertions.assertEquals(given, e.getGiven(), "given");
			Assertions.assertEquals(expected, e.getExpected(), "expected");
			throw e;
		}
	}

	public static void assertPasetoStringException(Runnable r, String token) {
		try {
			r.run();
		} catch (PasetoStringException e) {
			Assertions.assertEquals(token, e.getToken(), "token");
			throw e;
		}
	}

	public static void assertClaimException(Runnable r, Consumer<ClaimException> assertRunner, String rule,
			Token token) {
		try {
			r.run();
		} catch (ClaimException e) {
			if (assertRunner != null) { assertRunner.accept(e); }
			Assertions.assertEquals(rule, e.getRuleName(), "rule name");
			Assertions.assertEquals(token, e.getToken(), "token");
			throw e;
		}
	}

	public static void assertMissingClaimException(Runnable r, String rule, Token token, String claim) {
		try {
			r.run();
		} catch (MissingClaimException e) {
			Assertions.assertEquals(rule, e.getRuleName(), "rule name");
			Assertions.assertEquals(token, e.getToken(), "token");
			Assertions.assertEquals(claim, e.getClaim(), "claim");
			throw e;
		}
	}

	public static void assertMultiClaimException(Runnable r, Class<?>[] classes) {
		try {
			r.run();
		} catch (MultipleClaimException e) {
			Assertions.assertEquals(e.getExceptions().size(), 2, "count");

			for (int i = 0; i < classes.length; ++i) {
				Assertions.assertEquals(e.getExceptions().get(i).getClass(),
						classes[i], "index: " + i);
			}
			throw e;
		}
	}

	public static <_Token> void assertPasetoParseException(Runnable r, _Token token, PasetoParseException.Reason reason,
			int minLength) {
		try {
			r.run();
		} catch (PasetoParseException e) {
			Assertions.assertEquals(token, e.getToken());
			Assertions.assertEquals(reason, e.getReason());
			Assertions.assertEquals(minLength, e.getMinLength());
			throw e;
		}
	}
}
