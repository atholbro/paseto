/*
Copyright 2018 Andrew Holbrook

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit
persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

package net.aholbrook.paseto.test.utils;

import net.aholbrook.paseto.crypto.exception.ByteArrayLengthException;
import net.aholbrook.paseto.crypto.exception.ByteArrayRangeException;
import net.aholbrook.paseto.exception.InvalidFooterException;
import net.aholbrook.paseto.exception.InvalidHeaderException;
import net.aholbrook.paseto.exception.PasetoStringException;
import net.aholbrook.paseto.exception.claims.ClaimException;
import net.aholbrook.paseto.exception.claims.MissingClaimException;
import net.aholbrook.paseto.exception.claims.MultipleClaimException;
import net.aholbrook.paseto.service.Token;
import org.junit.Assert;

import java.util.function.Consumer;

public class AssertUtils {
	public static void assertEquals(byte[] expected, byte[] actual) {
		Assert.assertNotNull("result not null", actual);
		Assert.assertEquals("result length", expected.length, actual.length);
		for (int i = 0; i < actual.length; ++i) {
			Assert.assertEquals("array index " + Integer.toString(i),
					expected[i],
					actual[i]);
		}
	}

	public static void assertEquals(short[] expected, byte[] actual) {
		Assert.assertNotNull("result not null", actual);
		Assert.assertEquals("result length", expected.length, actual.length);
		for (int i = 0; i < actual.length; ++i) {
			Assert.assertEquals("array index " + Integer.toString(i),
					(byte) expected[i],
					actual[i]);
		}
	}

	public static void assertNotEquals(byte[] expected, byte[] actual) {
		Assert.assertNotNull("result not null", actual);
		Assert.assertEquals("result length", expected.length, actual.length);
		boolean match = true;
		for (int i = 0; i < actual.length; ++i) {
			if (expected[i] != actual[i]) {
				match = false;
			}
		}

		Assert.assertFalse("arrays match", match);
	}

	public static void assertByteArrayRangeException(Runnable r, String arg, int len, int lower, int upper) {
		try {
			r.run();
		} catch (ByteArrayRangeException e) {
			Assert.assertEquals("arg", arg, e.getArg());
			Assert.assertEquals("len", len, e.getLen());
			Assert.assertEquals("minBound", lower, e.getMinBound());
			Assert.assertEquals("maxBound", upper, e.getMaxBound());
			throw e;
		}
	}

	public static void assertByteArrayLengthException(Runnable r, String arg, int len, int required,
			boolean exact) {
		try {
			r.run();
		} catch (ByteArrayLengthException e) {
			Assert.assertEquals(arg, e.getArg());
			Assert.assertEquals(len, e.getLen());
			Assert.assertEquals(required, e.getRequired());
			Assert.assertEquals(exact, e.isExact());
			throw e;
		}
	}

	public static void assertInvalidHeaderException(Runnable r, String given, String expected) {
		try {
			r.run();
		} catch (InvalidHeaderException e) {
			Assert.assertEquals("given", given, e.getGiven());
			Assert.assertEquals("expected", expected, e.getExpected());
			throw e;
		}
	}

	public static void assertInvalidFooterException(Runnable r, String given, String expected) {
		try {
			r.run();
		} catch (InvalidFooterException e) {
			Assert.assertEquals("given", given, e.getGiven());
			Assert.assertEquals("expected", expected, e.getExpected());
			throw e;
		}
	}

	public static void assertPasetoStringException(Runnable r, String token) {
		try {
			r.run();
		} catch (PasetoStringException e) {
			Assert.assertEquals("token", token, e.getToken());
			throw e;
		}
	}

	public static void assertClaimException(Runnable r, Consumer<ClaimException> assertRunner, String rule,
			Token token) {
		try {
			r.run();
		} catch (ClaimException e) {
			if (assertRunner != null) { assertRunner.accept(e); }
			Assert.assertEquals("rule name", rule, e.getRuleName());
			Assert.assertEquals("token", token, e.getToken());
			throw e;
		}
	}

	public static void assertMissingClaimException(Runnable r, String rule, Token token, String claim) {
		try {
			r.run();
		} catch (MissingClaimException e) {
			Assert.assertEquals("rule name", rule, e.getRuleName());
			Assert.assertEquals("token", token, e.getToken());
			Assert.assertEquals("claim", claim, e.getClaim());
			throw e;
		}
	}

	public static void assertMultiClaimException(Runnable r, Class[] classes) {
		try {
			r.run();
		} catch (MultipleClaimException e) {
			Assert.assertEquals("count", e.getExceptions().size(), 2);

			for (int i = 0; i < classes.length; ++i) {
				Assert.assertEquals("index: " + Integer.toString(i),
						e.getExceptions().get(i).getClass(), classes[i]);
			}
			throw e;
		}
	}
}
