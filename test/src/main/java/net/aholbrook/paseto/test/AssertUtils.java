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

package net.aholbrook.paseto.test;

import org.junit.Assert;

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
		for (int i = 0; i < actual.length; ++i) {
			Assert.assertNotEquals("array index " + Integer.toString(i),
					expected[i],
					actual[i]);
		}
	}
}