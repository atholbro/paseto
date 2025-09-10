package net.aholbrook.paseto.exception;

public class KeyLengthException extends PasetoException {
	private final int expected;
	private final int actual;

	public KeyLengthException(int expected, int actual) {
		super(message(expected, actual));

		this.expected = expected;
		this.actual = actual;
	}

	public int getExpected() {
		return expected;
	}

	public int getActual() {
		return actual;
	}

	private static String message(int expected, int actual) {
		return "Got wrong Key version: " + actual + " given, expected: " + expected + ".";
	}
}
