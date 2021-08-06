package net.aholbrook.paseto.exception;

import net.aholbrook.paseto.Version;

public class KeyVersionException extends PasetoException {
	private final Version expected;
	private final Version actual;

	public KeyVersionException(Version expected, Version actual) {
		super(message(expected, actual));

		this.expected = expected;
		this.actual = actual;
	}

	public Version getExpected() {
		return expected;
	}

	public Version getActual() {
		return actual;
	}

	private static String message(Version expected, Version actual) {
		return "Got wrong Key version: " + actual + " given, expected: " + expected + ".";
	}
}
