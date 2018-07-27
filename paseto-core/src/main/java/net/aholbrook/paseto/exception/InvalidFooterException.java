package net.aholbrook.paseto.exception;

import net.aholbrook.paseto.util.StringUtils;

public class InvalidFooterException extends PasetoStringException {
	private final String given, expected;

	public InvalidFooterException(String given, String expected, String token) {
		super(message(given, expected), token);
		this.given = given;
		this.expected = expected;
	}

	public String getGiven() {
		return given;
	}

	public String getExpected() {
		return expected;
	}

	public static String message(String given, String expected) {
		StringBuilder sb = new StringBuilder();
		sb.append("Invalid footer in token: \"")
				.append(StringUtils.ntes(given))
				.append("\", expected: \"")
				.append(expected)
				.append("\".");
		return sb.toString();
	}
}
