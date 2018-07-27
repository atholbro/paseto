package net.aholbrook.paseto.exception;

import net.aholbrook.paseto.util.StringUtils;

public class InvalidHeaderException extends PasetoStringException {
	private final String given, expected;

	public InvalidHeaderException(String given, String expected, String token) {
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
		sb.append("Invalid header in token: \"")
				.append(StringUtils.ntes(given))
				.append("\", expected: \"")
				.append(expected)
				.append("\".");
		return sb.toString();
	}
}
