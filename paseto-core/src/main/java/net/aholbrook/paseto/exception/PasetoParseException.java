package net.aholbrook.paseto.exception;

public class PasetoParseException extends PasetoStringException {
	private final Reason reason;
	private int minLength = 0;

	public PasetoParseException(Reason reason, String token) {
		super(message(reason, token), token);
		this.reason = reason;
	}

	public Reason getReason() {
		return reason;
	}

	public int getMinLength() {
		return minLength;
	}

	public PasetoParseException setMinLength(int minLength) {
		this.minLength = minLength;
		return this;
	}

	public enum Reason {
		MISSING_SECTIONS,
		PAYLOAD_LENGTH
	}

	public static String message(Reason reason, String token) {
		StringBuilder sb = new StringBuilder();

		switch (reason) {
			case MISSING_SECTIONS:
				sb.append("Invalid token: \"")
						.append(token)
						.append("\" unable to locate 3-4 paseto sections.");
				break;

			case PAYLOAD_LENGTH:
				sb.append("Invalid token: \"")
						.append(token)
						.append("\" payload section does not meet minimum length requirements.");
				break;
		}

		return sb.toString();
	}
}
