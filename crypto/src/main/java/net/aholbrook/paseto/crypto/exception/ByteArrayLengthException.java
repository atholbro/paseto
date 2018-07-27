package net.aholbrook.paseto.crypto.exception;

public class ByteArrayLengthException extends CryptoProviderException {
	private final String arg;
	private final int len;
	private final int required;
	private final boolean exact;

	public ByteArrayLengthException(String arg, int len, int required) {
		this(arg, len, required, true, null);
	}

	public ByteArrayLengthException(String arg, int len, int required, boolean exact) {
		this(arg, len, required, exact, null);
	}

	public ByteArrayLengthException(String arg, int len, int required, boolean exact, Throwable cause) {
		super(message(arg, len, required, exact), cause);
		this.arg = arg;
		this.len = len;
		this.required = required;
		this.exact = exact;
	}

	public String getArg() {
		return arg;
	}

	public int getLen() {
		return len;
	}

	public int getRequired() {
		return required;
	}

	public boolean isExact() {
		return exact;
	}

	private static String message(String arg, int len, int required, boolean exact) {
		StringBuilder sb = new StringBuilder();
		sb.append(arg)
				.append(": ")
				.append(required)
				.append(exact ? " exact " : " ")
				.append("bytes required, given ")
				.append(len)
				.append(" bytes .");
		return sb.toString();
	}
}
