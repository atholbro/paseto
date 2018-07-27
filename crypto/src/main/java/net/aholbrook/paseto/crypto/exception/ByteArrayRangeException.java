package net.aholbrook.paseto.crypto.exception;

public class ByteArrayRangeException extends CryptoProviderException {
	private final String arg;
	private final int len;
	private final int minBound;
	private final int maxBound;

	public ByteArrayRangeException(String arg, int len, int minBound, int maxBound) {
		this(arg, len, minBound, maxBound, null);
	}

	public ByteArrayRangeException(String arg, int len, int minBound, int maxBound, Throwable throwable) {
		super(message(arg, minBound, maxBound), throwable);
		this.arg = arg;
		this.len = len;
		this.minBound = minBound;
		this.maxBound = maxBound;
	}

	public String getArg() {
		return arg;
	}

	public int getLen() {
		return len;
	}

	public int getMinBound() {
		return minBound;
	}

	public int getMaxBound() {
		return maxBound;
	}

	private static String message(String arg, int minBound, int maxBound) {
		StringBuilder sb = new StringBuilder();
		sb.append(arg)
				.append(": length outside of range ")
				.append(minBound).append("..").append(maxBound)
				.append(".");
		return sb.toString();
	}
}
