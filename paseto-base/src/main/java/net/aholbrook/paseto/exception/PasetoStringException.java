package net.aholbrook.paseto.exception;

public class PasetoStringException extends PasetoException {
	private final String token;

	public PasetoStringException(String s, String token) {
		super(s);
		this.token = token;
	}

	public PasetoStringException(String s, String token, Throwable throwable) {
		super(s, throwable);
		this.token = token;
	}


	public String getToken() {
		return token;
	}
}
