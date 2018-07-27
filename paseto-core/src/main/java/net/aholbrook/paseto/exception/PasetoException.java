package net.aholbrook.paseto.exception;

public class PasetoException extends RuntimeException {
	public PasetoException(String s) {
		super(s);
	}

	public PasetoException(String s, Throwable throwable) {
		super(s, throwable);
	}
}
