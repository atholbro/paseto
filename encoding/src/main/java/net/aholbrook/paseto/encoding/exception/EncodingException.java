package net.aholbrook.paseto.encoding.exception;

public class EncodingException extends RuntimeException {
	public EncodingException(String msg, Throwable throwable) {
		super(msg, throwable);
	}
}
