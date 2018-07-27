package net.aholbrook.paseto.exception;

public class SignatureVerificationException extends PasetoStringException {
	public SignatureVerificationException(String token) {
		super("Failed to verify token signature.", token);
	}
}
