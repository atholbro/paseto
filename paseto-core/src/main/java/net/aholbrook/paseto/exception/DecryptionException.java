package net.aholbrook.paseto.exception;

public class DecryptionException extends PasetoStringException {
	public DecryptionException(String token) {
		super("Failed to decrypt token payload.", token);
	}
}
