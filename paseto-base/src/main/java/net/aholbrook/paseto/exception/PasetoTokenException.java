package net.aholbrook.paseto.exception;

import net.aholbrook.paseto.Token;

public class PasetoTokenException extends PasetoException {
	private final Token token;

	public PasetoTokenException(String s, Token token) {
		super(s);
		this.token = token;
	}

	public PasetoTokenException(String s, Token token, Throwable throwable) {
		super(s, throwable);
		this.token = token;
	}


	public Token getToken() {
		return token;
	}
}
