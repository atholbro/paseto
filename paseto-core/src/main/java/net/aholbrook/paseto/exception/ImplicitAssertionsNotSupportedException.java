package net.aholbrook.paseto.exception;

import net.aholbrook.paseto.Version;

public class ImplicitAssertionsNotSupportedException extends PasetoException {
	public ImplicitAssertionsNotSupportedException(Version actual) {
		super(message(actual));
	}

	private static String message(Version actual) {
		return "Implicit assertions are not support for " + actual.name() + " tokens.";
	}
}
