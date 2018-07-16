package net.aholbrook.paseto.exception.claims;

import net.aholbrook.paseto.Token;

import java.util.LinkedList;
import java.util.List;

public class MultipleClaimException extends ClaimException {
	private final List<ClaimException> exceptions = new LinkedList<>();

	public MultipleClaimException(Token token) {
		super("Multiple verification errors.", "", token);
	}

	public void add(ClaimException e) {
		exceptions.add(e);
	}

	public List<ClaimException> getExceptions() {
		return exceptions;
	}

	@Override
	public String getMessage() {
		return message(exceptions);
	}

	public void throwIfNotEmpty() {
		if (exceptions.size() == 1) {
			throw exceptions.get(0);
		} else if (exceptions.size() > 1) {
			throw this;
		}
	}

	private static String message(List<ClaimException> exceptions) {
		StringBuilder sb = new StringBuilder("Multiple verification errors: ");

		String delim = "";
		for (ClaimException re : exceptions) {
			sb.append(delim).append(re.getRuleName()).append(": ").append(re.getMessage());
			delim = "\n";
		}

		return sb.toString();
	}
}
