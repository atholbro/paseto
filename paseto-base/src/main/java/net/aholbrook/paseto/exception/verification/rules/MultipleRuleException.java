package net.aholbrook.paseto.exception.verification.rules;

import net.aholbrook.paseto.Token;

import java.util.LinkedList;
import java.util.List;

public class MultipleRuleException extends RuleException {
	private final List<RuleException> exceptions = new LinkedList<>();

	public MultipleRuleException(Token token) {
		super("Multiple verification errors.", "", token);
	}

	public void add(RuleException e) {
		exceptions.add(e);
	}

	public List<RuleException> getExceptions() {
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

	private static String message(List<RuleException> exceptions) {
		StringBuilder sb = new StringBuilder("Multiple verification errors: ");

		String delim = "";
		for (RuleException re : exceptions) {
			sb.append(delim).append(re.getRuleName()).append(": ").append(re.getMessage());
			delim = "\n";
		}

		return sb.toString();
	}
}
