package net.aholbrook.paseto.verification;

import net.aholbrook.paseto.Token;
import net.aholbrook.paseto.exception.verification.rules.MultipleRuleException;
import net.aholbrook.paseto.exception.verification.rules.RuleException;
import net.aholbrook.paseto.verification.rules.CurrentlyValid;
import net.aholbrook.paseto.verification.rules.IssuedInPast;
import net.aholbrook.paseto.verification.rules.Rule;

public class PasetoVerification {
	public static final Rule[] DEFAULT_RULES = new Rule[] {
			new IssuedInPast(), new CurrentlyValid()
	};

	public static PasetoVerificationContext verify(Token token) {
		return verify(token, DEFAULT_RULES);
	}

	public static PasetoVerificationContext verify(Token token, Rule[] rules) {
		PasetoVerificationContext context = new PasetoVerificationContext(token);
		MultipleRuleException mre = new MultipleRuleException(token);

		for (Rule rule : rules) {
			try {
				rule.check(token, context);
			} catch (RuleException re) {
				mre.add(re);
			}
		}

		mre.throwIfNotEmpty();
		return context;
	}

	public static <_ReturnType> _ReturnType verify(Token token, Runnable<_ReturnType> runnable) {
		PasetoVerificationContext context = verify(token);
		return runnable.run(context);
	}

	public static <_ReturnType> _ReturnType verify(Token token, Rule[] rules, Runnable<_ReturnType> runnable) {
		PasetoVerificationContext context = verify(token, rules);
		return runnable.run(context);
	}

	public interface Runnable<_ReturnType> {
		_ReturnType run(PasetoVerificationContext context);
	}
}
