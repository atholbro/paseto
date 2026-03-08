package net.aholbrook.paseto.rules

import net.aholbrook.paseto.Token
import net.aholbrook.paseto.crypto.constantTimeEquals
import net.aholbrook.paseto.exception.IncorrectSubjectException
import net.aholbrook.paseto.exception.MissingClaimException

data class Subject(val subject: String) : Rule {
    override operator fun invoke(token: Token, mode: Rule.Mode, currentResults: Map<Rule, RuleResult>) {
        if (token.subject.isNullOrEmpty()) {
            throw MissingClaimException("sub", token)
        }

        if (!token.subject.constantTimeEquals(subject)) {
            throw IncorrectSubjectException(subject, token.subject, token)
        }
    }
}
