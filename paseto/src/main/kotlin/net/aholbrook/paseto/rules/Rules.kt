package net.aholbrook.paseto.rules

import net.aholbrook.paseto.PasetoDslMarker
import net.aholbrook.paseto.Token
import net.aholbrook.paseto.exception.MultipleValidationExceptions
import net.aholbrook.paseto.exception.PasetoTokenException
import kotlin.contracts.ExperimentalContracts
import kotlin.contracts.InvocationKind
import kotlin.contracts.contract

sealed interface RuleResult
object RuleVerified : RuleResult

@JvmInline
value class RuleFailed(val cause: PasetoTokenException) : RuleResult

sealed interface Rule {
    /**
     * Verify that the given token passes this rule.
     *
     * @param token Token to check.
     * @param currentResults The results of all rules which have run before this rule.
     */
    operator fun invoke(token: Token, mode: Mode, currentResults: Map<Rule, RuleResult>)

    enum class Mode {
        ENCODE,
        DECODE,
    }
}

fun interface CustomRule : Rule

class Rules internal constructor(@PublishedApi internal val rules: List<Rule>) {
    fun verifyAll(token: Token, mode: Rule.Mode): Map<Rule, RuleResult> {
        val context = mutableMapOf<Rule, RuleResult>()
        val mre = MultipleValidationExceptions(token)

        for (rule in rules) {
            try {
                rule(token, mode, context)
                context[rule] = RuleVerified
            } catch (re: PasetoTokenException) {
                mre.add(re)
                context[rule] = RuleFailed(re)
            }
        }

        if (mre.exceptions.isNotEmpty()) {
            throw mre
        }
        return context
    }

    inline fun <reified T> findByTypeOrNull(): T? = rules.find { it::class == T::class } as? T
}

inline fun <reified T> Map<Rule, RuleResult>.findByTypeOrNull(): Pair<Rule, RuleResult>? =
    entries.find { it.key::class == T::class }?.let { it.key to it.value }

@PasetoDslMarker
class RulesBuilder @PublishedApi internal constructor() {
    var forAudience: ForAudience? = null
    var identifiedBy: IdentifiedBy? = null
    var issuedBy: IssuedBy? = null
    var issuedInPast: IssuedInPast? = IssuedInPast()
    var notBefore: NotBefore? = null
    var notExpired: NotExpired? = NotExpired()
    var subject: Subject? = null
    var validAt: ValidAt? = null
    val customRules = mutableListOf<CustomRule>()

    @PublishedApi
    internal fun build(): Rules = Rules(
        listOfNotNull(
            forAudience,
            identifiedBy,
            issuedBy,
            issuedInPast,
            notBefore,
            notExpired,
            subject,
            validAt,
        ) + customRules,
    )

    @PublishedApi
    internal fun copy(rules: Rules) {
        forAudience = rules.findByTypeOrNull()
        identifiedBy = rules.findByTypeOrNull()
        issuedBy = rules.findByTypeOrNull()
        issuedInPast = rules.findByTypeOrNull()
        notBefore = rules.findByTypeOrNull<NotBefore>()
        notExpired = rules.findByTypeOrNull()
        subject = rules.findByTypeOrNull()
        validAt = rules.findByTypeOrNull()
        customRules.addAll(rules.rules.mapNotNull { it as? CustomRule })
    }
}

@OptIn(ExperimentalContracts::class)
inline fun rules(init: RulesBuilder.() -> Unit = { }): Rules {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return RulesBuilder().apply(init).build()
}

@OptIn(ExperimentalContracts::class)
inline fun rules(copyFrom: Rules, init: RulesBuilder.() -> Unit): Rules {
    contract { callsInPlace(init, InvocationKind.EXACTLY_ONCE) }
    return RulesBuilder().apply { copy(copyFrom) }.apply(init).build()
}
