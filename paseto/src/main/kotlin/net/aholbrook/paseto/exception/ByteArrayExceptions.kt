package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi

/**
 * Thrown when a byte array has invalid exact/expected length.
 *
 * @property arg Argument name associated with failure.
 * @property len Provided byte array length.
 * @property required Required length.
 * @property isExact Whether [required] is exact (`true`) or minimum (`false`).
 * @param cause Optional source exception.
 */
class ByteArrayLengthException @InternalApi constructor(
    val arg: String,
    val len: Int,
    val required: Int,
    val isExact: Boolean = true,
    cause: Throwable? = null,
) : PasetoException(
    "$arg: $required ${if (isExact) "exact " else ""}bytes required, given $len bytes.",
    cause,
)

/**
 * Thrown when a byte array length is outside an inclusive range.
 *
 * @property arg Argument name associated with failure.
 * @property len Provided byte array length.
 * @property minBound Inclusive lower bound.
 * @property maxBound Inclusive upper bound.
 * @param throwable Optional source exception.
 */
class ByteArrayRangeException @InternalApi constructor(
    val arg: String,
    val len: Int,
    val minBound: Int,
    val maxBound: Int,
    throwable: Throwable? = null,
) : PasetoException("$arg: length outside of range $minBound..$maxBound.", throwable)
