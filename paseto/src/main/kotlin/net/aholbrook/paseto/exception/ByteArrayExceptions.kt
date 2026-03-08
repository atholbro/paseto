package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi

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

class ByteArrayRangeException @InternalApi constructor(
    val arg: String,
    val len: Int,
    val minBound: Int,
    val maxBound: Int,
    throwable: Throwable? = null,
) : PasetoException("$arg: length outside of range $minBound..$maxBound.", throwable)
