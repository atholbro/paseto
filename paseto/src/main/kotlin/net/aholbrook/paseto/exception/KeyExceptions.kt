package net.aholbrook.paseto.exception

import net.aholbrook.paseto.InternalApi
import net.aholbrook.paseto.protocol.Version

class KeyLengthException @InternalApi constructor(val actual: Int, val allowed: Array<Int>) :
    PasetoException("Key length $actual is not in the list of allowed key lengths: $allowed.")

class KeyPurposeException @InternalApi constructor(val expected: String, val actual: String) :
    PasetoException("Got wrong Key purpose: $actual given, expected: $expected.")

class KeyVersionException @InternalApi constructor(val expected: Version, val actual: Version) :
    PasetoException("Got wrong Key version: $actual given, expected: $expected.")

class KeyClearedException @InternalApi constructor() :
    PasetoException("Key instance has already been consumed and cleared. Lpad a new key for each operation.")

class KeyPemUnsupportedTypeException @InternalApi constructor(val type: String) :
    PasetoException("Unsupported PEM type: $type")

class KeyV3Exception @InternalApi constructor(msg: String, cause: Throwable? = null) : PasetoException(msg, cause)
