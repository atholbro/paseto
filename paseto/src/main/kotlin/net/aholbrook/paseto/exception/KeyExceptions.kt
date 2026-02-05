package net.aholbrook.paseto.exception

import net.aholbrook.paseto.protocol.Version

class KeyLengthException(val actual: Int, val allowed: Array<Int>) :
    PasetoException("Key length $actual is not in the list of allowed key lengths: $allowed.")

class KeyPurposeException(val expected: String, val actual: String) :
    PasetoException("Got wrong Key purpose: $actual given, expected: $expected.")

class KeyVersionException(val expected: Version, val actual: Version) :
    PasetoException("Got wrong Key version: $actual given, expected: $expected.")

class KeyPemUnsupportedTypeException(val type: String) :
    PasetoException("Unsupported PEM type: $type")

class KeyV3Exception(msg: String, cause: Throwable? = null) : PasetoException(msg, cause)
