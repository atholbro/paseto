package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.protocol.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.SymmetricKey

fun AsymmetricSecretKey.copy() =
    AsymmetricSecretKey.ofRawBytes(getKeyMaterialFor(version, Purpose.PUBLIC).copyOf(), version)
fun SymmetricKey.copy() = SymmetricKey.ofRawBytes(getKeyMaterialFor(version, Purpose.LOCAL).copyOf(), version)
fun KeyPair.copy() = KeyPair(secretKey?.copy(), publicKey)
