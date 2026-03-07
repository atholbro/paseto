package net.aholbrook.paseto.crypto

import net.aholbrook.paseto.protocol.Purpose
import net.aholbrook.paseto.protocol.key.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.key.KeyPair
import net.aholbrook.paseto.protocol.key.SymmetricKey

fun AsymmetricSecretKey.copy() =
    AsymmetricSecretKey.ofRawBytes(getKeyMaterialFor(version, Purpose.PUBLIC).copyOf(), version)
fun SymmetricKey.copy() = SymmetricKey.ofRawBytes(getKeyMaterialFor(version, Purpose.LOCAL).copyOf(), version)
fun KeyPair.copy() = KeyPair(secretKey?.copy(), publicKey)
