package net.aholbrook.paseto.vectorgen

import com.github.ajalt.clikt.core.CliktCommand
import com.github.ajalt.clikt.core.main
import com.github.ajalt.clikt.parameters.arguments.argument
import com.github.ajalt.clikt.parameters.options.option
import com.github.ajalt.clikt.parameters.types.enum
import com.github.ajalt.clikt.parameters.types.file
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.encodeToStream
import net.aholbrook.paseto.Purpose
import net.aholbrook.paseto.ServiceTestVector
import net.aholbrook.paseto.ServiceTestVectors
import net.aholbrook.paseto.crypto.copy
import net.aholbrook.paseto.crypto.withTestNonce
import net.aholbrook.paseto.protocol.AsymmetricPublicKey
import net.aholbrook.paseto.protocol.AsymmetricSecretKey
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.SymmetricKey
import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.rules.rules
import net.aholbrook.paseto.tokenFromVector
import net.aholbrook.paseto.tokenService
import org.bouncycastle.util.encoders.Hex
import java.security.SecureRandom

private val json = Json {
    prettyPrint = true
    explicitNulls = false
    ignoreUnknownKeys = false
}

private val rng = SecureRandom()

fun main(args: Array<String>) = GenerateCommand()
    .main(args)

class GenerateCommand : CliktCommand(name = "vector-gen") {
    val pasetoVersion by option("-p", "--paseto-version", help = "Output PASETO version")
        .enum<Version>()

    val input by argument(help = "Input vectors")
        .file(mustExist = true, canBeDir = false)
    val output by argument(help = "Output vectors file")
        .file(canBeDir = false)

    @OptIn(ExperimentalSerializationApi::class)
    override fun run() {
        val key = SymmetricKey.generate(Version.V4).toHex()
        println("new key: $key")

        val inputVectors = input.inputStream().use {
            json.decodeFromStream<ServiceTestVectors>(it)
        }
        val inputVersion = Version.valueOf(inputVectors.version.uppercase())

        val regenerateMap = mutableMapOf<String, String>()
        val publicRekeyMap = mutableMapOf<String, KeyPair>()

        val outputVectors = inputVectors.tests.mapNotNull { vector ->
            when (vector.mode) {
                "local" -> convertLocalVector(vector, inputVersion, pasetoVersion, regenerateMap)
                "public" -> convertPublicVector(vector, inputVersion, pasetoVersion, publicRekeyMap)
                else -> null
            }
        }
        val outputObject = ServiceTestVectors(
            name = inputVectors.name.replace(
                oldValue = inputVersion.toString(),
                newValue = (pasetoVersion ?: inputVersion).toString()
            ),
            version = (pasetoVersion ?: inputVersion).toString(),
            tests = outputVectors
        )

        if (!output.exists()) {
            output.createNewFile()
        }

        json.encodeToStream(ServiceTestVectors.serializer(), outputObject,output.outputStream())
        //println(json.encodeToString(ServiceTestVectors.serializer(), outputObject))
    }

    private fun convertLocalVector(
        vector: ServiceTestVector,
        inputVersion: Version,
        pasetoVersion: Version?,
        regenerateMap: MutableMap<String, String>
    ): ServiceTestVector? {
        if (vector.key == null) { return null }

        val key = if (pasetoVersion != null && inputVersion != pasetoVersion) {
            SymmetricKey.ofHex(
                regenerateMap.getOrPut(vector.key!!) { SymmetricKey.generate(pasetoVersion).toHex() },
                pasetoVersion
            )
        } else {
            SymmetricKey.ofHex(vector.key!!, inputVersion)
        }
        val nonce = if (pasetoVersion != null && inputVersion != pasetoVersion) {
            Hex.decode(
                regenerateMap.getOrPut(vector.nonce!!) {
                    val nonce = when (pasetoVersion) {
                        Version.V1 -> ByteArray(32)
                        Version.V2 -> ByteArray(24)
                        Version.V3 -> ByteArray(32)
                        Version.V4 -> ByteArray(32)
                    }
                    rng.nextBytes(nonce)
                    Hex.toHexString(nonce)
                }
            )
        } else {
            Hex.decode(vector.nonce!!)
        }

        val token = tokenFromVector(vector)
        val encoded = withTestNonce(nonce) {
            val service = tokenService(pasetoVersion ?: inputVersion, Purpose.Local { key.copy() }) {
                rules = rules {
                    issuedInPast = null
                    notExpired = null
                }
            }
            val encoded = service.encode(token)
            service.decode(encoded)
            encoded
        }

        return vector.copy(
            name = vector.name.replace(inputVersion.toString(), (pasetoVersion ?: inputVersion).toString()),
            nonce = Hex.toHexString(nonce),
            key = key.toHex(),
            token = encoded,
        )
    }

    private fun convertPublicVector(
        vector: ServiceTestVector,
        inputVersion: Version,
        pasetoVersion: Version?,
        rekeyMap: MutableMap<String, KeyPair>
    ): ServiceTestVector? {
        if (vector.secretKey == null || vector.publicKey == null) { return null }

        val keyPair = if (pasetoVersion != null && inputVersion != pasetoVersion) {
            rekeyMap.getOrPut(vector.secretKey + vector.publicKey) {
                KeyPair.generate(pasetoVersion)
            }
        } else {
            if (inputVersion == Version.V1) {
                KeyPair(
                    secretKey = AsymmetricSecretKey.ofPem(vector.secretKey!!, inputVersion),
                    publicKey = AsymmetricPublicKey.ofPem(vector.publicKey!!, inputVersion),
                )
            } else {
                KeyPair(
                    secretKey = AsymmetricSecretKey.ofHex(vector.secretKey!!, inputVersion),
                    publicKey = AsymmetricPublicKey.ofHex(vector.publicKey!!, inputVersion),
                )
            }
        }

        val token = tokenFromVector(vector)
        val encoded = withTestNonce(vector.nonce?.toByteArray()) {
            val service = tokenService(pasetoVersion ?: inputVersion, Purpose.Public { keyPair.copy() }) {
                rules = rules {
                    issuedInPast = null
                    notExpired = null
                }
            }
            service.encode(token)
        }

        return vector.copy(
            name = vector.name.replace(inputVersion.toString(), (pasetoVersion ?: inputVersion).toString()),
            secretKey = if (pasetoVersion == Version.V1) {
                keyPair.secretKey!!.toPem()
            } else {
                keyPair.secretKey!!.toHex()
            },
            publicKey = if (pasetoVersion == Version.V1) {
                keyPair.publicKey.toPem()
            } else {
                keyPair.publicKey.toHex()
            },
            token = encoded,
        )
    }
}


