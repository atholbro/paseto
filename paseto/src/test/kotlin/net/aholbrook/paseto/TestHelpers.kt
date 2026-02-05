package net.aholbrook.paseto

import net.aholbrook.paseto.crypto.copy
import net.aholbrook.paseto.protocol.KeyPair
import net.aholbrook.paseto.protocol.SymmetricKey
import net.aholbrook.paseto.protocol.Version
import java.io.File

private val keyV1Local_ by lazy { SymmetricKey.generate(Version.V1) }
private val keyV1Public_ by lazy { KeyPair.generate(Version.V1) }
private val keyV2Local_ by lazy { SymmetricKey.generate(Version.V2) }
private val keyV2Public_ by lazy { KeyPair.generate(Version.V2) }
private val keyV4Local_ by lazy { SymmetricKey.generate(Version.V4) }
private val keyV4Public_ by lazy { KeyPair.generate(Version.V4) }

val keyV1Local: SymmetricKey get() = keyV1Local_.copy()
val keyV1Public: KeyPair get() = keyV1Public_.copy()
val keyV2Local: SymmetricKey get() = keyV2Local_.copy()
val keyV2Public: KeyPair get() = keyV2Public_.copy()
val keyV4Local: SymmetricKey get() = keyV4Local_.copy()
val keyV4Public: KeyPair get() = keyV4Public_.copy()

object TestFiles {
    fun p12ResourcePath(name: String): String {
        val stream = TestFiles::class.java.getResourceAsStream("/p12/$name")
            ?: error("Unable to find /p12/$name in test resources")
        val temp = File.createTempFile(name.removeSuffix(".p12"), ".p12")
        temp.deleteOnExit()

        stream.use { input ->
            temp.outputStream().use { output ->
                input.copyTo(output)
            }
        }

        return temp.path
    }
}
