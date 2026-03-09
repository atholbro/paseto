package net.aholbrook.paseto

import net.aholbrook.paseto.protocol.Version
import net.aholbrook.paseto.protocol.key.KeyPair
import net.aholbrook.paseto.protocol.key.SymmetricKey
import java.io.InputStream

val keyV1Local by lazy { SymmetricKey.generate(Version.V1) }
val keyV1Public by lazy { KeyPair.generate(Version.V1) }
val keyV2Local by lazy { SymmetricKey.generate(Version.V2) }
val keyV2Public by lazy { KeyPair.generate(Version.V2) }
val keyV3Local by lazy { SymmetricKey.generate(Version.V3) }
val keyV3Public by lazy { KeyPair.generate(Version.V3) }
val keyV4Local by lazy { SymmetricKey.generate(Version.V4) }
val keyV4Public by lazy { KeyPair.generate(Version.V4) }

object TestFiles {
    fun p12ResourceStream(name: String): InputStream = TestFiles::class.java.getResourceAsStream("/p12/$name")
        ?: error("Unable to find /p12/$name in test resources")
}
