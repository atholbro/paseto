package net.aholbrook.paseto.protocol.key

import org.bouncycastle.util.io.pem.PemObject
import org.bouncycastle.util.io.pem.PemReader
import org.bouncycastle.util.io.pem.PemWriter
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.io.StringWriter

internal fun pemEncode(type: String, content: ByteArray): String = StringWriter().also { sw ->
    PemWriter(sw).use { pw ->
        pw.writeObject(PemObject(type, content))
    }
}.toString()

internal fun pemDecode(pem: ByteArray): Pair<String, ByteArray> {
    val obj = PemReader(InputStreamReader(ByteArrayInputStream(pem))).use { reader ->
        reader.readPemObject()
    }
    return Pair(obj.type, obj.content)
}
