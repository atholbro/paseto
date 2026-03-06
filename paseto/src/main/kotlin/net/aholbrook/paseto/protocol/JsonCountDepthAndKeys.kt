package net.aholbrook.paseto.protocol

internal fun jsonCountDepthAndKeys(json: String): Pair<Int, Int> {
    var depth = 0
    var maxDepth = 0
    var keys = 0
    var inString = false
    var i = 0

    while (i < json.length) {
        val c = json[i]

        if (inString) {
            when (c) {
                '\\' -> ++i
                '"' -> inString = false
            }
        } else {
            when (c) {
                '"' -> inString = true

                '{', '[' -> {
                    if (++depth > maxDepth) {
                        maxDepth = depth
                    }
                }

                '}', ']' -> {
                    if (--depth < 0) {
                        maxDepth = -1
                        keys = -1
                        break
                    }
                }

                ':' -> {
                    ++keys
                }
            }
        }

        ++i
    }

    return Pair(maxDepth, keys)
}
