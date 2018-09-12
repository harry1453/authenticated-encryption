package com.harry1453.authenticatedencryption

import java.io.UnsupportedEncodingException

class ByteArrayUtils {
    companion object {
        private val hexChars = charArrayOf('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')

        fun toHexString(bytes: ByteArray?): String? {
            if (bytes == null) {
                return null
            }
            val chars = CharArray(bytes.size * 2)
            for (i in bytes.indices) {
                chars[i * 2] = hexChars[bytes[i].toInt() shr 4 and 0xF]
                chars[i * 2 + 1] = hexChars[bytes[i].toInt() and 0xF]
            }
            return String(chars)
        }

        fun hexStringToByteArray(string: String): ByteArray {
            val len = string.length
            val data = ByteArray(len / 2)
            var i = 0
            while (i < len) {
                data[i / 2] = ((Character.digit(string[i], 16) shl 4) + Character.digit(string[i + 1], 16)).toByte()
                i += 2
            }
            return data
        }
    }
}