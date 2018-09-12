package com.harry1453.authenticatedencryption

import java.util.*

class EncryptedData { // TODO parcelable and serializable
    val encryptedData: ByteArray
    val iv: ByteArray

    constructor(encryptedData: ByteArray, iv: ByteArray) {
        this.encryptedData = encryptedData
        this.iv = iv
    }

    constructor(stringRepresentation: String) {
        val stringTokenizer = StringTokenizer(stringRepresentation, "/")

        if (stringTokenizer.countTokens() != 2) {
            throw IllegalArgumentException()
        }

        this.iv = ByteArrayUtils.hexStringToByteArray(stringTokenizer.nextToken())
        this.encryptedData = ByteArrayUtils.hexStringToByteArray(stringTokenizer.nextToken())
    }

    override fun toString(): String {
        return ByteArrayUtils.toHexString(iv) + "/" + ByteArrayUtils.toHexString(encryptedData)
    }
}