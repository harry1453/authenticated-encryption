package com.harry1453.authenticatedencryption

import android.os.Parcel
import android.os.Parcelable
import java.util.*

class EncryptedData : Parcelable {

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(this.toString())
    }

    override fun describeContents() = 0

    val encryptedData: ByteArray
    val iv: ByteArray

    constructor(parcel: Parcel) : this(parcel.readString())

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

    override fun toString() = ByteArrayUtils.toHexString(iv) + "/" + ByteArrayUtils.toHexString(encryptedData)

    companion object CREATOR : Parcelable.Creator<EncryptedData> {
        override fun createFromParcel(parcel: Parcel): EncryptedData {
            return EncryptedData(parcel)
        }

        override fun newArray(size: Int): Array<EncryptedData?> {
            return arrayOfNulls(size)
        }
    }
}