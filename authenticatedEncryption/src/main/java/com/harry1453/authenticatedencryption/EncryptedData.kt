package com.harry1453.authenticatedencryption

import android.os.Parcel
import android.os.Parcelable
import java.util.*

class EncryptedData : Parcelable {

    val encryptedData: ByteArray
    val iv: ByteArray

    constructor(encryptedData: ByteArray, iv: ByteArray) {
        this.encryptedData = encryptedData
        this.iv = iv
    }

    constructor(stringRepresentation: String) {
        val stringTokenizer = StringTokenizer(stringRepresentation, "/")

        if (stringTokenizer.countTokens() != 2) {
            throw IllegalArgumentException("String representation of EncryptedData invalid.")
        }

        this.iv = ByteArrayUtils.hexStringToByteArray(stringTokenizer.nextToken())
        this.encryptedData = ByteArrayUtils.hexStringToByteArray(stringTokenizer.nextToken())
    }

    override fun toString() = ByteArrayUtils.toHexString(iv) + "/" + ByteArrayUtils.toHexString(encryptedData)

    override fun equals(other: Any?) = Objects.equals(this.toString(), other.toString())

    override fun writeToParcel(dest: Parcel, flags: Int) {
        dest.writeString(this.toString())
    }

    override fun describeContents() = 0

    companion object CREATOR : Parcelable.Creator<EncryptedData> {
        override fun createFromParcel(parcel: Parcel) = EncryptedData(parcel.readString())

        override fun newArray(size: Int): Array<EncryptedData?> = arrayOfNulls(size)
    }
}