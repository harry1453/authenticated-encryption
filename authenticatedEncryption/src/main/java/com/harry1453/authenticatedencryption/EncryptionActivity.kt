package com.harry1453.authenticatedencryption

import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.support.v7.app.AppCompatActivity
import com.harry1453.authenticatedencryption.exception.AuthenticationException
import com.harry1453.authenticatedencryption.exception.EncryptionException
import com.harry1453.authenticatedencryption.exception.NoLockScreenException
import io.reactivex.Single

abstract class EncryptionActivity : AppCompatActivity() {

    lateinit var viewModel: EncryptionActivityViewModel

    private var canEncrypt = true

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        try {
            viewModel = ViewModelProviders.of(this, EncryptionActivityViewModelFactory(this, getAuthenticationConfig())).get(EncryptionActivityViewModel::class.java)
        } catch (e: NoLockScreenException) {
            onNoLockScreenSet()
            canEncrypt = false
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        viewModel.encryptionService.onActivityResult(requestCode, resultCode)
    }

    /**
     * Encrypt the provided message using the key provided by the Android KeyStore.
     *
     * @param message The message to be encrypted
     *
     * @return (From the Single) The decrypted message
     * @throws AuthenticationException (within the single) if the user did not authenticate
     * @throws KeyPermanentlyInvalidatedException (within the single) if the key has been permanently invalidated within the Android KeyStore, such as by fingerprint enrollment
     * @throws EncryptionException (within the single) if the encryption was unsuccessful and the data could not be encrypted.
     */
    protected fun encrypt(message: String): Single<EncryptedData> {
        requireCanEncrypt()
        return viewModel.encryptionService.encrypt(this, message)
    }

    /**
     * Encrypt the provided message using the key provided by the Android KeyStore.
     *
     * @param message The message to be encrypted
     * @param title The title of the activity that prompts for authentication
     * @param description The description of the activity that prompts for authentication
     *
     * @return (From the Single) The decrypted message
     * @throws AuthenticationException (within the single) if the user did not authenticate
     * @throws KeyPermanentlyInvalidatedException (within the single) if the key has been permanently invalidated within the Android KeyStore, such as by fingerprint enrollment
     * @throws EncryptionException (within the single) if the encryption was unsuccessful and the data could not be encrypted.
     */
    protected fun encrypt(message: String, title: String, description: String): Single<EncryptedData> {
        requireCanEncrypt()
        return viewModel.encryptionService.encrypt(this, message, title, description)
    }

    /**
     * Decrypt the provided encrypted message using the key provided by the Android KeyStore.
     *
     * @param encryptedMessage The encrypted message
     *
     * @return (From the Single) The decrypted message
     * @throws AuthenticationException (within the single) if the user did not authenticate
     * @throws KeyPermanentlyInvalidatedException (within the single) if the key has been permanently invalidated within the Android KeyStore, such as by fingerprint enrollment
     * @throws EncryptionException (within the single) if the encryption was unsuccessful and the data could not be encrypted.
     */
    protected fun decrypt(encryptedMessage: EncryptedData): Single<String> {
        requireCanEncrypt()
        return viewModel.encryptionService.decrypt(this, encryptedMessage)
    }

    /**
     * Decrypt the provided encrypted message using the key provided by the Android KeyStore.
     *
     * @param encryptedMessage The encrypted message
     * @param title The title of the activity that prompts for authentication
     * @param description The description of the activity that prompts for authentication
     *
     * @return (From the Single) The decrypted message
     * @throws AuthenticationException (within the single) if the user did not authenticate
     * @throws KeyPermanentlyInvalidatedException (within the single) if the key has been permanently invalidated within the Android KeyStore, such as by fingerprint enrollment
     * @throws EncryptionException (within the single) if the encryption was unsuccessful and the data could not be encrypted.
     */
    protected fun decrypt(encryptedMessage: EncryptedData, title: String, description: String): Single<String> {
        requireCanEncrypt()
        return viewModel.encryptionService.decrypt(this, encryptedMessage, title, description)
    }

    /**
     * Returns whether the Encryption Service was setup correctly and the key was created successfully or existed.
     *
     * This will be false if the user does not have a lock screen set.
     */
    protected fun canEncrypt() = canEncrypt

    private fun requireCanEncrypt() {
        if (!canEncrypt()) throw IllegalArgumentException()
    }

    abstract fun getAuthenticationConfig(): AuthenticationConfig

    /**
     * A callback method to prompt the user that a secure lock screen is required.
     */
    protected open fun onNoLockScreenSet() {}
}