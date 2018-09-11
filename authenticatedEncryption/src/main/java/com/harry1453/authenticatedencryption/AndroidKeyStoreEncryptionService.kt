package com.harry1453.authenticatedencryption

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.Base64
import io.reactivex.Single
import io.reactivex.android.schedulers.AndroidSchedulers
import io.reactivex.schedulers.Schedulers
import java.nio.charset.Charset
import java.security.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class AndroidKeyStoreEncryptionService private constructor(private val keyguardManager: KeyguardManager, private val authenticationConfig: AuthenticationConfig) {

    private val authenticateRequestCode = 1001
    private val ivBytes = "encryptionIntVec"

    init {
        try {
            getKey()
        } catch (e: NullPointerException) {
            createKey(authenticationConfig.keyName)
        }
    }

    companion object {
        /**
         * Get an instance of the service
         *
         * @return The encryption service if it could be created, null otherwise.
         * @param activity The activity to use to create the service
         * @param authenticationConfig The configuration to use for the service.
         */
        fun getInstance(activity: Activity, authenticationConfig: AuthenticationConfig) : AndroidKeyStoreEncryptionService? {
            val keyguardManager = activity.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager?
            return if (keyguardManager != null) {
                AndroidKeyStoreEncryptionService(keyguardManager, authenticationConfig)
            } else {
                null
            }
        }
    }

    private var authenticationResultListener: ((Int) -> Unit)? = null

    /**
     * Request permission from the KeyguardManager to use the key
     * stored in the Android KeyStore.
     */
    private fun requestKeyPermission(activity: Activity, title: String, description: String) {
        val intent = keyguardManager.createConfirmDeviceCredentialIntent(title, description)
        if (intent != null) {
            activity.startActivityForResult(intent, authenticateRequestCode)
        }
    }

    /**
     * Encrypt the provided message using the key provided by the Android KeyStore.
     *
     * @param activity The calling Activity
     * @param message The message to be encrypted
     * @param title The title of the authentication activity
     * @param description The description shown in the authentication activity
     *
     * Within the Single:
     * @return The encrypted message
     * @throws UserNotAuthenticatedException if the user did not authenticate
     * @throws KeyPermanentlyInvalidatedException if the key is invalidated
     * @throws IllegalArgumentException if there was an error encrypting the data
     */
    fun encrypt(activity: Activity, message: String, title: String = authenticationConfig.defaultAuthenticationDialogTitle, description: String = authenticationConfig.defaultAuthenticationDialogDescription): Single<String> = Single.create<String> { emitter ->
        authenticationResultListener = { result ->
            if (result == Activity.RESULT_OK) {
                var encryptionResult = ""
                try {
                    encryptionResult = tryEncrypt(message) ?: throw IllegalArgumentException()
                } catch (e: UserNotAuthenticatedException) {
                    emitter.onError(e)
                } catch (e: KeyPermanentlyInvalidatedException) {
                    emitter.onError(e)
                } catch (e: IllegalArgumentException) {
                    emitter.onError(RuntimeException("Could not encrypt data", e))
                }
                if (encryptionResult != "") {
                emitter.onSuccess(encryptionResult)
                }
            } else {
                emitter.onError(UserNotAuthenticatedException("User did not authenticate"))
            }
        }

        requestKeyPermission(activity, title, description)
    }
            .subscribeOn(Schedulers.computation())
            .observeOn(AndroidSchedulers.mainThread())

    /**
     * Decrypt the provided encrypted message using the key provided by the Android KeyStore.
     *
     * @param activity The calling Activity
     * @param encryptedMessage The encrypted message
     * @param title The title of the authentication activity
     * @param description The description shown in the authentication activity
     *
     * Within the Single:
     * @return The decrypted message
     * @throws UserNotAuthenticatedException if the user did not authenticate
     * @throws KeyPermanentlyInvalidatedException if the key is invalidated
     * @throws IllegalArgumentException if there was an error decrypting the data
     */
    fun decrypt(activity: Activity, encryptedMessage: String, title: String = authenticationConfig.defaultAuthenticationDialogTitle, description: String = authenticationConfig.defaultAuthenticationDialogDescription): Single<String> = Single.create<String> { emitter ->
        authenticationResultListener = { result ->
            if (result == Activity.RESULT_OK) {
                var decryptionResult = ""
                try {
                    decryptionResult = tryDecrypt(encryptedMessage) ?: throw IllegalArgumentException()
                } catch (e: UserNotAuthenticatedException) {
                    emitter.onError(e)
                } catch (e: KeyPermanentlyInvalidatedException) {
                    emitter.onError(e)
                } catch (e: IllegalArgumentException) {
                    emitter.onError(RuntimeException("Could not decrypt data", e))
                }
                if (decryptionResult != "") {
                    emitter.onSuccess(decryptionResult)
                }
            } else {
                emitter.onError(IllegalArgumentException("User did not authenticate"))
            }
        }

        requestKeyPermission(activity, title, description)
    }
            .subscribeOn(Schedulers.computation())
            .observeOn(AndroidSchedulers.mainThread())

    /**
     * Method that should be invoked in the Activity's onActivityResult()
     *
     * Provides an entry point for when the authentication activity returns its result.
     */
    fun onActivityResult(requestCode: Int, resultCode: Int) {
        if (requestCode == authenticateRequestCode) {
            if (authenticationResultListener != null) {
                authenticationResultListener!!.invoke(resultCode)
                authenticationResultListener = null // Prevent it from being called twice
            }
        }
    }

    /**
     * Fetches the default key from the Android KeyStore.
     *
     * @return The SecretKey from the KeyStore
     *
     * @throws NullPointerException if the Key does not exist in the KeyStore
     */
    private fun getKey(): SecretKey {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.getKey(authenticationConfig.keyName, null) as SecretKey? ?: throw NullPointerException("Key does not exist")
    }

    private fun getCipher(): Cipher {
        return Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
    }

    private fun getIvParameterSpec(): IvParameterSpec {
        return IvParameterSpec(ivBytes.toByteArray(Charset.defaultCharset()))
    }

    /**
     * Creates the default key in the Android KeyStore.
     *
     * @return true if the key was successfully created, false if there was an error
     */
    private fun createKey(keyName: String): Boolean {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            keyGenerator.init(KeyGenParameterSpec.Builder(keyName, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setUserAuthenticationValidityDurationSeconds(1) // Requires authentication every time
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setRandomizedEncryptionRequired(false) // FIXME
                    .build())
            keyGenerator.generateKey()
            return true
        } catch (e: Throwable) {
            e.printStackTrace()
            return false
        }
    }

    /**
     * Attempts to encrypt the message via the key provided by the Android KeyStore.
     *
     * @param message The message to be encrypted
     *
     * @return The encrypted message if successful, or null if unsuccessful in encrypting the data
     *
     * @throws UserNotAuthenticatedException if the key is specified to require authentication
     *  and the user has not authenticated recently enough as defined when creating the key
     *
     * @throws KeyPermanentlyInvalidatedException if the key has been permanently invalidated by,
     *  for example, changing the device's screen lock or changing the registered fingerprints.
     *
     * @throws NullPointerException if the key has not been created yet.
     */
    private fun tryEncrypt(message: String): String? {
        return try {
            encrypt(message, getKey())
        } catch (e: NullPointerException) {
            // The key does not exist.
            throw NullPointerException()
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Key has been permanently invalidated.
            throw KeyException("Key Invalidated", e)
        } catch (e: UserNotAuthenticatedException) {
            // The user has not authenticated.
            throw UserNotAuthenticatedException()
        } catch (e: Throwable) {
            // All other exceptions mean the encryption failed - return null.
            e.printStackTrace()
            null
        }
    }

    /**
     * Attempts to decrypt the message via the key provided by the Android KeyStore.
     *
     * @param encryptedMessage The encryptedMessage to be decrypted
     *
     * @return The decrypted message if successful, or null if unsuccessful in decrypting the data
     *
     * @throws UserNotAuthenticatedException if the key is specified to require authentication
     *  and the user has not authenticated recently enough as defined when creating the key
     *
     * @throws KeyPermanentlyInvalidatedException if the key has been permanently invalidated by,
     *  for example, changing the device's screen lock or changing the registered fingerprints.
     *
     * @throws NullPointerException if the key has not been created yet.
     */
    private fun tryDecrypt(encryptedMessage: String): String? {
        return try {
            decrypt(encryptedMessage, getKey())
        } catch (e: NullPointerException) {
            // The key does not exist.
            throw NullPointerException()
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Key has been permanently invalidated.
            throw KeyException("Key Invalidated", e)
        } catch (e: UserNotAuthenticatedException) {
            // The user has not authenticated.
            throw UserNotAuthenticatedException()
        } catch (e: Throwable) {
            // All other exceptions mean the decryption failed - return null.
            null
        }
    }

    /**
     * Low level encryption function - encrypts the data using the specified key.
     *
     * Throws many different exceptions depending on the keystore used.
     */
    private fun encrypt(message: String, key: SecretKey): String {
        val cipher = getCipher()
        cipher.init(Cipher.ENCRYPT_MODE, key, getIvParameterSpec())
        return Base64.encodeToString(cipher.doFinal(message.toByteArray()), Base64.DEFAULT)
    }

    /**
     * Low level decryption function - decrypts the data using the specified key.
     *
     * Throws many different exceptions depending on the keystore used.
     */
    private fun decrypt(encrypted: String, key: SecretKey): String {
        val cipher = getCipher()
        cipher.init(Cipher.DECRYPT_MODE, key, getIvParameterSpec())
        return String(cipher.doFinal(Base64.decode(encrypted, Base64.DEFAULT)))
    }
}