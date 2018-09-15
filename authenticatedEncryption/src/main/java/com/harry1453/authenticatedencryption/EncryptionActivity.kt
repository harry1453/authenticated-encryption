package com.harry1453.authenticatedencryption

import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
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

    protected fun encrypt(message: String): Single<EncryptedData> {
        requireCanEncrypt()
        return viewModel.encryptionService.encrypt(this, message)
    }

    protected fun encrypt(message: String, title: String, description: String): Single<EncryptedData> {
        requireCanEncrypt()
        return viewModel.encryptionService.encrypt(this, message, title, description)
    }

    protected fun decrypt(encryptedMessage: EncryptedData): Single<String> {
        requireCanEncrypt()
        return viewModel.encryptionService.decrypt(this, encryptedMessage)
    }

    protected fun decrypt(encryptedMessage: EncryptedData, title: String, description: String): Single<String> {
        requireCanEncrypt()
        return viewModel.encryptionService.decrypt(this, encryptedMessage, title, description)
    }

    protected fun canEncrypt() = canEncrypt

    private fun requireCanEncrypt() {
        if (!canEncrypt()) throw IllegalArgumentException()
    }

    abstract fun getAuthenticationConfig(): AuthenticationConfig

    protected open fun onNoLockScreenSet() {}
}