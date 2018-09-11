package com.harry1453.authenticatedencryption

import android.arch.lifecycle.ViewModelProviders
import android.content.Intent
import android.os.Bundle
import android.support.v7.app.AppCompatActivity
import io.reactivex.Single

abstract class EncryptionActivity : AppCompatActivity() {
    lateinit var viewModel: EncryptionActivityViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        viewModel = ViewModelProviders.of(this, EncryptionActivityViewModelFactory(this, getAuthenticationConfig())).get(EncryptionActivityViewModel::class.java)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        viewModel.encryptionService.onActivityResult(requestCode, resultCode)
    }

    protected fun encrypt(message: String): Single<String> {
        return viewModel.encryptionService.encrypt(this, message)
    }

    protected fun encrypt(message: String, title: String, description: String): Single<String> {
        return viewModel.encryptionService.encrypt(this, message, title, description)
    }

    protected fun decrypt(encryptedMessage: String): Single<String> {
        return viewModel.encryptionService.decrypt(this, encryptedMessage)
    }

    protected fun decrypt(encryptedMessage: String, title: String, description: String): Single<String> {
        return viewModel.encryptionService.decrypt(this, encryptedMessage, title, description)
    }

    abstract fun getAuthenticationConfig(): AuthenticationConfig
}