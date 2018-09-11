package com.harry1453.encryptionutils

import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProvider

class EncryptionActivityViewModelFactory(private val activity: EncryptionActivity, private val authenticationConfig: AuthenticationConfig): ViewModelProvider.Factory {
    override fun <T : ViewModel?> create(modelClass: Class<T>): T {
        return EncryptionActivityViewModel(AndroidKeyStoreEncryptionService.getInstance(activity, authenticationConfig) ?: throw IllegalArgumentException()) as T
    }
}