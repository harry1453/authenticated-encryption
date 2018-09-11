package com.harry1453.encrypt;

import android.support.annotation.NonNull;
import android.os.Bundle;

import com.harry1453.authenticatedencryption.AuthenticationConfig;
import com.harry1453.authenticatedencryption.EncryptionActivity;

public class MainActivity extends EncryptionActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
    }

    @NonNull
    @Override
    public AuthenticationConfig getAuthenticationConfig() {
        return new AuthenticationConfig("secretKey", "Authenticate", "Please authenticate.");
    }
}
