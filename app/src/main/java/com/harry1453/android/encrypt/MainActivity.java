package com.harry1453.android.encrypt;

import android.support.annotation.NonNull;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.harry1453.encryptionutils.AuthenticationConfig;
import com.harry1453.encryptionutils.EncryptionActivity;

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
