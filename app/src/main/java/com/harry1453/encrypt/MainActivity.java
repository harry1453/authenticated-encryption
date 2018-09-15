package com.harry1453.encrypt;

import android.support.annotation.NonNull;
import android.os.Bundle;
import android.util.Log;

import com.harry1453.authenticatedencryption.AuthenticationConfig;
import com.harry1453.authenticatedencryption.EncryptedData;
import com.harry1453.authenticatedencryption.EncryptionActivity;

public class MainActivity extends EncryptionActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //encrypt("smello").subscribe(result -> Log.e("a", "encrypted: " + result.toString()));
        if (canEncrypt()) {
            decrypt(new EncryptedData("df6388454b929fdb6a0df1e864ea7617/496c462b7361326f344d4577515a4331384c396874673d3d0a")).subscribe(result -> Log.e("a", "decrypted: " + result.toString()));
        }
    }

    @NonNull
    @Override
    public AuthenticationConfig getAuthenticationConfig() {
        return new AuthenticationConfig("secretKey", "Authenticate", "Please authenticate.");
    }

    @Override
    protected void onNoLockScreenSet() {
        Log.e("AE", "No Lockscreen Set");
    }
}
