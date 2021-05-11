package com.example.app;

import android.app.Activity;

public abstract class BaseActivity extends Activity {

    protected String getIntentUrl() {
        return getIntent().getStringExtra("url");
    }

    protected String getBundleUrl() {
        return getIntent().getExtras().getString("url");
    }
}
