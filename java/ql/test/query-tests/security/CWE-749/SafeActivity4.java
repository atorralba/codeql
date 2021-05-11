package com.example.app;

import android.os.Bundle;

import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class SafeActivity4 extends BaseActivity {
	// Test onCreate with both JavaScript and cross-origin resource access enabled while taking
	// remote user inputs from bundle extras.
	// The Activity is implicitly not exported.
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(-1);

		WebView wv = (WebView) findViewById(-1);
		WebSettings webSettings = wv.getSettings();

		webSettings.setJavaScriptEnabled(true);
		webSettings.setAllowFileAccessFromFileURLs(true);

		wv.setWebViewClient(new WebViewClient() {
			@Override
			public boolean shouldOverrideUrlLoading(WebView view, String url) {
				view.loadUrl(url);
				return true;
			}
		});

		String thisUrl = getIntentUrl();
		wv.loadUrl(thisUrl); // Safe
		thisUrl = getBundleUrl();
		wv.loadUrl(thisUrl); // Safe
	}
}
