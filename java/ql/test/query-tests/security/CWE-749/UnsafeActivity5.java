package com.example.app;

import android.os.Bundle;

import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

public class UnsafeActivity5 extends BaseActivity {
	/*
	 * Test onCreate with both JavaScript and cross-origin resource access enabled while taking
	 * remote user inputs from bundle extras.
	 * 
	 * The Activity is explicitly exported.
	 * 
	 * Note this case of invoking a helper method from a base class that then calls to
	 * `getIntent().getStringExtra(...)` is not yet detected thus is beyond what the query is
	 * capable of.
	 */
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
		wv.loadUrl(thisUrl); // $ MISSING: hasUnsafeAndroidAccess
		thisUrl = getBundleUrl();
		wv.loadUrl(thisUrl); // $ MISSING: hasUnsafeAndroidAccess
	}
}
