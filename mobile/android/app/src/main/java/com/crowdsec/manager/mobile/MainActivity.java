package com.crowdsec.manager.mobile;

import android.os.Bundle;
import android.webkit.WebSettings;
import com.getcapacitor.BridgeActivity;

public class MainActivity extends BridgeActivity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        // Allow ws:// WebSocket connections from the https://localhost WebView context.
        // Required because androidScheme:'https' causes the WebView to run at
        // https://localhost, which would otherwise block insecure ws:// connections.
        getBridge().getWebView().getSettings()
                .setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
    }
}
