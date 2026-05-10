import { createRoot } from "react-dom/client";
import { Capacitor } from "@capacitor/core";
import { SplashScreen } from "@capacitor/splash-screen";
import { StatusBar, Style } from "@capacitor/status-bar";
import { Keyboard, KeyboardResize } from "@capacitor/keyboard";
import App from "./App.tsx";
import "./index.css";

createRoot(document.getElementById("root")!).render(<App />);

// Hide native splash screen after React has rendered
SplashScreen.hide();

// Configure native plugins. Edge-to-edge layout is handled natively
// (Android: WindowCompat.setDecorFitsSystemWindows in MainActivity + transparent
// status/nav bars in styles.xml; iOS: default WKWebView behavior). The
// deprecated setOverlaysWebView / setBackgroundColor APIs (Android 15 SDK 35
// removed Window.setStatusBarColor) are intentionally not called.
if (Capacitor.isNativePlatform()) {
  StatusBar.setStyle({ style: Style.Light });

  Keyboard.setResizeMode({ mode: KeyboardResize.Body });
  Keyboard.setScroll({ isDisabled: false });
}
