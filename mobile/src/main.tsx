import { createRoot } from "react-dom/client";
import { Capacitor } from "@capacitor/core";
import { SplashScreen } from "@capacitor/splash-screen";
import { StatusBar, Style } from "@capacitor/status-bar";
import { Keyboard, KeyboardResize } from "@capacitor/keyboard";
import App from "./App.tsx";
import "./index.css";

createRoot(document.getElementById("root")!).render(<App />);

// Hide the native splash after the first React paint so the login screen is
// visible only once the app is ready.
if (Capacitor.isNativePlatform()) {
  void requestAnimationFrame(() => {
    void SplashScreen.hide({ fadeOutDuration: 250 }).catch(() => {
      // Ignore failures when running in a web preview mode or if the plugin
      // is not yet available.
    });
  });

  StatusBar.setStyle({ style: Style.Light });

  Keyboard.setResizeMode({ mode: KeyboardResize.Body });
  Keyboard.setScroll({ isDisabled: false });
}
