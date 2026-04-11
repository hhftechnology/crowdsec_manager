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

// Configure native plugins for edge-to-edge display
if (Capacitor.isNativePlatform()) {
  StatusBar.setOverlaysWebView({ overlay: true });
  StatusBar.setStyle({ style: Style.Light });
  StatusBar.setBackgroundColor({ color: '#00000000' });

  Keyboard.setResizeMode({ mode: KeyboardResize.Body });
  Keyboard.setScroll({ isDisabled: false });
}
