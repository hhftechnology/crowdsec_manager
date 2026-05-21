import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "com.crowdsec.manager.mobile",
  appName: "CrowdSec Manager",
  webDir: "dist",
  server: {
    cleartext: true,
    androidScheme: "http",
    iosScheme: "http",
    hostname: "localhost",
  },
  plugins: {
    CapacitorHttp: {
      enabled: true,
    },
    SplashScreen: {
      launchAutoHide: true,
      backgroundColor: "#faf9f5",
      splashFullScreen: true,
      androidSplashResourceName: "splash",
      androidScaleType: "CENTER_CROP",
    },
    StatusBar: {
      style: "LIGHT",
    },
    Keyboard: {
      resize: "body",
      resizeOnFullScreen: true,
    },
  },
};

export default config;
