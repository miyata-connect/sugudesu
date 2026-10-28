// Firebase Proxy Configuration
export const FIREBASE_PROXY_URL = "https://firebase-proxy.miyata-connect-jp.workers.dev";

// Cloudinary Configuration
export const CLOUD_NAME = "dkda2jqxn";
export const UPLOAD_PRESET = "sugudesu_img_only";
export const WORKER_SIGNER_URL = "https://cloudinary-sign.miyata-connect-jp.workers.dev/";

// Firestore Collections
export const LICENSES_COL = "licenses";
export const USERS_COL = "users";
export const PAGES_COL = "pages";

// LocalStorage Keys
export const INSTALL_ID_KEY = "onepage_install_id";

// AI Configuration
export const AI_PROXY_URL = "https://gemini-proxy.miyata-connect-jp.workers.dev/v1beta/models/gemini-1.5-flash:generateContent";
export const AI_TIMEOUT_MS = 20000;

// Global State
export const state = {
    isPro: false,
    generatedUrl: "",
    viewerProDoc: false,
    viewerState: {
        name: "",
        zip: "",
        address: "",
        ssid: "",
        pass: "",
        dayMode: "",
        dayText: ""
    }
};
