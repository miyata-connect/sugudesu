// Firebase Configuration
export const firebaseConfig = {
    apiKey: "AIzaSyAgZ02MBSzbicGoBi1Eb4tgRWgtEHeUeP0",
    authDomain: "sugudesu-jp.firebaseapp.com",
    projectId: "sugudesu-jp",
    storageBucket: "sugudesu-jp.firebasestorage.app",
    messagingSenderId: "306434861424",
    appId: "1:306434861424:web:301c48e2cfd8a5681407b5"
};

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

// Google OAuth Configuration (for Google Sheets API)
export const GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com"; // TODO: 実際のClient IDに置き換え
export const GOOGLE_SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets";
export const GOOGLE_OAUTH_REDIRECT_URI = window.location.origin + "/oauth-callback";

// Receipt Scanner Configuration
export const RECEIPT_SPREADSHEET_NAME = "すぐですレシート記録";
export const RECEIPT_SHEET_NAME = "レシート記録";

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
