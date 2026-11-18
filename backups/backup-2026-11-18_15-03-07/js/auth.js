import { initializeApp } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-app.js";
import {
    getAuth,
    onAuthStateChanged,
    GoogleAuthProvider,
    OAuthProvider,
    signInWithRedirect,
    getRedirectResult,
    signOut,
    signInWithCustomToken,
    createUserWithEmailAndPassword,
    signInWithEmailAndPassword,
    RecaptchaVerifier,
    signInWithPhoneNumber
} from "https://www.gstatic.com/firebasejs/10.7.0/firebase-auth.js";
import {
    getFirestore,
    doc,
    getDoc,
    runTransaction,
    serverTimestamp
} from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";

import { firebaseConfig, LICENSES_COL, USERS_COL, state } from './config.js';
import { getOrCreateInstallId } from './utils.js';

// ==================== FIREBASE INITIALIZATION ====================
const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

// ==================== STATE ====================
let phoneConfirmationResult = null;
let recaptchaVerifier = null;
let emailIsSignUp = false;

console.log("=== Firebase Initialized ===");
console.log("Domain:", window.location.hostname);
console.log("Auth Domain:", firebaseConfig.authDomain);

// ==================== UI HELPERS ====================
const ui = {
    uid: () => document.getElementById("my-uid"),
    loginGoogleBtn: () => document.getElementById("google-login-btn"),
    loginAppleBtn: () => document.getElementById("apple-login-btn"),
    loginLineBtn: () => document.getElementById("line-login-btn"),
    loginEmailBtn: () => document.getElementById("email-login-btn"),
    loginPhoneBtn: () => document.getElementById("phone-login-btn"),
    logoutBtn: () => document.getElementById("logout-btn"),
    authLog: () => document.getElementById("auth-log")
};

function setAuthUiLoggedOut() {
    document.getElementById("sticky-header-title").textContent = "ログインしてください";
    document.getElementById("sticky-header-uid").style.display = "none";

    ui.loginGoogleBtn().style.display = "inline-block";
    ui.loginAppleBtn().style.display = "inline-block";
    ui.loginLineBtn().style.display = "inline-block";
    ui.loginEmailBtn().style.display = "inline-block";
    ui.loginPhoneBtn().style.display = "inline-block";
    ui.logoutBtn().style.display = "none";

    ui.authLog().textContent = "";
    
    document.getElementById("login-welcome-screen").style.display = "flex";
    document.getElementById("sticky-header").style.display = "none";
    document.getElementById("creator-mode").style.display = "none";
    document.getElementById("viewer-mode").style.display = "none";
}

function setAuthUiLoggedIn(user) {
    console.log("✅ User logged in:", user.uid);
    document.getElementById("sticky-header-title").textContent = "ログイン中";
    document.getElementById("sticky-header-uid").style.display = "block";
    ui.uid().textContent = user.uid.substring(0, 6) + "...";

    ui.loginGoogleBtn().style.display = "none";
    ui.loginAppleBtn().style.display = "none";
    ui.loginLineBtn().style.display = "none";
    ui.loginEmailBtn().style.display = "none";
    ui.loginPhoneBtn().style.display = "none";
    ui.logoutBtn().style.display = "inline-block";

    ui.authLog().textContent = "ログイン成功";
    ui.authLog().style.color = "#88ff88";
    
    document.getElementById("login-welcome-screen").style.display = "none";
    document.getElementById("sticky-header").style.display = "block";
    document.getElementById("creator-mode").style.display = "block";
}

// ==================== LOGIN FUNCTIONS ====================
window.googleLogin = async function() {
    console.log("=== Google Login Started ===");
    ui.authLog().textContent = "Googleへ移動中...";
    ui.authLog().style.color = "#88ccff";

    try {
        const provider = new GoogleAuthProvider();
        await signInWithRedirect(auth, provider);
    } catch (error) {
        console.error("❌ Google login error:", error);
        ui.authLog().textContent = "エラー: " + error.code;
        ui.authLog().style.color = "#ff8888";
    }
};

window.appleLogin = async function() {
    console.log("=== Apple Login Started ===");
    ui.authLog().textContent = "Appleへ移動中...";
    ui.authLog().style.color = "#88ccff";

    try {
        const provider = new OAuthProvider("apple.com");
        provider.addScope("email");
        provider.addScope("name");
        await signInWithRedirect(auth, provider);
    } catch (error) {
        console.error("❌ Apple login error:", error);
        ui.authLog().textContent = "エラー: " + error.code;
        ui.authLog().style.color = "#ff8888";
    }
};

window.lineLogin = async function() {
    console.log("=== LINE Login Started (OIDC) ===");
    ui.authLog().textContent = "LINEへ移動中...";
    ui.authLog().style.color = "#88ccff";

    try {
        const provider = new OAuthProvider("oidc.line");
        provider.addScope("profile");
        provider.addScope("openid");
        provider.addScope("email");
        
        console.log("LINE provider configured:", provider.providerId);
        await signInWithRedirect(auth, provider);
    } catch (error) {
        console.error("❌ LINE login error:", error);
        ui.authLog().textContent = "エラー: " + error.code;
        ui.authLog().style.color = "#ff8888";
    }
};

// ==================== EMAIL AUTH ====================
window.openEmailModal = function() {
    document.getElementById("email-modal").classList.add("show");
    document.getElementById("email-error").textContent = "";
    document.getElementById("email-input").value = "";
    document.getElementById("password-input").value = "";
    emailIsSignUp = false;
    updateEmailModalMode();
};

window.closeEmailModal = function() {
    document.getElementById("email-modal").classList.remove("show");
};

window.toggleEmailMode = function() {
    emailIsSignUp = !emailIsSignUp;
    updateEmailModalMode();
};

function updateEmailModalMode() {
    const title = document.getElementById("email-modal-title");
    const btn = document.getElementById("email-submit-btn");
    const toggleText = document.getElementById("email-toggle-text");
    const toggleLink = document.getElementById("email-toggle-link");

    if (emailIsSignUp) {
        title.textContent = "新規登録";
        btn.textContent = "登録";
        toggleText.textContent = "既にアカウントをお持ちの方は";
        toggleLink.textContent = "ログイン";
    } else {
        title.textContent = "メールでログイン";
        btn.textContent = "ログイン";
        toggleText.textContent = "アカウントをお持ちでない方は";
        toggleLink.textContent = "新規登録";
    }
}

window.submitEmail = async function() {
    const email = document.getElementById("email-input").value.trim();
    const password = document.getElementById("password-input").value;
    const errorEl = document.getElementById("email-error");

    if (!email || !password) {
        errorEl.textContent = "メールアドレスとパスワードを入力してください";
        return;
    }

    if (password.length < 6) {
        errorEl.textContent = "パスワードは6文字以上で入力してください";
        return;
    }

    errorEl.textContent = "";

    try {
        if (emailIsSignUp) {
            await createUserWithEmailAndPassword(auth, email, password);
            console.log("✅ Email signup successful");
        } else {
            await signInWithEmailAndPassword(auth, email, password);
            console.log("✅ Email login successful");
        }
        closeEmailModal();
    } catch (error) {
        console.error("❌ Email auth error:", error);
        let msg = "エラーが発生しました";
        if (error.code === "auth/email-already-in-use") msg = "このメールアドレスは既に使用されています";
        else if (error.code === "auth/invalid-email") msg = "メールアドレスの形式が正しくありません";
        else if (error.code === "auth/weak-password") msg = "パスワードが弱すぎます";
        else if (error.code === "auth/user-not-found") msg = "ユーザーが見つかりません";
        else if (error.code === "auth/wrong-password") msg = "パスワードが間違っています";
        else if (error.code === "auth/invalid-credential") msg = "メールアドレスまたはパスワードが間違っています";
        errorEl.textContent = msg;
    }
};

// ==================== PHONE AUTH ====================
window.openPhoneModal = function() {
    document.getElementById("phone-modal").classList.add("show");
    document.getElementById("phone-error").textContent = "";
    document.getElementById("phone-number-input").value = "";
    document.getElementById("sms-code-input").value = "";
    resetPhoneModal();
    setupRecaptcha();
};

window.closePhoneModal = function() {
    document.getElementById("phone-modal").classList.remove("show");
    if (recaptchaVerifier) {
        recaptchaVerifier.clear();
        recaptchaVerifier = null;
    }
};

window.resetPhoneModal = function() {
    document.getElementById("phone-step1").classList.add("active");
    document.getElementById("phone-step2").classList.remove("active");
    document.getElementById("phone-error").textContent = "";
    phoneConfirmationResult = null;
};

function setupRecaptcha() {
    if (recaptchaVerifier) {
        recaptchaVerifier.clear();
    }
    const container = document.getElementById("recaptcha-container");
    container.innerHTML = "";

    recaptchaVerifier = new RecaptchaVerifier(auth, container, {
        size: "normal",
        callback: () => {
            console.log("✅ reCAPTCHA solved");
        },
        "expired-callback": () => {
            console.log("⚠️ reCAPTCHA expired");
            document.getElementById("phone-error").textContent = "reCAPTCHAが期限切れです。再試行してください。";
        }
    });

    recaptchaVerifier.render().catch(err => {
        console.error("❌ reCAPTCHA render error:", err);
        document.getElementById("phone-error").textContent = "reCAPTCHAの読み込みに失敗しました";
    });
}

window.sendSmsCode = async function() {
    const phoneInput = document.getElementById("phone-number-input").value.trim();
    const errorEl = document.getElementById("phone-error");

    if (!phoneInput) {
        errorEl.textContent = "電話番号を入力してください";
        return;
    }

    let phoneNumber = phoneInput.replace(/[-\s]/g, "");
    if (phoneNumber.startsWith("0")) {
        phoneNumber = "+81" + phoneNumber.substring(1);
    } else if (!phoneNumber.startsWith("+")) {
        phoneNumber = "+81" + phoneNumber;
    }

    console.log("📱 Sending SMS to:", phoneNumber);

    errorEl.textContent = "";
    document.getElementById("phone-send-btn").disabled = true;
    document.getElementById("phone-send-btn").textContent = "送信中...";

    try {
        phoneConfirmationResult = await signInWithPhoneNumber(auth, phoneNumber, recaptchaVerifier);
        console.log("✅ SMS sent successfully");

        document.getElementById("phone-step1").classList.remove("active");
        document.getElementById("phone-step2").classList.add("active");
    } catch (error) {
        console.error("❌ SMS send error:", error);
        let msg = "SMSの送信に失敗しました";
        if (error.code === "auth/invalid-phone-number") msg = "電話番号の形式が正しくありません";
        else if (error.code === "auth/too-many-requests") msg = "リクエストが多すぎます。しばらくしてから再試行してください";
        errorEl.textContent = msg;
        setupRecaptcha();
    } finally {
        document.getElementById("phone-send-btn").disabled = false;
        document.getElementById("phone-send-btn").textContent = "認証コードを送信";
    }
};

window.verifySmsCode = async function() {
    const code = document.getElementById("sms-code-input").value.trim();
    const errorEl = document.getElementById("phone-error");

    if (!code) {
        errorEl.textContent = "認証コードを入力してください";
        return;
    }

    if (!phoneConfirmationResult) {
        errorEl.textContent = "認証プロセスに問題が発生しました。最初からやり直してください。";
        return;
    }

    errorEl.textContent = "";

    try {
        await phoneConfirmationResult.confirm(code);
        console.log("✅ Phone auth successful");
        closePhoneModal();
    } catch (error) {
        console.error("❌ Code verification error:", error);
        let msg = "認証コードが正しくありません";
        if (error.code === "auth/code-expired") msg = "認証コードの有効期限が切れました";
        errorEl.textContent = msg;
    }
};

// ==================== LOGOUT ====================
window.doLogout = async function() {
    console.log("=== Logout Started ===");
    try {
        await signOut(auth);
        console.log("✅ Sign out successful");
        setAuthUiLoggedOut();
    } catch (error) {
        console.error("❌ Logout error:", error);
        alert("ログアウトに失敗しました: " + error.message);
    }
};

// ==================== CUSTOM TOKEN ====================
async function trySignInWithCustomTokenFromUrl() {
    const params = new URLSearchParams(window.location.search);
    const token = params.get("firebaseCustomToken");
    if (!token) {
        console.log("ℹ️ No custom token in URL");
        return false;
    }

    console.log("🔑 Custom token found in URL");

    try {
        await signInWithCustomToken(auth, token);
        console.log("✅ Custom token sign-in successful");
        
        params.delete("firebaseCustomToken");
        const clean = `${window.location.pathname}${params.toString() ? "?" + params.toString() : ""}${window.location.hash || ""}`;
        window.history.replaceState({}, "", clean);
        
        return true;
    } catch (e) {
        console.error("❌ Custom token sign-in failed", e);
        ui.authLog().textContent = "外部ログイン失敗: " + e.code;
        ui.authLog().style.color = "#ff8888";
        return false;
    }
}

// ==================== ENTITLEMENT ====================
async function checkEntitlement(uid) {
    const userRef = doc(db, USERS_COL, uid);
    try {
        const snap = await getDoc(userRef);
        if (snap.exists() && snap.data().plan === "pro") {
            console.log("✅ Pro user detected");
            unlockProUI();
            await touchDeviceIfPro(uid, snap.data().licenseId);
        } else {
            console.log("ℹ️ Free user");
        }
    } catch (e) {
        console.error("❌ Entitlement check failed", e);
    }
}

async function touchDeviceIfPro(uid, licenseId) {
    if (!licenseId) return;

    const installId = getOrCreateInstallId();
    const licenseRef = doc(db, LICENSES_COL, licenseId);

    try {
        await runTransaction(db, async (tx) => {
            const licSnap = await tx.get(licenseRef);
            if (!licSnap.exists()) return;

            const lic = licSnap.data() || {};
            if (lic.claimedByUid && lic.claimedByUid !== uid) return;

            const devices = lic.devices || {};
            if (devices[installId]) {
                tx.update(licenseRef, {
                    [`devices.${installId}.lastSeenAt`]: serverTimestamp()
                });
            }
        });
    } catch (e) {
        console.error("❌ touchDevice failed", e);
    }
}

function unlockProUI() {
    state.isPro = true;
    document.getElementById('pro-feature-img').style.display = 'block';
    document.getElementById('pro-feature-slug').style.display = 'block';
    document.getElementById('pro-feature-ssid').style.display = 'block';

    ui.authLog().textContent = "Pro Active ✨";
    ui.authLog().style.color = "#ffd700";
}

// ==================== AUTH STATE LISTENER ====================
export async function initializeAuthListeners() {
    const hasCustomToken = await trySignInWithCustomTokenFromUrl();
    
    if (!hasCustomToken) {
        try {
            console.log("⏳ Checking redirect result...");
            const result = await getRedirectResult(auth);
            if (result && result.user) {
                console.log("✅ Redirect login successful:", result.user.uid);
                setAuthUiLoggedIn(result.user);
                await checkEntitlement(result.user.uid);
                
                const cleanUrl = window.location.pathname + window.location.hash;
                window.history.replaceState({}, "", cleanUrl);
            } else {
                console.log("ℹ️ No redirect result");
            }
        } catch (error) {
            console.error("❌ Redirect result error:", error.code, error.message);
            ui.authLog().textContent = "ログインエラー: " + error.code;
            ui.authLog().style.color = "#ff8888";
            
            const cleanUrl = window.location.pathname + window.location.hash;
            window.history.replaceState({}, "", cleanUrl);
        }
    }

    onAuthStateChanged(auth, async (user) => {
        console.log("=== onAuthStateChanged ===", user ? `UID: ${user.uid}` : "Not logged in");
        if (!user) {
            setAuthUiLoggedOut();
            return;
        }
        setAuthUiLoggedIn(user);
        await checkEntitlement(user.uid);
    });
}
