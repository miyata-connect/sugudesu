import { doc, getDoc } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";
import { db } from './auth.js';
import { state, PAGES_COL } from './config.js';
import {
    setText,
    showIf,
    setFlexIf,
    clearQr,
    normalizeHttpUrl,
    buildMapsOpenUrl,
    buildMapsDirectionsUrl,
    parsePrettySlugFromHash,
    parseLegacyQuery,
    dayModeLabel,
    sanitizePhoneForTel,
    setDayMode,
    setCategoryMode
} from './utils.js';
import { generateQr, generateSnsQrs, generateShareQr } from './qr.js';
import { initializeSegmentedControls } from './generator.js';

/**
 * Load page from Firestore
 * @param {string} slug - Page slug
 * @returns {Promise<Object>} - Page data
 */
async function loadPrettyPage(slug) {
    const ref = doc(db, PAGES_COL, slug);
    const snap = await getDoc(ref);
    if (!snap.exists()) {
        throw "ページが見つかりません";
    }
    return snap.data();
}

/**
 * Render viewer from data
 * @param {Object} data - Page data
 */
function renderViewerFromData(data) {
    const category = (data.category || "shop").trim();
    const name = (data.name || "Shop").trim();
    const zip = (data.zip || "").trim();
    const address = (data.address || "").trim();
    const access = (data.access || "").trim();

    const open = (data.open || "").trim();
    const lo = (data.lo || "").trim();
    const close = (data.close || "").trim();

    const dayMode = (data.dayMode || "").trim();
    const dayText = (data.dayText || "").trim();

    const email = (data.email || "").trim();
    const phone = (data.phone || "").trim();

    const ssid = (data.ssid || "WiFi").trim();
    const pass = (data.pass || "").trim();
    const imgUrl = (data.imgUrl || "").trim();

    const ig = (data.ig || "").trim();
    const tw = (data.tw || "").trim();
    const wb = (data.wb || "").trim();

    const ai = (data.ai && typeof data.ai === "object") ? data.ai : null;

    // Update state
    state.viewerState.name = name;
    state.viewerState.zip = zip;
    state.viewerState.address = address;
    state.viewerState.ssid = ssid;
    state.viewerState.pass = pass;
    state.viewerState.dayMode = dayMode;
    state.viewerState.dayText = dayText;

    // Basic info
    document.title = name;
    setText("view-name", name, "SHOP");
    setText("view-ssid", "SSID: " + ssid, "SSID: ---");
    setText("view-pass", pass, "---");

    // Badge
    const badge = document.getElementById("viewer-badge");
    badge.textContent = state.viewerProDoc ? "OFFICIAL PRO" : "OFFICIAL INFO";

    // Hours
    if (open || close) {
        const hours = `${open || "--:--"} - ${close || "--:--"}`;
        setText("view-hours", hours, "---");
    } else {
        setText("view-hours", "---", "---");
    }

    if (lo) {
        document.getElementById("view-lo").style.display = "block";
        setText("view-lo-val", lo, "");
    } else {
        document.getElementById("view-lo").style.display = "none";
    }

    // Address
    setText("view-zip", zip ? `〒${zip}` : "〒---", "〒---");
    setText("view-address", address || "---", "---");

    showIf("row-access", !!access || !!address || !!zip);
    setText("view-access", access || "---", "---");

    const destText = [zip, address].filter(Boolean).join(" ");
    const canNav = !!destText;

    document.getElementById("btn-nav-start").style.display = (state.viewerProDoc && canNav) ? "inline-flex" : "none";
    document.getElementById("btn-map-nav").style.display = (state.viewerProDoc && canNav) ? "flex" : "none";

    // Contact
    showIf("row-email", !!email);
    setText("view-email", email, "---");

    showIf("row-phone", !!phone);
    setText("view-phone", phone, "---");

    const phoneLink = document.getElementById("view-phone-link");
    const tel = sanitizePhoneForTel(phone);
    if (state.viewerProDoc && tel) {
        phoneLink.href = `tel:${tel}`;
        phoneLink.style.display = "inline-flex";
    } else {
        phoneLink.href = "#";
        phoneLink.style.display = "none";
    }

    // Day info
    const label = dayModeLabel(dayMode || "open_days");
    setText("view-day-label", label, "DAY INFO");
    setText("view-daytext", dayText || "---", "---");

    // Image
    if (imgUrl && imgUrl !== "null") {
        const img = document.getElementById('view-img');
        img.src = imgUrl;
        img.style.display = 'block';
        showIf("view-no-img", false);
    } else {
        showIf("view-no-img", true);
        showIf("view-img", false);
    }

    // Map link
    if (destText) {
        document.getElementById('btn-map-link').href = buildMapsOpenUrl(destText);
        document.getElementById('btn-map-link').style.display = 'flex';
    } else {
        document.getElementById('btn-map-link').style.display = 'none';
    }

    // SNS links
    const instaUrl = ig ? `https://www.instagram.com/${ig.replace(/^@/, "")}/` : "";
    const xUrl = tw ? `https://x.com/${tw.replace(/^@/, "")}/` : "";
    const webUrl = wb ? normalizeHttpUrl(wb) : "";

    if (instaUrl) {
        document.getElementById('btn-insta').href = instaUrl;
        setFlexIf('btn-insta', true);
    } else {
        setFlexIf('btn-insta', false);
    }

    if (xUrl) {
        document.getElementById('btn-x').href = xUrl;
        setFlexIf('btn-x', true);
    } else {
        setFlexIf('btn-x', false);
    }

    if (webUrl) {
        document.getElementById('btn-web').href = webUrl;
        setFlexIf('btn-web', true);
    } else {
        setFlexIf('btn-web', false);
    }

    // SNS QR codes
    clearQr("snsqr-insta-code");
    clearQr("snsqr-x-code");
    clearQr("snsqr-web-code");

    generateSnsQrs({
        instagram: instaUrl,
        x: xUrl,
        website: webUrl
    }, state.viewerProDoc);

    // AI content
    const aiRow = document.getElementById("row-ai");
    const aiText = document.getElementById("view-ai-text");
    const aiHl = document.getElementById("view-ai-highlights");

    if (state.viewerProDoc && ai && (ai.text || (ai.highlights && ai.highlights.length))) {
        aiRow.style.display = "block";
        aiText.textContent = (ai.text || "").trim() || "—";
        if (Array.isArray(ai.highlights) && ai.highlights.length) {
            aiHl.style.display = "block";
            const lines = ai.highlights.slice(0, 5).map(s => `• ${String(s).trim()}`).filter(Boolean);
            aiHl.innerHTML = `<small>${lines.join("<br>")}</small>`;
        } else {
            aiHl.style.display = "none";
            aiHl.textContent = "";
        }
    } else {
        aiRow.style.display = "none";
        aiText.textContent = "";
        aiHl.style.display = "none";
        aiHl.textContent = "";
    }

    // Wi-Fi password copy
    document.getElementById('view-wifi-area').onclick = function() {
        navigator.clipboard.writeText(pass);
        alert("パスワードをコピーしました: " + pass);
    };

    // Share QR
    generateShareQr(state.viewerProDoc);

    // PDF button
    const pdfBtn = document.getElementById("btn-wifi-pdf");
    if (state.viewerProDoc) {
        pdfBtn.style.display = "flex";
    } else {
        pdfBtn.style.display = "none";
    }
}

/**
 * Google Maps directions handler
 */
window.openGoogleMapsDirections = function() {
    const destText = [state.viewerState.zip, state.viewerState.address].filter(Boolean).join(" ");
    const url = buildMapsDirectionsUrl(destText);
    if (!url) return;
    window.open(url, "_blank", "noopener,noreferrer");
};

/**
 * Share page handler
 */
window.sharePage = function() {
    if (navigator.share) {
        navigator.share({
            title: document.title,
            url: window.location.href
        });
    } else {
        navigator.clipboard.writeText(window.location.href);
        alert("URLをコピーしました!");
    }
};

/**
 * Router sheet handlers
 */
window.openRouterSheet = function() {
    alert("この機能は現在無効です");
};

window.closeRouterSheet = function() {
    document.getElementById("router-sheet-backdrop").style.display = "none";
};

/**
 * Initialize page load
 */
export async function initializePageLoad() {
    console.log("=== Page Load Initialized ===");

    const prettySlug = parsePrettySlugFromHash();
    const legacy = parseLegacyQuery();

    // Initialize segmented controls
    initializeSegmentedControls();

    // Check if viewer mode
    if (prettySlug || legacy) {
        document.getElementById('viewer-mode').style.display = 'block';
        document.getElementById('login-welcome-screen').style.display = 'none';

        try {
            if (prettySlug) {
                state.viewerProDoc = true;
                const data = await loadPrettyPage(prettySlug);
                renderViewerFromData(data);
            } else {
                state.viewerProDoc = false;
                renderViewerFromData(legacy);
            }
        } catch (e) {
            console.error("❌ Viewer error:", e);
            alert(typeof e === "string" ? e : "表示エラーが発生しました");
        }
    } else {
        // Creator mode or login screen
        // Auth state will handle display
    }
}
