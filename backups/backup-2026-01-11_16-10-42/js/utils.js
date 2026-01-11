import { INSTALL_ID_KEY } from './config.js';

// ==================== ID MANAGEMENT ====================
export function getOrCreateInstallId() {
    let id = localStorage.getItem(INSTALL_ID_KEY);
    if (id) return id;
    if (window.crypto && typeof window.crypto.randomUUID === "function") {
        id = window.crypto.randomUUID();
    } else {
        id = "id_" + Math.random().toString(16).slice(2) + "_" + Date.now().toString(16);
    }
    localStorage.setItem(INSTALL_ID_KEY, id);
    return id;
}

// ==================== URL UTILITIES ====================
export function normalizeHttpUrl(url) {
    try {
        const u = new URL(url);
        if (u.protocol !== "http:" && u.protocol !== "https:") return "";
        return u.toString();
    } catch (_) {
        return "";
    }
}

export function sanitizeSlug(input) {
    const raw = (input || "").trim().toLowerCase();
    if (!raw) return "";
    const s = raw.replace(/[^a-z0-9_-]/g, "").replace(/_{2,}/g, "_").replace(/-{2,}/g, "-");
    return s.substring(0, 32);
}

export function randomSlug(len) {
    const chars = "abcdefghijkmnpqrstuvwxyz23456789";
    let out = "";
    for (let i = 0; i < len; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
}

export function getBasePathNoQuery() {
    return window.location.href.split("?")[0].split("#")[0];
}

export function buildPrettyUrl(slug) {
    const base = getBasePathNoQuery();
    return `${base}#/onepage/${encodeURIComponent(slug)}`;
}

export function parsePrettySlugFromHash() {
    const h = (window.location.hash || "").trim();
    const m = h.match(/^#\/onepage\/([^/?#]+)(\?.*)?$/);
    if (!m) return "";
    try {
        return decodeURIComponent(m[1]);
    } catch (_) {
        return m[1];
    }
}

// ==================== MAPS UTILITIES ====================
export function buildMapsOpenUrl(destText) {
    const d = encodeURIComponent(destText || "");
    if (!d) return "";
    return `https://www.google.com/maps/search/?api=1&query=${d}`;
}

export function buildMapsDirectionsUrl(destText) {
    const d = encodeURIComponent(destText || "");
    if (!d) return "";
    return `https://www.google.com/maps/dir/?api=1&destination=${d}`;
}

// ==================== WIFI UTILITIES ====================
export function buildWifiQrPayload(ssid, pass) {
    const s = (ssid || "").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/:/g, "\\:");
    const p = (pass || "").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/:/g, "\\:");
    return `WIFI:T:WPA;S:${s};P:${p};;`;
}

// ==================== TEXT UTILITIES ====================
export function toAsciiToken(s) {
    const raw = (s || "").trim();
    if (!raw) return "";
    const only = raw.replace(/[^A-Za-z0-9 _-]/g, "");
    const squashed = only.replace(/\s+/g, "-").replace(/-{2,}/g, "-").replace(/_{2,}/g, "_");
    const trimmed = squashed.replace(/^[-_]+|[-_]+$/g, "");
    return trimmed.substring(0, 24);
}

export function clampSsid(s) {
    const raw = (s || "").trim();
    if (!raw) return "";
    const allowed = raw.replace(/[^A-Za-z0-9 _-]/g, "");
    const cleaned = allowed.replace(/\s+/g, " ").trim();
    return cleaned.substring(0, 32);
}

export function makeSsidCandidates(count, name, slug) {
    const nTok = toAsciiToken(name);
    const sTok = toAsciiToken(slug);

    const baseA = nTok || sTok || "SUGUDESU";
    const baseB = sTok || nTok || "SHOP";
    const now = Date.now().toString(36).toUpperCase().slice(-4);

    const patterns = [
        () => `${baseA}-${randomSlug(4).toUpperCase()}`,
        () => `${baseB}-GUEST-${randomSlug(4).toUpperCase()}`,
        () => `SUGUDESU-${baseA}-${randomSlug(3).toUpperCase()}`,
        () => `${baseA}_WIFI_${randomSlug(3).toUpperCase()}`,
        () => `GUEST-${baseA}-${now}`,
        () => `WIFI-${baseA}-${randomSlug(3).toUpperCase()}`,
        () => `${baseB}-${randomSlug(2).toUpperCase()}${Math.floor(10 + Math.random()*89)}`,
        () => `${baseA}-${Math.floor(1000 + Math.random()*9000)}`,
        () => `SUGUDESU-GUEST-${randomSlug(5).toUpperCase()}`,
        () => `${baseA}-${baseB}-${randomSlug(2).toUpperCase()}`,
        () => `SHOP-WIFI-${randomSlug(5).toUpperCase()}`,
        () => `GUEST-WIFI-${randomSlug(5).toUpperCase()}`
    ];

    const want = Math.max(6, Math.min(18, Number(count || 12)));
    const uniq = [];
    let safety = 0;

    while (uniq.length < want && safety < 200) {
        safety++;
        const p = patterns[Math.floor(Math.random() * patterns.length)];
        const cand = clampSsid(p());
        if (!cand) continue;
        if (uniq.includes(cand)) continue;
        uniq.push(cand);
    }

    return uniq.slice(0, want);
}

// ==================== PASSWORD GENERATION ====================
export function generatePassword(len) {
    const chars = "abcdefghijkmnpqrstuvwxyz23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    const n = Math.max(8, Math.min(24, Number(len || 12)));
    let out = "";

    if (window.crypto && window.crypto.getRandomValues) {
        const buf = new Uint32Array(n);
        window.crypto.getRandomValues(buf);
        for (let i = 0; i < n; i++) out += chars[buf[i] % chars.length];
        return out;
    }

    for (let i = 0; i < n; i++) out += chars[Math.floor(Math.random() * chars.length)];
    return out;
}

// ==================== DAY MODE UTILITIES ====================
export function dayModeLabel(mode) {
    if (mode === "open_days") return "営業日";
    if (mode === "closed_days") return "休業日";
    if (mode === "irregular") return "不定休";
    return "営業日/休業日";
}

export function categoryLabel(mode) {
    if (mode === "company") return "企業";
    return "店舗";
}

// ==================== DOM UTILITIES ====================
export function setText(id, value, fallback) {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = value ? value : (fallback || "");
}

export function showIf(id, cond) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = cond ? "block" : "none";
}

export function setFlexIf(id, cond) {
    const el = document.getElementById(id);
    if (!el) return;
    el.style.display = cond ? "flex" : "none";
}

export function clearQr(id) {
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = "";
}

export function makeQr(targetId, text, size) {
    const el = document.getElementById(targetId);
    if (!el) return;
    el.innerHTML = "";
    new QRCode(el, { text, width: size, height: size, colorDark: "#333", colorLight: "#fff" });
}

export function sanitizePhoneForTel(phone) {
    const p = (phone || "").trim();
    if (!p) return "";
    const cleaned = p.replace(/[^\d+]/g, "");
    if (!cleaned) return "";
    return cleaned;
}

// ==================== SEGMENTED CONTROL ====================
export function setDayMode(mode) {
    const hidden = document.getElementById("in-daymode");
    const text = document.getElementById("in-daytext");
    const seg = document.getElementById("daymode-seg");
    const ind = document.getElementById("daymode-indicator");
    const btns = (seg && seg.querySelectorAll) ? Array.from(seg.querySelectorAll(".seg-btn")) : [];

    hidden.value = mode;
    if (btns && btns.length > 0) {
        btns.forEach((b, idx) => {
            const isOn = b.dataset.mode === mode;
            b.classList.toggle("active", isOn);
            if (isOn) {
                ind.style.transform = `translateX(${idx * 100}%)`;
            }
        });
    }
    
    if (mode === "open_days") text.placeholder = "例：月〜金 / 土日 / 祝日営業";
    if (mode === "closed_days") text.placeholder = "例：水曜 / 第2火曜 / 水曜+隔週";
    if (mode === "irregular") text.placeholder = "例：不定休（SNSをご確認ください）";
}

export function setCategoryMode(mode) {
    const hidden = document.getElementById("in-category");
    const seg = document.getElementById("category-seg");
    const ind = document.getElementById("category-indicator");
    const btns = seg ? Array.from(seg.querySelectorAll(".seg-btn")) : [];

    hidden.value = mode;

    btns.forEach((b, idx) => {
        const isOn = b.dataset.mode === mode;
        b.classList.toggle("active", isOn);
        if (isOn) {
            ind.style.transform = `translateX(${idx * 100}%)`;
        }
    });
}

// ==================== QUERY PARAMS ====================
export function parseLegacyQuery() {
    const params = new URLSearchParams(window.location.search);
    if (!params.has('n')) return null;

    const legacy = {
        category: params.get('cat') || "shop",
        name: params.get('n') || "Shop",
        zip: params.get('z') || "",
        address: params.get('a') || "",
        access: params.get('ac') || "",
        open: params.get('o') || "",
        lo: params.get('lo') || "",
        close: params.get('c') || "",
        dayMode: params.get('dm') || "open_days",
        dayText: params.get('dt') || "",
        email: params.get('em') || "",
        phone: params.get('ph') || "",
        ssid: params.get('s') || "WiFi",
        pass: params.get('p') || "",
        imgUrl: params.get('i') || "",
        ig: params.get('ig') || "",
        tw: params.get('tw') || "",
        wb: params.get('wb') || ""
    };
    return legacy;
}
