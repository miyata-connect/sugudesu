/**
 * utils.js v1.0.0
 * 共通ユーティリティ関数
 */

import { INSTALL_ID_KEY } from './config.js';

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

export function normalizeHttpUrl(url) {
    try {
        const parsedUrl = new URL(url);
        if (parsedUrl.protocol !== "http:" && parsedUrl.protocol !== "https:") return "";
        return parsedUrl.toString();
    } catch (_) {
        return "";
    }
}

export function buildMapsOpenUrl(destText) {
    const encoded = encodeURIComponent(destText || "");
    if (!encoded) return "";
    return `https://www.google.com/maps/search/?api=1&query=${encoded}`;
}

export function buildMapsDirectionsUrl(destText) {
    const encoded = encodeURIComponent(destText || "");
    if (!encoded) return "";
    return `https://www.google.com/maps/dir/?api=1&destination=${encoded}`;
}

export function parsePrettySlugFromHash() {
    const hash = (window.location.hash || "").trim();
    const match = hash.match(/^#\/onepage\/([^/?#]+)(\?.*)?$/);
    if (!match) return "";
    try {
        return decodeURIComponent(match[1]);
    } catch (_) {
        return match[1];
    }
}

export function parseLegacyQuery() {
    const params = new URLSearchParams(window.location.search);
    if (!params.has('n')) return null;
    return {
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
}

export function dayModeLabel(mode) {
    if (mode === "open_days") return "営業日";
    if (mode === "closed_days") return "休業日";
    if (mode === "irregular") return "不定休";
    return "営業日/休業日";
}

export function sanitizePhoneForTel(phone) {
    const raw = (phone || "").trim();
    if (!raw) return "";
    return raw.replace(/[^\d+]/g, "") || "";
}

export function setText(id, value, fallback = "") {
    const element = document.getElementById(id);
    if (!element) return;
    element.textContent = value || fallback;
}

export function showIf(id, cond) {
    const element = document.getElementById(id);
    if (!element) return;
    element.style.display = cond ? "block" : "none";
}

export function setFlexIf(id, cond) {
    const element = document.getElementById(id);
    if (!element) return;
    element.style.display = cond ? "flex" : "none";
}

export function clearQr(id) {
    const element = document.getElementById(id);
    if (!element) return;
    element.innerHTML = "";
}