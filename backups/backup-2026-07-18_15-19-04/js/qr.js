import { buildWifiQrPayload } from './utils.js';
import { state } from './config.js';

/**
 * Download Wi-Fi QR as PDF
 */
window.downloadWifiPdf = function() {
    if (!state.viewerProDoc) {
        alert("このPDF機能はPROページのみです");
        return;
    }

    const ssid = state.viewerState.ssid || "";
    const pass = state.viewerState.pass || "";
    const name = state.viewerState.name || "sugudesu";

    if (!ssid || !pass) {
        alert("Wi-Fi情報が不足しています");
        return;
    }

    if (!window.jspdf || !window.jspdf.jsPDF) {
        alert("PDFライブラリの読み込みに失敗しました");
        return;
    }

    const qrPayload = buildWifiQrPayload(ssid, pass);

    const tmp = document.getElementById("wifi-qr-tmp");
    tmp.innerHTML = "";
    const holder = document.createElement("div");
    holder.style.width = "240px";
    holder.style.height = "240px";
    tmp.appendChild(holder);

    new QRCode(holder, {
        text: qrPayload,
        width: 220,
        height: 220,
        colorDark: "#000000",
        colorLight: "#ffffff"
    });

    const canvas = holder.querySelector("canvas");
    let dataUrl = "";
    if (canvas && typeof canvas.toDataURL === "function") {
        dataUrl = canvas.toDataURL("image/png");
    } else {
        const img = holder.querySelector("img");
        if (img && img.src) dataUrl = img.src;
    }

    if (!dataUrl) {
        alert("QR生成に失敗しました");
        return;
    }

    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF({ orientation: "portrait", unit: "mm", format: "a4" });

    const margin = 18;
    let y = 20;

    pdf.setFont("helvetica", "bold");
    pdf.setFontSize(18);
    pdf.text("Wi-Fi Access QR", margin, y);

    y += 10;
    pdf.setFont("helvetica", "normal");
    pdf.setFontSize(12);
    pdf.text(`Shop: ${name}`, margin, y);

    y += 8;
    pdf.text(`SSID: ${ssid}`, margin, y);

    y += 8;
    pdf.text(`PASS: ${pass}`, margin, y);

    y += 10;
    const qrSizeMm = 80;
    const x = margin;
    pdf.addImage(dataUrl, "PNG", x, y, qrSizeMm, qrSizeMm);

    y += qrSizeMm + 10;
    pdf.setFontSize(10);
    pdf.text("Scan this QR to join Wi-Fi. Print and place near the router or counter.", margin, y);

    const fileSafeName = (name || "wifi").replace(/[\\\/:*?"<>|]/g, "_").substring(0, 40);
    pdf.save(`wifi-qr_${fileSafeName}.pdf`);
};

/**
 * Generate QR code in element
 * @param {string} elementId - Target element ID
 * @param {string} text - QR content
 * @param {number} size - QR size in pixels
 * @param {Object} colors - Optional color overrides
 */
export function generateQr(elementId, text, size = 120, colors = {}) {
    const el = document.getElementById(elementId);
    if (!el) return;
    
    el.innerHTML = "";
    
    const colorDark = colors.dark || "#333";
    const colorLight = colors.light || "#fff";
    
    new QRCode(el, {
        text,
        width: size,
        height: size,
        colorDark,
        colorLight
    });
}

/**
 * Generate SNS QR codes
 * @param {Object} snsData - SNS URLs
 * @param {boolean} isPro - Is PRO user
 */
export function generateSnsQrs(snsData, isPro) {
    if (!isPro) {
        document.getElementById("sns-qr-area").style.display = "none";
        return;
    }

    const hasAnySns = !!(snsData.instagram || snsData.x || snsData.website);
    if (!hasAnySns) {
        document.getElementById("sns-qr-area").style.display = "none";
        return;
    }

    document.getElementById("sns-qr-area").style.display = "block";

    if (snsData.instagram) {
        document.getElementById("snsqr-insta").style.display = "block";
        generateQr("snsqr-insta-code", snsData.instagram, 110);
    } else {
        document.getElementById("snsqr-insta").style.display = "none";
    }

    if (snsData.x) {
        document.getElementById("snsqr-x").style.display = "block";
        generateQr("snsqr-x-code", snsData.x, 110);
    } else {
        document.getElementById("snsqr-x").style.display = "none";
    }

    if (snsData.website) {
        document.getElementById("snsqr-web").style.display = "block";
        generateQr("snsqr-web-code", snsData.website, 110);
    } else {
        document.getElementById("snsqr-web").style.display = "none";
    }
}

/**
 * Generate page share QR
 * @param {boolean} isPro - Is PRO user
 */
export function generateShareQr(isPro) {
    const shareArea = document.getElementById("share-qr-area");
    const qrHost = document.getElementById("viewer-qr");
    
    if (!isPro) {
        shareArea.style.display = "none";
        return;
    }

    shareArea.style.display = "block";
    qrHost.innerHTML = "";
    
    new QRCode(qrHost, {
        text: window.location.href,
        width: 120,
        height: 120,
        colorDark: "#333",
        colorLight: "#fff"
    });
}
