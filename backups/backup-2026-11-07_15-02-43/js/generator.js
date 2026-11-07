import { doc, runTransaction, serverTimestamp } from "https://www.gstatic.com/firebasejs/10.7.0/firebase-firestore.js";
import { auth, db } from './auth.js';
import { state, PAGES_COL } from './config.js';
import {
    normalizeHttpUrl,
    sanitizeSlug,
    randomSlug,
    getBasePathNoQuery,
    buildPrettyUrl,
    clampSsid,
    generatePassword,
    makeSsidCandidates,
    setDayMode,
    setCategoryMode
} from './utils.js';
import { uploadImageToCloudinary } from './cloudinary.js';
import { callAiProxy, extractAiFields, prepareAiInput } from './ai.js';

/**
 * Initialize segmented controls
 */
export function initializeSegmentedControls() {
    const daySeg = document.getElementById("daymode-seg");
    if (daySeg) {
        daySeg.querySelectorAll(".seg-btn").forEach((b) => {
            b.addEventListener("click", () => setDayMode(b.dataset.mode));
        });
        setDayMode("open_days");
    }

    const catSeg = document.getElementById("category-seg");
    if (catSeg) {
        catSeg.querySelectorAll(".seg-btn").forEach((b) => {
            b.addEventListener("click", () => setCategoryMode(b.dataset.mode));
        });
        setCategoryMode("shop");
    }
}

/**
 * SSID suggestion handler
 */
window.suggestSsid = function() {
    if (!state.isPro) {
        alert("この機能はPRO専用です");
        return;
    }

    const name = document.getElementById("in-name").value;
    const slug = document.getElementById("in-slug").value;
    const list = makeSsidCandidates(12, name, slug);
    
    const wrap = document.getElementById("ssid-suggestions");
    wrap.innerHTML = "";
    wrap.style.display = "flex";

    list.forEach((cand) => {
        const b = document.createElement("button");
        b.type = "button";
        b.className = "ssid-chip";
        b.textContent = cand;
        b.onclick = function() {
            const input = document.getElementById("in-ssid");
            input.value = cand;
            alert("SSIDにセットしました: " + cand);
        };
        wrap.appendChild(b);
    });
};

/**
 * Router link updater
 */
window.updateRouterLink = function() {
    const url = document.getElementById('router-select').value;
    const btn = document.getElementById('router-link-btn');
    if (url) {
        btn.href = url;
        btn.style.display = 'flex';
    } else {
        btn.style.display = 'none';
    }
};

/**
 * Save page document to Firestore
 * @param {string} slug - Page slug
 * @param {Object} data - Page data
 * @param {string} ownerUid - Owner user ID
 */
async function savePageDoc(slug, data, ownerUid) {
    const ref = doc(db, PAGES_COL, slug);
    await runTransaction(db, async (tx) => {
        const snap = await tx.get(ref);
        if (snap.exists()) {
            const cur = snap.data() || {};
            if (cur.ownerUid && cur.ownerUid !== ownerUid) {
                throw "このアカウント名は既に使用されています";
            }
            tx.set(ref, {
                ...data,
                ownerUid: ownerUid,
                updatedAt: serverTimestamp()
            }, { merge: true });
        } else {
            tx.set(ref, {
                ...data,
                ownerUid: ownerUid,
                createdAt: serverTimestamp(),
                updatedAt: serverTimestamp()
            }, { merge: false });
        }
    });
}

/**
 * Start page generation
 */
window.startGeneration = async function() {
    const btn = document.getElementById('btn-gen');
    btn.disabled = true;
    btn.textContent = "処理中...";

    try {
        let uploadedImageUrl = "";
        const fileInput = document.getElementById('in-file');

        // Upload image if PRO and file selected
        if (state.isPro && fileInput && fileInput.files && fileInput.files.length > 0) {
            btn.textContent = "写真を保存中...";
            uploadedImageUrl = await uploadImageToCloudinary(fileInput.files[0]);
        }

        // Generate password
        btn.textContent = "パスワード生成中...";
        const pass = generatePassword(12);

        // Collect form data
        const category = (document.getElementById("in-category").value || "shop").trim();
        const name = (document.getElementById('in-name').value || "Shop").trim();
        const zip = (document.getElementById('in-zip').value || "").trim();
        const address = (document.getElementById('in-address').value || "").trim();
        const access = (document.getElementById('in-access').value || "").trim();

        const open = (document.getElementById('in-open').value || "").trim();
        const lo = (document.getElementById('in-lo').value || "").trim();
        const close = (document.getElementById('in-close').value || "").trim();

        const dayMode = (document.getElementById("in-daymode").value || "open_days").trim();
        const dayText = (document.getElementById("in-daytext").value || "").trim();
        if (!dayText) throw "営業日/休業日（詳細）を入力してください";

        const email = (document.getElementById('in-email').value || "").trim();
        const phone = (document.getElementById('in-phone').value || "").trim();

        const ssidRaw = (document.getElementById('in-ssid').value || "WiFi").trim();
        const ssid = clampSsid(ssidRaw) || "WiFi";

        const insta = (document.getElementById('in-insta').value || "").trim();
        const x = (document.getElementById('in-x').value || "").trim();
        const web = (document.getElementById('in-web').value || "").trim();
        const safeWeb = web ? normalizeHttpUrl(web) : "";

        // Prepare payload
        const payload = {
            category,
            name,
            zip,
            address,
            access,
            open,
            lo,
            close,
            dayMode,
            dayText,
            email,
            phone,
            ssid,
            pass,
            imgUrl: uploadedImageUrl,
            ig: insta,
            tw: x,
            wb: safeWeb
        };

        // PRO features
        if (state.isPro) {
            const user = auth.currentUser;
            if (!user) throw "未ログインです。ログインしてください。";

            // AI generation
            btn.textContent = "AI文章生成中...";
            const aiInput = prepareAiInput({
                category, name, zip, address, access,
                open, lo, close,
                dayMode, dayText,
                email, phone, ssid,
                ig: insta, tw: x, wb: safeWeb
            });

            const aiRes = await callAiProxy(aiInput);
            const aiFields = extractAiFields(aiRes);
            if (aiFields && (aiFields.text || (aiFields.highlights && aiFields.highlights.length))) {
                payload.ai = aiFields;
            }

            // Save to Firestore
            btn.textContent = "HPを作成中...";
            let slug = sanitizeSlug(document.getElementById('in-slug').value);
            if (!slug) slug = randomSlug(10);

            await savePageDoc(slug, payload, user.uid);
            state.generatedUrl = buildPrettyUrl(slug);

        } else {
            // Free version - URL params
            const baseUrl = getBasePathNoQuery();
            const params = new URLSearchParams();
            params.append('cat', category);
            params.append('n', name);
            params.append('z', zip);
            params.append('a', address);
            params.append('ac', access);
            params.append('o', open);
            params.append('lo', lo);
            params.append('c', close);
            params.append('dm', dayMode);
            params.append('dt', dayText);
            params.append('em', email);
            params.append('ph', phone);
            params.append('s', ssid);
            params.append('p', pass);
            params.append('i', uploadedImageUrl);
            if (insta) params.append('ig', insta);
            if (x) params.append('tw', x);
            if (safeWeb) params.append('wb', safeWeb);

            state.generatedUrl = `${baseUrl}?${params.toString()}`;
        }

        // Display results
        document.getElementById('gen-url').textContent = state.generatedUrl;

        const qrContainer = document.getElementById("qrcode-container");
        const freeNoQr = document.getElementById("free-no-qr");
        qrContainer.innerHTML = "";

        if (state.isPro) {
            qrContainer.style.display = "inline-block";
            freeNoQr.style.display = "none";
            new QRCode(qrContainer, {
                text: state.generatedUrl,
                width: 180,
                height: 180,
                colorDark: "#d4af37",
                colorLight: "#ffffff"
            });
        } else {
            qrContainer.style.display = "none";
            freeNoQr.style.display = "block";
        }

        document.getElementById('gen-pass-disp').textContent = pass;

        // Router setup visibility
        const proApNote = document.getElementById("pro-ap-note");
        const routerSelect = document.getElementById("router-select");
        const routerLinkBtn = document.getElementById("router-link-btn");

        if (state.isPro) {
            proApNote.style.display = "block";
            routerSelect.style.display = "none";
            routerLinkBtn.style.display = "none";
        } else {
            proApNote.style.display = "none";
            routerSelect.style.display = "block";
            updateRouterLink();
        }

        document.getElementById('result-area').style.display = 'block';

        btn.textContent = "完了";
        btn.disabled = false;

    } catch (e) {
        console.error("❌ Generation error:", e);
        alert(typeof e === "string" ? e : "エラーが発生しました");
        btn.disabled = false;
        btn.textContent = "ページ作成開始";
    }
};

// Make generatedUrl globally accessible for preview button
window.generatedUrl = "";
Object.defineProperty(window, 'generatedUrl', {
    get() { return state.generatedUrl; },
    set(val) { state.generatedUrl = val; }
});
