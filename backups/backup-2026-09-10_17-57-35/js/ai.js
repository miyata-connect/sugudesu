import { AI_PROXY_URL, AI_TIMEOUT_MS } from './config.js';
import { categoryLabel, dayModeLabel } from './utils.js';

/**
 * Call AI proxy to generate shop description and highlights
 * @param {Object} input - Shop information
 * @returns {Promise<Object|null>} - AI generated content or null
 */
export async function callAiProxy(input) {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), AI_TIMEOUT_MS);

    try {
        const prompt = `以下の店舗情報を基に、200文字以内で魅力的な紹介文を作成してください。また、5つ以内の重要ポイントをリストアップしてください。

店舗情報:
- カテゴリ: ${input.category || "店舗"}
- 名称: ${input.name || ""}
- 郵便番号: ${input.zip || ""}
- 住所: ${input.address || ""}
- アクセス: ${input.access || ""}
- 営業時間: ${input.open || ""} - ${input.close || ""}
- ラストオーダー: ${input.lo || "なし"}
- ${input.dayMode || ""}: ${input.dayText || ""}
- メール: ${input.email || ""}
- 電話: ${input.phone || ""}
- SSID: ${input.ssid || ""}
- Instagram: ${input.instagram || ""}
- X: ${input.x || ""}
- ウェブサイト: ${input.website || ""}

JSON形式で以下のように出力してください:
{
  "text": "紹介文（200文字以内）",
  "highlights": ["ポイント1", "ポイント2", "ポイント3", "ポイント4", "ポイント5"]
}`;

        const res = await fetch(AI_PROXY_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                contents: [{
                    parts: [{ text: prompt }]
                }]
            }),
            signal: ctrl.signal
        });

        if (!res.ok) return null;

        const data = await res.json().catch(() => null);
        if (!data || !data.candidates || !data.candidates[0]) return null;

        const candidate = data.candidates[0];
        if (!candidate.content || !candidate.content.parts || !candidate.content.parts[0]) return null;

        const textContent = candidate.content.parts[0].text || "";
        const jsonMatch = textContent.match(/\{[\s\S]*\}/);
        if (!jsonMatch) return null;

        const parsed = JSON.parse(jsonMatch[0]);
        return parsed;

    } catch (e) {
        console.warn("⚠️ AI proxy failed", e);
        return null;
    } finally {
        clearTimeout(timer);
    }
}

/**
 * Extract and validate AI fields
 * @param {Object} aiRes - AI response
 * @returns {Object|null} - Validated AI fields
 */
export function extractAiFields(aiRes) {
    if (!aiRes) return null;

    if (typeof aiRes.text === "string") {
        return {
            text: aiRes.text.trim(),
            highlights: Array.isArray(aiRes.highlights) ? aiRes.highlights.slice(0, 5) : []
        };
    }

    return null;
}

/**
 * Prepare AI input from form data
 * @param {Object} formData - Form data from generator
 * @returns {Object} - Formatted AI input
 */
export function prepareAiInput(formData) {
    return {
        category: categoryLabel(formData.category),
        name: formData.name,
        zip: formData.zip,
        address: formData.address,
        access: formData.access,
        open: formData.open,
        lo: formData.lo,
        close: formData.close,
        dayMode: dayModeLabel(formData.dayMode),
        dayText: formData.dayText,
        email: formData.email,
        phone: formData.phone,
        ssid: formData.ssid,
        instagram: formData.ig,
        x: formData.tw,
        website: formData.wb
    };
}
