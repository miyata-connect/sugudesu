import { CLOUD_NAME, UPLOAD_PRESET, WORKER_SIGNER_URL } from './config.js';

/**
 * Upload image to Cloudinary with signature
 * @param {File} file - Image file to upload
 * @returns {Promise<string>} - Uploaded image URL
 */
export async function uploadImageToCloudinary(file) {
    if (!file) {
        throw new Error("画像ファイルが選択されていません");
    }

    // Get signature from worker
    console.log("📤 Requesting upload signature...");
    const signRes = await fetch(WORKER_SIGNER_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ upload_preset: UPLOAD_PRESET })
    });
    
    const signData = await signRes.json();
    
    if (!signData.signature) {
        throw new Error("署名の取得に失敗しました。");
    }

    // Upload to Cloudinary
    console.log("☁️ Uploading to Cloudinary...");
    const formData = new FormData();
    formData.append("file", file);
    formData.append("upload_preset", UPLOAD_PRESET);
    formData.append("api_key", signData.api_key);
    formData.append("timestamp", signData.timestamp);
    formData.append("signature", signData.signature);

    const uploadRes = await fetch(
        `https://api.cloudinary.com/v1_1/${CLOUD_NAME}/image/upload`, 
        {
            method: "POST",
            body: formData
        }
    );
    
    const uploadData = await uploadRes.json();
    
    if (!uploadData.secure_url) {
        throw new Error("画像のアップロードに失敗しました");
    }

    console.log("✅ Image uploaded:", uploadData.secure_url);
    return uploadData.secure_url;
}
