import { AI_PROXY_URL } from './config.js';
import { auth } from './auth.js';

// Google Sheets API設定
const SHEETS_API_URL = 'https://sheets.googleapis.com/v4/spreadsheets';
const SPREADSHEET_NAME = 'すぐですレシート記録';

// グローバル状態
let receiptImageData = null;
let googleSheetsToken = null;
let spreadsheetId = null;

/**
 * PRO版チェック
 */
function checkProStatus() {
    // TODO: 実際のPRO版チェックロジックを実装
    // 現在はダミー実装
    return true;
}

/**
 * レシートセクションを表示
 */
window.showReceiptSection = function() {
    const user = auth.currentUser;
    if (!user) {
        alert('ログインしてください');
        return;
    }

    if (!checkProStatus()) {
        alert('この機能はPRO版（¥980/月）でご利用いただけます');
        return;
    }

    const receiptSection = document.getElementById('receipt-section');
    const connectArea = document.getElementById('receipt-connect-area');
    const scannerArea = document.getElementById('receipt-scanner-area');

    receiptSection.style.display = 'block';

    // Google Sheets連携状態をチェック
    if (googleSheetsToken) {
        connectArea.style.display = 'none';
        scannerArea.style.display = 'block';
    } else {
        connectArea.style.display = 'block';
        scannerArea.style.display = 'none';
    }
}

/**
 * Googleスプレッドシートと連携
 */
window.connectGoogleSheets = async function() {
    try {
        const clientId = 'YOUR_GOOGLE_CLIENT_ID'; // TODO: 実際のClient IDに置き換え
        const redirectUri = window.location.origin + '/oauth-callback';
        const scope = 'https://www.googleapis.com/auth/spreadsheets';

        const oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
        const params = new URLSearchParams({
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'token',
            scope: scope,
            state: 'receipt_auth'
        });

        // OAuth認証画面へ遷移
        window.location.href = oauth2Endpoint + '?' + params.toString();
    } catch (error) {
        console.error('Google Sheets連携エラー:', error);
        alert('連携に失敗しました: ' + error.message);
    }
};

/**
 * OAuth callbackからトークンを取得
 */
export function handleOAuthCallback() {
    const hash = window.location.hash.substring(1);
    const params = new URLSearchParams(hash);
    const accessToken = params.get('access_token');
    const state = params.get('state');

    if (accessToken && state === 'receipt_auth') {
        googleSheetsToken = accessToken;
        // TODO: Firestoreに保存（暗号化推奨）
        
        // URLをクリーンアップ
        window.history.replaceState({}, document.title, window.location.pathname);
        
        // スプレッドシート作成
        createSpreadsheet();
        
        // UIを更新
        showReceiptSection();
    }
}

/**
 * スプレッドシートを作成または取得
 */
async function createSpreadsheet() {
    try {
        const response = await fetch(SHEETS_API_URL, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${googleSheetsToken}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                properties: {
                    title: SPREADSHEET_NAME
                },
                sheets: [{
                    properties: {
                        title: 'レシート記録',
                        gridProperties: {
                            frozenRowCount: 1
                        }
                    }
                }]
            })
        });

        if (!response.ok) {
            throw new Error('スプレッドシート作成に失敗しました');
        }

        const data = await response.json();
        spreadsheetId = data.spreadsheetId;

        // ヘッダー行を追加
        await appendToSheet([
            ['日付', '店名', '金額', '品目', 'カテゴリ', '備考']
        ]);

        console.log('✅ スプレッドシート作成完了:', data.spreadsheetUrl);
    } catch (error) {
        console.error('スプレッドシート作成エラー:', error);
        alert('スプレッドシート作成に失敗しました: ' + error.message);
    }
}

/**
 * レシート画像を処理
 */
window.handleReceiptImage = function(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        receiptImageData = e.target.result;
        
        // プレビュー表示
        const preview = document.getElementById('receipt-preview');
        const previewImg = document.getElementById('receipt-preview-img');
        
        previewImg.src = receiptImageData;
        preview.style.display = 'block';
    };
    reader.readAsDataURL(file);
};

/**
 * レシートをキャンセル
 */
window.cancelReceipt = function() {
    receiptImageData = null;
    document.getElementById('receipt-preview').style.display = 'none';
    document.getElementById('receipt-image-input').value = '';
};

/**
 * レシートを解析
 */
window.analyzeReceipt = async function() {
    if (!receiptImageData) {
        alert('画像を選択してください');
        return;
    }

    const statusDiv = document.getElementById('receipt-status');
    statusDiv.style.display = 'block';
    statusDiv.innerHTML = '🔍 解析中...';

    try {
        // Base64からバイナリデータを抽出
        const base64Data = receiptImageData.split(',')[1];

        // Gemini Flash APIに送信
        const response = await fetch(AI_PROXY_URL.replace('gemini-1.5-flash', 'gemini-1.5-flash'), {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                contents: [{
                    parts: [
                        {
                            text: `このレシート画像から以下の情報をJSON形式で抽出してください：
- date: 日付（YYYY-MM-DD形式）
- store: 店名
- amount: 合計金額（数値のみ）
- items: 品目リスト（配列）
- category: カテゴリ（食費/交通費/消耗品/その他）
- notes: その他メモ

JSON形式のみで返してください。`
                        },
                        {
                            inline_data: {
                                mime_type: 'image/jpeg',
                                data: base64Data
                            }
                        }
                    ]
                }]
            })
        });

        if (!response.ok) {
            throw new Error('解析に失敗しました');
        }

        const result = await response.json();
        const aiText = result.candidates[0].content.parts[0].text;
        
        // JSONを抽出（```json ```で囲まれている場合）
        let jsonText = aiText;
        const jsonMatch = aiText.match(/```json\n([\s\S]*?)\n```/);
        if (jsonMatch) {
            jsonText = jsonMatch[1];
        }
        
        const receiptData = JSON.parse(jsonText.trim());

        statusDiv.innerHTML = '✅ 解析完了！スプレッドシートに保存中...';

        // スプレッドシートに保存
        await saveToSheet(receiptData);

        statusDiv.innerHTML = '✅ 保存完了！';
        
        // データ表示
        displayReceiptData(receiptData);

        // プレビューを非表示
        setTimeout(() => {
            cancelReceipt();
            statusDiv.style.display = 'none';
        }, 3000);

    } catch (error) {
        console.error('レシート解析エラー:', error);
        statusDiv.innerHTML = '❌ エラー: ' + error.message;
    }
};

/**
 * スプレッドシートに保存
 */
async function saveToSheet(data) {
    const row = [
        data.date || '',
        data.store || '',
        data.amount || '',
        (data.items || []).join(', '),
        data.category || '',
        data.notes || ''
    ];

    await appendToSheet([row]);
}

/**
 * スプレッドシートに行を追加
 */
async function appendToSheet(rows) {
    try {
        const response = await fetch(
            `${SHEETS_API_URL}/${spreadsheetId}/values/レシート記録:append?valueInputOption=RAW`,
            {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${googleSheetsToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    values: rows
                })
            }
        );

        if (!response.ok) {
            throw new Error('スプレッドシートへの書き込みに失敗しました');
        }

        console.log('✅ スプレッドシートに保存完了');
    } catch (error) {
        console.error('スプレッドシート書き込みエラー:', error);
        throw error;
    }
}

/**
 * レシートデータを表示
 */
function displayReceiptData(data) {
    const dataDiv = document.getElementById('receipt-data');
    const contentDiv = document.getElementById('receipt-data-content');

    let html = `
        <div style="margin-bottom: 10px;"><strong>日付:</strong> ${data.date || '-'}</div>
        <div style="margin-bottom: 10px;"><strong>店名:</strong> ${data.store || '-'}</div>
        <div style="margin-bottom: 10px;"><strong>金額:</strong> ¥${data.amount || '-'}</div>
        <div style="margin-bottom: 10px;"><strong>品目:</strong> ${(data.items || []).join(', ') || '-'}</div>
        <div style="margin-bottom: 10px;"><strong>カテゴリ:</strong> ${data.category || '-'}</div>
    `;

    if (data.notes) {
        html += `<div style="margin-bottom: 10px;"><strong>備考:</strong> ${data.notes}</div>`;
    }

    contentDiv.innerHTML = html;
    dataDiv.style.display = 'block';

    // 3秒後に非表示
    setTimeout(() => {
        dataDiv.style.display = 'none';
    }, 5000);
}

// 初期化
if (window.location.hash.includes('access_token')) {
    handleOAuthCallback();
}
