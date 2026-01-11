/**
 * app.js v1.0.0
 * アプリケーション初期化
 * 
 * 機能:
 * - 環境検出（ローカル/サーバー）
 * - HTMLパーツの動的ロード
 * - モジュール初期化
 * - エラーハンドリング
 */

// ==================== ENVIRONMENT DETECTION ====================

/**
 * 実行環境を検出
 * 
 * @returns {Object} 環境情報
 * @returns {string} return.protocol - プロトコル（file:, http:, https:）
 * @returns {boolean} return.isLocalFile - ローカルファイルか
 * @returns {boolean} return.isHttpServer - HTTPサーバーか
 * @returns {string} return.mode - モード（'local' or 'server'）
 */
export function detectEnvironment() {
    const protocol = window.location.protocol;
    const isLocalFile = protocol === 'file:';
    const isHttpServer = protocol === 'http:' || protocol === 'https:';
    
    return {
        protocol,
        isLocalFile,
        isHttpServer,
        mode: isLocalFile ? 'local' : 'server'
    };
}

// ==================== HTML LOADING ====================

/**
 * HTMLパーツをロード
 * 
 * @param {Object} env - 環境情報
 */
export async function loadHTMLParts(env) {
    try {
        if (env.isLocalFile) {
            await loadHTMLPartsLocal();
        } else {
            await loadHTMLPartsServer();
        }
        
        console.log('✅ HTML Parts Loaded');
    } catch (error) {
        console.error('❌ Failed to load HTML parts:', error);
        throw error;
    }
}

/**
 * サーバーモード: fetch()で動的ロード
 * 
 * @private
 */
async function loadHTMLPartsServer() {
    // Load login & pricing
    const loginResponse = await fetch('html/login.html');
    const loginHTML = await loginResponse.text();
    document.getElementById('login-container').innerHTML = loginHTML;
    
    const pricingResponse = await fetch('html/pricing.html');
    const pricingHTML = await pricingResponse.text();
    
    // Insert pricing into login-welcome-screen
    const loginWelcomeCard = document.querySelector('.login-welcome-card');
    if (loginWelcomeCard) {
        const pricingContainer = document.createElement('div');
        pricingContainer.innerHTML = pricingHTML;
        loginWelcomeCard.appendChild(pricingContainer.firstElementChild);
    }
    
    // Load viewer
    const viewerResponse = await fetch('html/viewer.html');
    const viewerHTML = await viewerResponse.text();
    document.getElementById('viewer-container').innerHTML = viewerHTML;
    
    // Load creator
    const creatorResponse = await fetch('html/creator.html');
    const creatorHTML = await creatorResponse.text();
    document.getElementById('creator-container').innerHTML = creatorHTML;
}

/**
 * ローカルモード: 警告メッセージを表示
 * 
 * @private
 */
async function loadHTMLPartsLocal() {
    const { getLocalModeWarning } = await import('./local-mode-warning.js');
    
    document.getElementById('login-container').innerHTML = getLocalModeWarning();
    document.getElementById('viewer-container').innerHTML = '';
    document.getElementById('creator-container').innerHTML = '';
}

// ==================== MODULE LOADING ====================

/**
 * JavaScriptモジュールをロード
 * 
 * @param {Object} env - 環境情報
 */
export async function loadModules(env) {
    if (env.isLocalFile) {
        console.warn('⚠️ ローカルモード: JSモジュールは読み込まれません');
        return;
    }
    
    try {
        // Import modules
        const { initializeAuthListeners } = await import('./auth.js');
        const { initializePageLoad } = await import('./viewer.js');
        
        // Initialize
        await initializeAuthListeners();
        await initializePageLoad();
        
        console.log('✅ Modules Loaded');
    } catch (error) {
        console.error('❌ Failed to load modules:', error);
        throw error;
    }
}

// ==================== UI CONTROL ====================

/**
 * ローディング画面を非表示
 */
export function hideLoadingScreen() {
    const loadingScreen = document.getElementById('loading-screen');
    if (loadingScreen) {
        setTimeout(() => {
            loadingScreen.classList.add('hidden');
        }, 500);
    }
}

/**
 * ローディング画面にモード表示
 * 
 * @param {Object} env - 環境情報
 */
export function updateLoadingMode(env) {
    const loadingMode = document.getElementById('loading-mode');
    if (loadingMode) {
        loadingMode.textContent = env.isLocalFile 
            ? '⚠️ ローカルモード（機能制限あり）' 
            : '✅ サーバーモード';
    }
}

/**
 * エラー画面を表示
 * 
 * @param {string} message - エラーメッセージ
 */
export function showError(message) {
    const container = document.getElementById('login-container');
    if (container) {
        container.innerHTML = `
            <div style="
                background: #1a1a1a;
                color: white;
                padding: 40px;
                text-align: center;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            ">
                <div>
                    <h2 style="color: #ff6464; margin-bottom: 20px;">エラーが発生しました</h2>
                    <p style="color: #ccc;">${message}</p>
                    <button onclick="location.reload()" style="
                        margin-top: 20px;
                        padding: 12px 24px;
                        background: #d4af37;
                        color: #000;
                        border: none;
                        border-radius: 8px;
                        cursor: pointer;
                        font-weight: bold;
                    ">再読み込み</button>
                </div>
            </div>
        `;
    }
}

// ==================== INITIALIZATION ====================

/**
 * アプリケーション初期化
 */
export async function initializeApp() {
    console.log('=== App Initialized v1.0.0 ===');
    
    // Detect environment
    const env = detectEnvironment();
    console.log('Mode:', env.mode);
    console.log('Protocol:', env.protocol);
    
    // Update loading screen
    updateLoadingMode(env);
    
    try {
        // Load HTML parts
        await loadHTMLParts(env);
        
        // Load modules (server mode only)
        if (env.isHttpServer) {
            await loadModules(env);
        }
        
        // Hide loading screen
        hideLoadingScreen();
        
        console.log('✅ App Ready');
    } catch (error) {
        console.error('❌ Initialization failed:', error);
        showError('アプリケーションの初期化に失敗しました');
    }
}