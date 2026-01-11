// Main Application Entry Point
console.log('SUGUDESU App Loading...');

// Import modules
import { initAuth } from './auth/index.js';
import { initUtils } from './utils/index.js';

// Initialize app
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM Content Loaded');
    
    // Initialize authentication
    initAuth();
    
    // Initialize utilities
    initUtils();
    
    console.log('SUGUDESU App Loaded Successfully');
});
