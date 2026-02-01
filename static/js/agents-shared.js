/**
 * Shared utilities for Agent pages
 * Used by: agents_dashboard.html, agents_submit.html, agents_lm2nt.html, agents_history.html
 */

// ============================================================
// CSRF Token Handling
// ============================================================

/**
 * Get CSRF token from meta tag or cookie
 * @returns {string} CSRF token value
 */
function getCsrfToken() {
    // Try meta tag first (Flask template)
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (metaTag && metaTag.content) {
        return metaTag.content;
    }
    // Fall back to cookie
    const match = document.cookie.match(/csrf_token=([^;]+)/);
    return match ? match[1] : '';
}

// ============================================================
// Console Logging
// ============================================================

/**
 * Log message to console element
 * @param {string} message - Message to log
 * @param {string} type - Log type: 'info', 'success', 'error', 'warning'
 */
function log(message, type = 'info') {
    const consoleEl = document.getElementById('console-log');
    if (!consoleEl) return;

    const timestamp = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.className = `console-entry ${type}`;
    entry.textContent = `[${timestamp}] ${message}`;
    consoleEl.appendChild(entry);
    consoleEl.scrollTop = consoleEl.scrollHeight;
}

/**
 * Clear console element
 */
function clearConsole() {
    const consoleEl = document.getElementById('console-log');
    if (consoleEl) {
        consoleEl.innerHTML = '<div class="console-entry info">[INFO] Console cleared</div>';
    }
}

// ============================================================
// Notification System
// ============================================================

/**
 * Show notification toast
 * @param {string} title - Notification title
 * @param {string} type - Notification type: 'info', 'success', 'error', 'warning'
 * @param {string} message - Optional message body
 */
function showNotification(title, type = 'info', message = '') {
    const container = document.getElementById('notification-container');
    if (!container) return;

    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.style.position = 'relative';

    const icon = type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ';

    notification.innerHTML = `
        <button class="notification-close" onclick="this.parentElement.remove()">×</button>
        <div class="notification-title">${icon} ${title}</div>
        ${message ? `<div class="notification-message">${message}</div>` : ''}
    `;

    container.appendChild(notification);

    // Auto-remove after 6 seconds
    setTimeout(() => {
        if (notification.parentElement) {
            notification.style.animation = 'slideOut 0.3s ease-in forwards';
            setTimeout(() => notification.remove(), 300);
        }
    }, 6000);
}

// ============================================================
// Formatting Utilities
// ============================================================

/**
 * Format bytes to human-readable size
 * @param {number} bytes - Number of bytes
 * @returns {string} Formatted size string
 */
function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

/**
 * Format duration in seconds to human-readable string
 * @param {number} seconds - Duration in seconds
 * @returns {string} Formatted duration string
 */
function formatDuration(seconds) {
    if (!seconds) return 'N/A';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
    return `${Math.round(seconds / 3600)}h ${Math.round((seconds % 3600) / 60)}m`;
}

/**
 * Format ISO timestamp to locale string
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Formatted date/time string
 */
function formatTimestamp(timestamp) {
    if (!timestamp) return 'Unknown';
    const date = new Date(timestamp);
    return date.toLocaleString();
}

/**
 * Format timestamp as relative time (e.g., "5m ago")
 * @param {string} timestamp - ISO timestamp string
 * @returns {string} Relative time string
 */
function formatLastSeen(timestamp) {
    if (!timestamp) return 'Never';
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return `${diffSec}s ago`;
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)}m ago`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)}h ago`;
    return date.toLocaleDateString();
}

/**
 * Format ETA seconds to human-readable string
 * @param {number} seconds - Seconds remaining
 * @returns {string} Formatted ETA string
 */
function formatEta(seconds) {
    if (!seconds || seconds <= 0) return 'N/A';
    if (seconds < 60) return `${Math.round(seconds)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.floor(seconds % 60)}s`;
    if (seconds < 86400) {
        const hours = Math.floor(seconds / 3600);
        const mins = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${mins}m`;
    }
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    return `${days}d ${hours}h`;
}

/**
 * Convert eta_seconds (Unix timestamp or seconds) to remaining time string
 * @param {number} etaValue - Unix timestamp or seconds remaining
 * @returns {string|null} Formatted ETA string or null
 */
function formatEtaFromTimestamp(etaValue) {
    if (!etaValue || etaValue <= 0) return null;
    const nowSecs = Math.floor(Date.now() / 1000);
    // If value looks like a Unix timestamp (> year 2001), calculate remaining
    if (etaValue > 1000000000) {
        const remaining = etaValue - nowSecs;
        if (remaining > 0) {
            return formatEta(remaining);
        } else {
            return 'Finishing...';
        }
    }
    // Otherwise treat as seconds remaining
    return formatEta(etaValue);
}

/**
 * Format hash speed to human-readable string
 * @param {number} speed - Speed in hashes per second
 * @returns {string} Formatted speed string
 */
function formatSpeed(speed) {
    if (!speed) return '0 H/s';
    if (speed >= 1e12) return (speed / 1e12).toFixed(2) + ' TH/s';
    if (speed >= 1e9) return (speed / 1e9).toFixed(2) + ' GH/s';
    if (speed >= 1e6) return (speed / 1e6).toFixed(2) + ' MH/s';
    if (speed >= 1e3) return (speed / 1e3).toFixed(2) + ' KH/s';
    return speed + ' H/s';
}

/**
 * Format GPU temperatures array to string
 * @param {number[]} temps - Array of GPU temperatures
 * @returns {string} Formatted temperature string
 */
function formatGpuTemps(temps) {
    if (!temps || temps.length === 0) return 'N/A';
    // Show max temp if multiple GPUs, or single value if one GPU
    if (temps.length === 1) return `${temps[0]}°C`;
    const maxTemp = Math.max(...temps);
    return `${maxTemp}°C (max)`;
}

/**
 * Format GPU utilization array to string
 * @param {number[]} utils - Array of GPU utilization percentages
 * @returns {string} Formatted utilization string
 */
function formatGpuUtils(utils) {
    if (!utils || utils.length === 0) return 'N/A';
    if (utils.length === 1) return `${utils[0]}%`;
    const avgUtil = Math.round(utils.reduce((a, b) => a + b, 0) / utils.length);
    return `${avgUtil}% (avg)`;
}

/**
 * Format completed-at timestamp for job history
 * Shows time only for recent (< 24h), date+time for older
 * @param {string} isoDate - ISO date string
 * @returns {string} Formatted date/time string
 */
function formatCompletedAt(isoDate) {
    if (!isoDate) return 'N/A';
    const date = new Date(isoDate);
    const now = new Date();
    const diffMs = now - date;
    const diffHours = diffMs / (1000 * 60 * 60);

    if (diffHours < 24) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }
    return date.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' +
           date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text - Text to escape
 * @returns {string} Escaped HTML string
 */
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

/**
 * Format duration from job metadata (handles pre-calculated or computed)
 * @param {object} job - Job object with started_at/completed_at or duration
 * @returns {string} Formatted duration string
 */
function formatJobDuration(job) {
    if (job.duration) {
        return formatDuration(job.duration);
    }
    if (job.started_at && job.completed_at) {
        const start = new Date(job.started_at);
        const end = new Date(job.completed_at);
        const seconds = (end - start) / 1000;
        return formatDuration(seconds);
    }
    return 'N/A';
}
