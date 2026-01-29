/**
 * Matrix Rain
 * A canvas-based Matrix digital rain effect - authentic style
 */

(function() {
    'use strict';

    const STORAGE_KEY = 'matrixModeEnabled';
    let canvas = null;
    let ctx = null;
    let animationId = null;
    let streams = [];
    let isRunning = false;

    // Matrix characters - katakana and symbols
    const matrixChars = 'アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲンヴガギグゲゴザジズゼゾダヂヅデドバビブベボパピプペポ0123456789';

    // Configuration
    const config = {
        fontSize: 15,
        columnSpacing: 20,      // Pixels between columns
        speed: 2,               // Pixels per frame the head moves
        trailLength: 25,        // Number of characters in the trail
        fadeSpeed: 0.93,        // How fast characters fade (0-1, higher = slower fade)
        flickerChance: 0.02,    // Chance a character changes per frame
        newStreamChance: 0.015  // Chance a new stream starts per column per frame
    };

    /**
     * Initialize the Matrix rain effect
     */
    function init() {
        canvas = document.getElementById('matrixCanvas');
        if (!canvas) {
            canvas = document.createElement('canvas');
            canvas.id = 'matrixCanvas';
            document.body.insertBefore(canvas, document.body.firstChild);
        }

        ctx = canvas.getContext('2d');
        resizeCanvas();
        window.addEventListener('resize', handleResize);

        if (localStorage.getItem(STORAGE_KEY) === 'true') {
            enableMatrixMode(false);
        }

        setupTrigger();
    }

    /**
     * Set up the hidden trigger element
     */
    function setupTrigger() {
        let trigger = document.querySelector('.matrix-trigger');
        if (!trigger) {
            trigger = document.createElement('div');
            trigger.className = 'matrix-trigger';
            trigger.textContent = '0';
            trigger.title = '';
            document.body.appendChild(trigger);
        }
        trigger.addEventListener('click', toggleMatrixMode);
    }

    /**
     * Resize canvas to fill window
     */
    function resizeCanvas() {
        if (!canvas) return;
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
        initStreams();
    }

    /**
     * Initialize streams - each column can have multiple falling streams
     */
    function initStreams() {
        streams = [];
        const columnCount = Math.floor(canvas.width / config.columnSpacing);

        // Start with some random streams already on screen
        for (let i = 0; i < columnCount; i++) {
            if (Math.random() < 0.4) {
                createStream(i, Math.random() * canvas.height);
            }
        }
    }

    /**
     * Create a new falling stream at a column
     */
    function createStream(columnIndex, startY = 0) {
        const stream = {
            column: columnIndex,
            x: columnIndex * config.columnSpacing,
            headY: startY,
            speed: config.speed * (0.5 + Math.random() * 1),
            chars: [],
            brightness: []
        };

        // Pre-populate characters for the trail
        for (let i = 0; i < config.trailLength; i++) {
            stream.chars.push(getRandomChar());
            stream.brightness.push(0);
        }

        streams.push(stream);
    }

    /**
     * Get a random Matrix character
     */
    function getRandomChar() {
        return matrixChars[Math.floor(Math.random() * matrixChars.length)];
    }

    /**
     * Handle window resize
     */
    function handleResize() {
        resizeCanvas();
    }

    /**
     * Draw one frame of the Matrix rain
     */
    function draw() {
        if (!ctx || !canvas) return;

        // Darken the entire canvas (creates the fade trail effect)
        ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        ctx.font = config.fontSize + 'px monospace';
        ctx.textAlign = 'center';

        const columnCount = Math.floor(canvas.width / config.columnSpacing);

        // Randomly spawn new streams
        for (let i = 0; i < columnCount; i++) {
            if (Math.random() < config.newStreamChance) {
                // Check if column doesn't have too many streams already
                const streamsInColumn = streams.filter(s => s.column === i).length;
                if (streamsInColumn < 2) {
                    createStream(i, -config.fontSize);
                }
            }
        }

        // Update and draw each stream
        for (let i = streams.length - 1; i >= 0; i--) {
            const stream = streams[i];

            // Move the head down
            stream.headY += stream.speed;

            // Update brightness - head is brightest, trail fades
            for (let j = 0; j < stream.chars.length; j++) {
                const charY = stream.headY - (j * config.fontSize);

                if (charY > 0 && charY < canvas.height) {
                    if (j === 0) {
                        // Head character - bright white
                        stream.brightness[j] = 1.0;
                    } else if (j === 1) {
                        // Second character - bright green
                        stream.brightness[j] = 0.95;
                    } else {
                        // Trail - start bright, fade over time
                        if (stream.brightness[j] < 0.9) {
                            stream.brightness[j] = 0.85 - (j * 0.025);
                        }
                        stream.brightness[j] *= config.fadeSpeed;
                    }

                    // Random character flicker
                    if (Math.random() < config.flickerChance) {
                        stream.chars[j] = getRandomChar();
                    }

                    // Draw the character
                    const brightness = Math.max(0, stream.brightness[j]);
                    if (brightness > 0.01) {
                        if (j === 0) {
                            // Head - white with glow
                            ctx.shadowBlur = 20;
                            ctx.shadowColor = '#fff';
                            ctx.fillStyle = '#fff';
                        } else if (j === 1) {
                            // Second char - very bright green
                            ctx.shadowBlur = 15;
                            ctx.shadowColor = '#0f0';
                            ctx.fillStyle = `rgb(${Math.floor(180 * brightness)}, 255, ${Math.floor(180 * brightness)})`;
                        } else {
                            // Trail - green with varying brightness
                            ctx.shadowBlur = 0;
                            const green = Math.floor(255 * brightness);
                            const rb = Math.floor(50 * brightness);
                            ctx.fillStyle = `rgb(${rb}, ${green}, ${rb})`;
                        }

                        ctx.fillText(stream.chars[j], stream.x, charY);
                    }
                }
            }

            ctx.shadowBlur = 0;

            // Remove stream if it's completely off screen
            const tailY = stream.headY - (config.trailLength * config.fontSize);
            if (tailY > canvas.height) {
                streams.splice(i, 1);
            }
        }

        animationId = requestAnimationFrame(draw);
    }

    /**
     * Start the Matrix rain animation
     */
    function start() {
        if (isRunning) return;
        isRunning = true;
        initStreams();
        draw();
    }

    /**
     * Stop the Matrix rain animation
     */
    function stop() {
        if (!isRunning) return;
        isRunning = false;
        if (animationId) {
            cancelAnimationFrame(animationId);
            animationId = null;
        }
        if (ctx && canvas) {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
        }
    }

    /**
     * Toggle Matrix mode on/off
     */
    function toggleMatrixMode() {
        if (document.body.classList.contains('matrix-mode')) {
            disableMatrixMode();
        } else {
            enableMatrixMode(true);
        }
    }

    /**
     * Enable Matrix mode
     */
    function enableMatrixMode(showToast = true) {
        document.body.classList.add('matrix-mode');
        localStorage.setItem(STORAGE_KEY, 'true');
        start();
        if (showToast) {
            showNotification('Matrix Mode: ACTIVATED');
        }
    }

    /**
     * Disable Matrix mode
     */
    function disableMatrixMode() {
        document.body.classList.remove('matrix-mode');
        localStorage.setItem(STORAGE_KEY, 'false');
        stop();
        showNotification('Matrix Mode: DEACTIVATED');
    }

    /**
     * Show a toast notification
     */
    function showNotification(message) {
        const existingToast = document.querySelector('.matrix-toast');
        if (existingToast) {
            existingToast.remove();
        }

        const toast = document.createElement('div');
        toast.className = 'matrix-toast';
        toast.textContent = message;
        document.body.appendChild(toast);

        requestAnimationFrame(() => {
            toast.classList.add('show');
        });

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 2000);
    }

    // Initialize when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    window.toggleMatrixMode = toggleMatrixMode;
})();
