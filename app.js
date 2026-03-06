import CryptoUtils from './crypto.js';

const CONFIG = {
    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
};

/**
 * SecureUI Manager
 * Handles all visual updates, logging, and state-based layout transitions.
 */
const SecureUI = {
    isReady: false,
    sessionState: 'idle', // idle, setup, joining, inviting, streaming, disconnected
    isAdmin: false,
    localStream: null,
    // Cached DOM elements the UI manager needs
    elements: {},

    log(msg, type = 'info') {
        const prefix = '[SECURE-SHARE]';
        const styles = {
            info: 'color: #00f2ff; font-weight: bold;',
            warn: 'color: #ffaa00; font-weight: bold;',
            error: 'color: #ff3b3b; font-weight: bold;',
            signal: 'color: #a855f7; font-weight: bold;',
            media: 'color: #10b981; font-weight: bold;'
        };
        console.log(`%c${prefix} %c${msg}`, styles[type] || styles.info, 'color: inherit;');

        // Add to DOM console
        const output = document.getElementById('debug-log-output');
        if (output) {
            const entry = document.createElement('div');
            entry.className = `log-entry ${type}`;
            entry.innerText = `[${new Date().toLocaleTimeString()}] ${msg}`;
            output.appendChild(entry);
            output.scrollTop = output.scrollHeight;

            // Auto-show on errors only
            if (type === 'error') {
                document.getElementById('debug-console').classList.remove('hidden');
            }
        }
    },

    toggleConsole() {
        const console = document.getElementById('debug-console');
        if (console) console.classList.toggle('hidden');
    },

    updateStatus(text, active = false) {
        const statusText = document.getElementById('connection-status');
        const dot = document.getElementById('connection-dot');
        if (statusText) statusText.innerText = text;
        if (dot) dot.className = active ? 'dot active' : 'dot';
        if (active) this.showToast(text);
    },

    showToast(msg, type = 'info') {
        // Also output to diagnostic console for trace visibility
        this.log(`[TOAST] ${msg}`, type);

        const container = document.getElementById('toast-container');
        if (!container) return;
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerText = msg;
        container.appendChild(toast);
        setTimeout(() => toast.remove(), 4000);
    },

    showModal(title, desc) {
        const modal = document.getElementById('modal-handshake');
        const mTitle = document.getElementById('modal-title');
        const mDesc = document.getElementById('modal-desc');
        if (mTitle) mTitle.innerText = title;
        if (mDesc) mDesc.innerText = desc;
        if (modal) modal.classList.remove('hidden');
    },

    hideModal() {
        const modal = document.getElementById('modal-handshake');
        if (modal) modal.classList.add('hidden');
    },

    updateLayout(state) {
        this.sessionState = state;
        this.log(`Syncing UI for state: ${state}`, 'signal');

        const mainUi = document.getElementById('main-ui');
        const streamView = document.getElementById('stream-view');

        // Dashboard visibility logic
        const isDashboard = ['disconnected', 'idle', 'setup', 'inviting', 'joining', 'streaming_ready'].includes(state);

        if (isDashboard) {
            mainUi.classList.remove('hidden');
            streamView.classList.add('hidden');
            this.hideModal();

            // Sync Host Card Buttons
            if (this.isAdmin) {
                const stopBtn = document.getElementById('btn-stop-share');
                const startBtn = document.getElementById('btn-start-share');
                const actBtn = document.getElementById('btn-host-activate');
                const goBtn = document.getElementById('btn-host-go-live');

                if (startBtn) {
                    if (this.localStream) {
                        startBtn.innerText = '1. Change Screen';
                        startBtn.classList.remove('disabled');
                    } else if (!window.isSecureContext && location.hostname !== 'localhost') {
                        startBtn.innerText = '🔒 Insecure Context';
                        startBtn.classList.add('disabled');
                    } else if (this.isMobile && !this.supportsDisplayCapture) {
                        startBtn.innerText = '🚫 Device Unsupported';
                        startBtn.classList.add('disabled');
                    } else {
                        startBtn.innerText = 'Pick Screen to Share';
                        startBtn.classList.remove('disabled');
                    }
                }

                // Show 'Enable Discovery' only after picking screen, but hide once inviting or streaming
                if (actBtn) actBtn.classList.toggle('hidden', !this.localStream || state !== 'setup');

                // Show 'Reset' if we have a stream or are in any active state beyond idle
                if (stopBtn) stopBtn.classList.toggle('hidden', state === 'setup' && !this.localStream);

                // Show 'GO LIVE' only when peer is linked (streaming_ready)
                if (goBtn) goBtn.classList.toggle('hidden', state !== 'streaming_ready');
            } else {
                // Peer: Show final 'GO' only when linked (streaming_ready)
                const finalJoin = document.getElementById('btn-final-join');
                if (finalJoin) {
                    finalJoin.classList.toggle('hidden', state !== 'streaming_ready');
                }
            }
        }
        else if (state === 'streaming') {
            mainUi.classList.add('hidden');
            streamView.classList.remove('hidden');

            let msg = document.getElementById('session-msg');
            if (msg) msg.classList.add('hidden');

            document.getElementById('video-loader').classList.add('hidden');
            document.getElementById('remote-video').classList.toggle('hidden', this.isAdmin);
        }
    },

    showRequest(visible) {
        const overlay = document.getElementById('request-overlay');
        if (overlay) overlay.classList.toggle('hidden', !visible);
    }
};

class SecureScreenshare {
    constructor() {
        SecureUI.log('Initializing Secure Link Protocol', 'info');
        this.pc = null;
        this.localStream = null;
        this.localKeyPair = null;
        this.derivedKey = null;
        this.peerPublicKey = null;
        this.handshakeFinalized = false;

        this.cacheDom();
        this.detectEnvironment();
        this.attachEvents();

        SecureUI.log('Security Context Initialized. System Trace Active.', 'info');

        // Generate discovery code immediately on load
        this.prepareBroadcast();
    }

    cacheDom() {
        this.btnStart = document.getElementById('btn-start-share');
        this.btnDisconnect = document.getElementById('btn-disconnect');
        this.btnFullscreen = document.getElementById('btn-toggle-fullscreen');

        // Peer specific steps
        this.peerStatusArea = document.getElementById('peer-status-area');
        this.peerStepMsg = document.getElementById('peer-step-msg');
        this.btnPeerJoinLink = document.getElementById('btn-peer-join-link');
        this.btnFinalJoin = document.getElementById('btn-final-join');

        this.btnHostActivate = document.getElementById('btn-host-activate');
        this.btnHostGoLive = document.getElementById('btn-host-go-live');

        this.displayMyCode = document.getElementById('display-my-code');
        this.btnCopyCode = document.getElementById('btn-copy-my-code');
        this.peerCodeInput = document.getElementById('peer-code-input');
        this.btnGoPeer = document.getElementById('btn-go-peer');

        // Background E2EE elements
        this.hsOutput = document.getElementById('handshake-output');
        this.hsInput = document.getElementById('handshake-input');
        this.btnComplete = document.getElementById('btn-complete-handshake');
    }

    attachEvents() {
        // Broadcaster action is now implicit on load, button just triggers final state if needed
        if (this.btnStart) this.btnStart.onclick = () => this.pickScreenOnly();
        this.btnStopShare = document.getElementById('btn-stop-share');
        if (this.btnStopShare) this.btnStopShare.onclick = () => this.stopPreparing();

        if (this.btnHostActivate) this.btnHostActivate.onclick = () => this.activateHostDiscovery();
        if (this.btnHostGoLive) this.btnHostGoLive.onclick = () => this.switchToStreamingView();

        if (this.btnGoPeer) this.btnGoPeer.onclick = () => this.initJoin();
        if (this.btnPeerJoinLink) this.btnPeerJoinLink.onclick = () => this.manualLinkPeer();
        if (this.btnFinalJoin) this.btnFinalJoin.onclick = () => this.switchToStreamingView();

        this.btnDisconnect.onclick = () => this.disconnect();
        this.btnFullscreen.onclick = () => this.toggleFullscreen();
        this.btnCopyCode.onclick = () => this.copyDiscoveryCode();

        this.btnAccept = document.getElementById('btn-accept-request');
        this.btnDecline = document.getElementById('btn-decline-request');

        if (this.btnAccept) this.btnAccept.onclick = () => this.acceptRequest();
        if (this.btnDecline) this.btnDecline.onclick = () => this.declineRequest();

        this.peerCodeInput.oninput = (e) => {
            let val = e.target.value.replace(/\s/g, '');
            if (val.length > 3) val = val.slice(0, 3) + ' ' + val.slice(3, 6);
            e.target.value = val;
        };

        this.peerCodeInput.onkeydown = (e) => {
            if (e.key === 'Enter') this.initJoin();
        };

        window.onbeforeunload = () => this.disconnect();

        // Background poller for Discovery, Renegotiation, and Disconnection
        this.setupSync();
    }

    detectEnvironment() {
        this.isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
        this.supportsDisplayCapture = !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia);
        this.isSecure = window.isSecureContext;

        SecureUI.isMobile = this.isMobile;
        SecureUI.supportsDisplayCapture = this.supportsDisplayCapture;

        if (!this.isSecure && location.hostname !== 'localhost') {
            SecureUI.log('Non-secure (HTTP) context. Browser blocks all Media APIs.', 'error');
        } else if (this.isMobile && !this.supportsDisplayCapture) {
            SecureUI.log('Mobile OS Restriction: This browser does not support broadcasting your screen. You can still watch other shares.', 'warn');
        } else {
            SecureUI.log('Environment Verified: Secure Context & Media APIs available.', 'info');
        }
    }

    generateDiscoveryCode() {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async copyDiscoveryCode() {
        const code = this.displayMyCode.innerText;
        if (code === '------') return;
        await navigator.clipboard.writeText(code);
        this.btnCopyCode.innerText = 'Copied!';
        setTimeout(() => this.btnCopyCode.innerText = 'Copy Code', 2000);
    }

    /**
     * DISCOVERY SIMULATION (Replacement for real signaling server)
     * We use localStorage as a shared signaling pool for local P2P testing.
     */
    postDiscovery(code, data) {
        localStorage.setItem(`discovery_${code}`, JSON.stringify({
            timestamp: Date.now(),
            data: data,
            active: true
        }));
    }

    removeDiscovery(code) {
        localStorage.removeItem(`discovery_${code}`);
        localStorage.removeItem(`discovery_${code}_response`);
    }

    getDiscovery(code) {
        const item = localStorage.getItem(`discovery_${code}`);
        if (!item) return null;
        return JSON.parse(item);
    }

    async prepareBroadcast() {
        SecureUI.isAdmin = true;
        this.myDiscoveryCode = this.generateDiscoveryCode();
        this.displayMyCode.innerText = this.myDiscoveryCode.slice(0, 3) + ' ' + this.myDiscoveryCode.slice(3, 6);

        SecureUI.log(`Security Context Initialized. Code: ${this.myDiscoveryCode}`, 'info');

        try {
            const status = CryptoUtils.getSecurityStatus();
            if (status.isLocal) {
                SecureUI.showToast("Local Handshake active for HTTP environment.", "warn");
                SecureUI.log(status.risk, 'warn');
            } else {
                SecureUI.log(status.risk, 'info');
            }

            this.localKeyPair = await CryptoUtils.generateECCKeyPair();
            SecureUI.sessionState = 'setup';
            SecureUI.updateLayout('setup'); // Sync UI on load
        } catch (err) {
            SecureUI.log(`Auto-prep failed: ${err.message}`, 'error');
        }
    }

    async pickScreenOnly() {
        SecureUI.log('User clicked "Pick Screen" button.', 'info');
        if (!navigator.mediaDevices) {
            SecureUI.log('CRITICAL: navigator.mediaDevices is undefined. Browser is blocking Media APIs due to non-secure (HTTP) context.', 'error');
            return SecureUI.showToast('Secure Context (HTTPS) required for media.', 'error');
        }

        try {
            // Stop existing if any
            if (this.localStream) {
                this.localStream.getTracks().forEach(t => t.stop());
            }

            SecureUI.log('Requesting capture access...', 'media');

            if (this.supportsDisplayCapture) {
                this.localStream = await navigator.mediaDevices.getDisplayMedia({
                    video: { cursor: "always", frameRate: 60, width: { ideal: 1920 }, height: { ideal: 1080 } },
                    audio: false
                });
            } else {
                const reason = this.isMobile ? "Mobile Browsers block screen capture for security." : "Device/Browser unsupported.";
                throw new Error(`${reason} Please use Desktop to host, or mobile to watch.`);
            }

            // Sync with UI manager
            SecureUI.localStream = this.localStream;

            this.localStream.getVideoTracks()[0].onended = () => this.disconnect();
            SecureUI.updateStatus('Media Prepared. Click GO to enable discovery.');
            SecureUI.updateLayout('setup');
        } catch (err) {
            SecureUI.log(`Capture failed: ${err.message}`, 'error');
            SecureUI.showToast(`Capture failed: ${err.name === 'NotAllowedError' ? 'Permission Denied' : err.message}`, 'error');
        }
    }

    activateHostDiscovery() {
        SecureUI.log('Activating Discovery (Step 2)...', 'signal');
        SecureUI.sessionState = 'inviting';
        SecureUI.updateStatus('Discovery Active. Waiting for Peer Request...');
        SecureUI.updateLayout('inviting');
    }

    async startManualBroadcast() {
        // Obsolete
    }

    stopPreparing() {
        SecureUI.log('Stopping screen preparation.', 'warn');
        if (this.localStream) {
            this.localStream.getTracks().forEach(t => t.stop());
            this.localStream = null;
            SecureUI.localStream = null; // Sync with UI
        }
        SecureUI.sessionState = 'setup';
        SecureUI.updateStatus('Broadcast Cancelled');
        SecureUI.updateLayout('setup');
    }

    async initJoin() {
        const code = this.peerCodeInput.value.replace(/\s/g, '');
        if (code.length !== 6) return SecureUI.showToast('Enter 6-digit code', 'warn');

        SecureUI.isAdmin = false;
        SecureUI.log(`Requesting connection to: ${code}`, 'signal');

        // Step 1: Stay on home, update status in card
        this.peerStatusArea.classList.remove('hidden');
        this.peerStepMsg.innerText = "Request Sent. Waiting for Host...";
        this.btnFinalJoin.classList.add('hidden');

        // Post a request to the host
        this.postDiscovery(`${code}_request`, {
            timestamp: Date.now(),
            peerId: 'anonymous-peer'
        });

        SecureUI.updateStatus('Peer Request Dispatched');
    }

    async manualLinkPeer() {
        SecureUI.log('User initiated manual link step...', 'info');
        const code = this.peerCodeInput.value.replace(/\s/g, '');
        const invite = this.getDiscovery(code);

        if (invite) {
            this.peerStepMsg.innerText = "Linking Securely...";
            this.btnPeerJoinLink.classList.add('hidden');
            this.processHostOffer(invite.data);
        } else {
            SecureUI.showToast('Host invitation not found', 'error');
        }
    }

    setupSync() {
        this.syncInterval = 1000; // Base interval (1s)
        this.maxSyncInterval = 5000; // Max back-off (5s)
        this.lastSyncData = null;

        const runSync = async () => {
            const startTime = Date.now();
            const hasChange = await this.backgroundSync();

            // Smart polling back-off
            if (hasChange) {
                this.syncInterval = 1000;
            } else {
                this.syncInterval = Math.min(this.syncInterval + 500, this.maxSyncInterval);
            }

            const nextTick = Math.max(0, this.syncInterval - (Date.now() - startTime));
            this.syncTimeout = setTimeout(runSync, nextTick);
        };

        runSync();
    }

    async backgroundSync() {
        let detectedChange = false;

        // 1. Host side: Polling for peer REQUEST
        if (SecureUI.isAdmin && (SecureUI.sessionState === 'inviting' || SecureUI.sessionState === 'setup') && !this.handshakeFinalized) {
            const request = this.getDiscovery(`${this.myDiscoveryCode}_request`);
            if (request && !this.requestDetected) {
                this.requestDetected = true;
                detectedChange = true;
                SecureUI.showRequest(true);
                SecureUI.log('Incoming connection request detected!', 'signal');
            }
            if (!request && this.requestDetected) {
                this.requestDetected = false;
                detectedChange = true;
                SecureUI.showRequest(false);
            }
        }

        // Host side step 2: Polling for peer RESPONSE
        if (SecureUI.isAdmin && SecureUI.sessionState === 'inviting' && this.offerPosted && !this.handshakeFinalized) {
            const response = this.getDiscovery(`${this.myDiscoveryCode}_response`);
            if (response) {
                this.handshakeFinalized = true;
                detectedChange = true;
                this.finalizeHandshake(response.data);
            }
        }

        // 2. Peer side: Polling for Host ACCEPT or DECLINE
        if (!SecureUI.isAdmin && !this.handshakeFinalized && !this.pc) {
            const code = this.peerCodeInput.value.replace(/\s/g, '');
            if (code.length === 6) {
                const invite = this.getDiscovery(code);
                const request = this.getDiscovery(`${code}_request`);

                if (invite && this.peerStatusArea && !this.peerStatusArea.classList.contains('hidden') && !this.btnPeerJoinLink.offsetParent) {
                    this.peerStepMsg.innerText = "Host Accepted!";
                    this.btnPeerJoinLink.classList.remove('hidden');
                    detectedChange = true;
                } else if (!request && !invite && this.peerStatusArea && !this.peerStatusArea.classList.contains('hidden')) {
                    this.peerStepMsg.innerText = "Connection Declined by Host.";
                    detectedChange = true;
                    setTimeout(() => { if (!this.pc) this.peerStatusArea.classList.add('hidden'); }, 3000);
                }
            }
        }

        // 3. Peer side: Polling for renegotiated offer (Fix for Black Screen)
        const isPeerWaiting = !SecureUI.isAdmin && (SecureUI.sessionState === 'joining' || SecureUI.sessionState === 'streaming');
        if (isPeerWaiting && this.pc && !this.remoteStreamActive) {
            const code = this.peerCodeInput.value.replace(/\s/g, '');
            const invite = this.getDiscovery(code);
            if (invite) {
                const data = JSON.parse(atob(invite.data));
                if (data.streamReady && this.pc.remoteDescription && this.pc.remoteDescription.sdp !== data.sdp.sdp) {
                    detectedChange = true;
                    this.handleRenegotiation(data);
                }
            }
        }

        this.checkPeerAliveness();
        return detectedChange;
    }

    async acceptRequest() {
        SecureUI.log('Request accepted. Initializing secure handshake...', 'signal');
        SecureUI.showRequest(false);

        try {
            const exportedPub = await CryptoUtils.exportPublicKey(this.localKeyPair.publicKey);
            this.createPeerConnection();

            if (this.localStream) {
                this.localStream.getTracks().forEach(track => {
                    this.pc.addTrack(track, this.localStream);
                });
            }

            const offer = await this.pc.createOffer();
            await this.pc.setLocalDescription(offer);
            await this.waitForIce(this.pc);

            const handshakeRaw = { pub: CryptoUtils.bufToHex(exportedPub), sdp: this.pc.localDescription, streamReady: !!this.localStream };
            this.postDiscovery(this.myDiscoveryCode, btoa(JSON.stringify(handshakeRaw)));
            this.offerPosted = true;

            SecureUI.updateStatus('Handshake in progress...');
        } catch (err) {
            SecureUI.log('Accept failed: ' + err.message, 'error');
        }
    }

    declineRequest() {
        SecureUI.log('Request declined.', 'warn');
        SecureUI.showRequest(false);
        this.removeDiscovery(`${this.myDiscoveryCode}_request`);
        this.requestDetected = false;
    }

    async processHostOffer(encryptedOffer) {
        try {
            SecureUI.log('Host accepted request! Authenticating...', 'signal');
            const data = JSON.parse(atob(encryptedOffer));

            this.localKeyPair = await CryptoUtils.generateECCKeyPair();
            const exportedPub = await CryptoUtils.exportPublicKey(this.localKeyPair.publicKey);

            this.peerPublicKey = await CryptoUtils.importPublicKey(CryptoUtils.hexToBuf(data.pub));
            this.derivedKey = await CryptoUtils.deriveEncryptionKey(this.localKeyPair.privateKey, this.peerPublicKey);

            this.createPeerConnection();
            await this.pc.setRemoteDescription(new RTCSessionDescription(data.sdp));

            const answer = await this.pc.createAnswer();
            await this.pc.setLocalDescription(answer);
            await this.waitForIce(this.pc);

            const responseRaw = { pub: CryptoUtils.bufToHex(exportedPub), sdp: this.pc.localDescription };
            this.postDiscovery(`${this.peerCodeInput.value.replace(/\s/g, '')}_response`, btoa(JSON.stringify(responseRaw)));

            this.handshakeFinalized = true;
            SecureUI.updateStatus('Linked! Stream incoming...', true);
        } catch (err) {
            SecureUI.log('Process offer failed: ' + err.message, 'error');
        }
    }

    async handleRenegotiation(data) {
        try {
            SecureUI.log('Detected Host update (Stream Ready). Finalizing Link...', 'signal');
            await this.pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
            const answer = await this.pc.createAnswer();
            await this.pc.setLocalDescription(answer);

            const code = this.peerCodeInput.value.replace(/\s/g, '');
            const responseRaw = { pub: 'renegotiated', sdp: this.pc.localDescription };
            this.postDiscovery(`${code}_response`, btoa(JSON.stringify(responseRaw)));

            // Note: switching to streaming view happens in ontrack
            SecureUI.log('Handshake for stream complete', 'signal');
        } catch (err) {
            SecureUI.log('Renegotiation failed: ' + err.message, 'error');
        }
    }

    checkPeerAliveness() {
        if (SecureUI.sessionState === 'streaming' || SecureUI.sessionState === 'inviting' || SecureUI.sessionState === 'joining') {
            const code = SecureUI.isAdmin ? this.myDiscoveryCode : this.peerCodeInput.value.replace(/\s/g, '');
            const target = SecureUI.isAdmin ? `${code}_response` : code;

            // Only check if handshake was finalized, otherwise it's expected not to find the peer
            if (!this.getDiscovery(target) && this.handshakeFinalized) {
                SecureUI.log('Peer seems to have left. Resetting...', 'warn');
                SecureUI.showToast('Peer Disconnected', 'warn');
                this.disconnect();
            }
        }
    }

    async finalizeHandshake(encryptedAnswer) {
        try {
            SecureUI.log('Peer response received. Completing link...', 'signal');
            const data = JSON.parse(atob(encryptedAnswer));
            this.peerPublicKey = await CryptoUtils.importPublicKey(CryptoUtils.hexToBuf(data.pub));
            this.derivedKey = await CryptoUtils.deriveEncryptionKey(this.localKeyPair.privateKey, this.peerPublicKey);

            await this.pc.setRemoteDescription(new RTCSessionDescription(data.sdp));
            this.handshakeFinalized = true;

            SecureUI.log('Secure Link Established!', 'info');
            SecureUI.updateStatus('Link Ready. Click GO to Broadcast.');

            // Show the GO button for final redirect
            SecureUI.updateLayout('streaming_ready');

        } catch (err) {
            SecureUI.log('Finalization failed: ' + err.message, 'error');
        }
    }

    switchToStreamingView() {
        SecureUI.sessionState = 'streaming';
        SecureUI.updateLayout('streaming');
        SecureUI.updateStatus('Secure P2P Online', true);
    }

    createPeerConnection() {
        this.pc = new RTCPeerConnection(CONFIG);
        this.pc.oniceconnectionstatechange = () => {
            SecureUI.log(`ICE State: ${this.pc.iceConnectionState}`, 'info');
            if (this.pc.iceConnectionState === 'connected') {
                SecureUI.log('Tunnel Secure. Link Established.', 'info');
                SecureUI.updateStatus('Step Completed. Click GO to continue.');
                SecureUI.updateLayout('streaming_ready');

                if (!SecureUI.isAdmin) {
                    this.peerStepMsg.innerText = "Secure Link Active!";
                }
            }
            if (['disconnected', 'failed', 'closed'].includes(this.pc.iceConnectionState)) {
                this.disconnect();
            }
        };

        this.pc.ontrack = (event) => {
            SecureUI.log('Remote track received (Step 2 Complete)!', 'media');
            this.remoteStreamActive = true;
            const video = document.getElementById('remote-video');

            if (event.streams && event.streams[0]) {
                video.srcObject = event.streams[0];
            } else {
                video.srcObject = new MediaStream([event.track]);
            }

            video.play().catch(e => SecureUI.log('Video auto-play delayed', 'warn'));

            // STAY ON HOME - reveal manual GO button
            SecureUI.updateLayout('streaming_ready');
        };
    }

    disconnect() {
        SecureUI.log('Ending Secure Session', 'warn');
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
            SecureUI.localStream = null; // Sync with UI
        }
        if (this.pc) {
            this.pc.close();
            this.pc = null;
        }

        // Signal removal if we were the host
        if (SecureUI.isAdmin && this.myDiscoveryCode) {
            this.removeDiscovery(this.myDiscoveryCode);
        } else if (!SecureUI.isAdmin) {
            const code = this.peerCodeInput.value.replace(/\s/g, '');
            this.removeDiscovery(code); // Remove the host's offer
            this.removeDiscovery(`${code}_response`); // Remove our response
        }

        this.handshakeFinalized = false;
        this.remoteStreamActive = false;
        this.requestDetected = false;
        this.offerPosted = false;
        SecureUI.updateLayout('disconnected');
        SecureUI.updateStatus('Session Disconnected');

        // Re-prepare broadcast on disconnect to show new code
        setTimeout(() => this.prepareBroadcast(), 1000);
    }

    toggleFullscreen() {
        if (!document.fullscreenElement) {
            document.getElementById('stream-view').requestFullscreen();
        } else document.exitFullscreen();
    }

    waitForIce(pc) {
        return new Promise(resolve => {
            const timeout = setTimeout(() => {
                SecureUI.log('ICE Timeout: Proceeding', 'warn');
                resolve();
            }, 3000);
            if (pc.iceGatheringState === 'complete') {
                clearTimeout(timeout);
                resolve();
            } else {
                pc.onicecandidate = (event) => {
                    if (!event.candidate) {
                        clearTimeout(timeout);
                        resolve();
                    }
                };
            }
        });
    }
}

document.addEventListener('DOMContentLoaded', () => {
    if (!CryptoUtils.isSupported()) return alert('WebCrypto not supported.');
    window.app = new SecureScreenshare();
});
