
const STORAGE_SESSION = 'shade_session';
const STORAGE_PRIVATE_KEY = 'shade_private_key';
const STORAGE_PUBLIC_KEY = 'shade_public_key';
const HASH_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*[]{}|;:,.<>?/~';
const HASH_HOLD_MS = 10000;
const AVATAR_COLORS = [
    '#8b5cf6', '#6366f1', '#ec4899', '#14b8a6',
    '#f59e0b', '#ef4444', '#3b82f6', '#a855f7',
    '#f472b6', '#22d3ee', '#a78bfa', '#34d399'
];



async function generateRSAKeys() {
    const keyPair = await crypto.subtle.generateKey(
        { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
        true, ['encrypt', 'decrypt']
    );
    const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    return {
        publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))),
        privateKey: btoa(String.fromCharCode(...new Uint8Array(privateKey))),
        keyPair: keyPair
    };
}

async function importPublicKey(pem) {
    const binaryString = atob(pem);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
    return await crypto.subtle.importKey('spki', bytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['encrypt']);
}

async function importPrivateKey(pem) {
    const binaryString = atob(pem);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
    return await crypto.subtle.importKey('pkcs8', bytes, { name: 'RSA-OAEP', hash: 'SHA-256' }, true, ['decrypt']);
}

async function encryptWithPublicKey(plaintext, publicKeyPem) {
    try {
        const pubKey = await importPublicKey(publicKeyPem);
        const encoder = new TextEncoder();
        const data = encoder.encode(plaintext);
        const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const aesKeyRaw = await crypto.subtle.exportKey('raw', aesKey);
        const encryptedKey = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pubKey, aesKeyRaw);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encryptedData = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, aesKey, data);
        const result = new Uint8Array(encryptedKey.byteLength + iv.length + encryptedData.byteLength);
        result.set(new Uint8Array(encryptedKey), 0);
        result.set(iv, encryptedKey.byteLength);
        result.set(new Uint8Array(encryptedData), encryptedKey.byteLength + iv.length);
        return btoa(String.fromCharCode(...result));
    } catch (e) {
        console.error('Ошибка шифрования:', e);
        return null;
    }
}

async function decryptWithPrivateKey(encryptedBase64, privateKeyPem) {
    try {
        const privKey = await importPrivateKey(privateKeyPem);
        const encrypted = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
        const rsaKeyLength = 256;
        const encryptedKey = encrypted.slice(0, rsaKeyLength);
        const aesKeyRaw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, encryptedKey);
        const aesKey = await crypto.subtle.importKey('raw', aesKeyRaw, { name: 'AES-GCM' }, true, ['decrypt']);
        const iv = encrypted.slice(rsaKeyLength, rsaKeyLength + 12);
        const encryptedData = encrypted.slice(rsaKeyLength + 12);
        const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, aesKey, encryptedData);
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        console.error('Ошибка дешифрования:', e);
        return null;
    }
}



let currentUser = null;
let chats = [];
let activeChatId = null;
const revealedMessages = new Set();
const hashCache = new Map();

let ws = null;
let wsConnected = false;
let messageQueue = [];
let reconnectAttempts = 0;
let reconnectTimeout = null;
const MAX_RECONNECT_ATTEMPTS = 10;

let isSearchMode = false;
let publicKeyCache = {};
let isSending = false;


const authScreen = document.getElementById('auth-screen');
const app = document.getElementById('app');
const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const loginError = document.getElementById('login-error');
const registerError = document.getElementById('register-error');
const authTabs = document.querySelectorAll('.auth-tab');
const logoutBtn = document.getElementById('logout-btn');
const chatList = document.getElementById('chat-list');
const searchInput = document.getElementById('search');
const emptyState = document.getElementById('empty-state');
const activeChat = document.getElementById('active-chat');
const chatName = document.getElementById('chat-name');
const chatStatus = document.getElementById('chat-status');
const chatStatusText = document.getElementById('chat-status-text');
const messagesEl = document.getElementById('messages');
const messageForm = document.getElementById('message-form');
const messageInput = document.getElementById('message-input');
const hashHint = document.getElementById('hash-hint');
const sidebarAvatar = document.getElementById('sidebar-avatar');
const sidebarNickname = document.getElementById('sidebar-nickname');
const sidebarUsername = document.getElementById('sidebar-username');
const profileOverlay = document.getElementById('profile-overlay');
const confirmOverlay = document.getElementById('confirm-overlay');
const chatAvatar = document.getElementById('chat-avatar');
const fileInput = document.getElementById('file-input');
const avatarInput = document.getElementById('avatar-input');
const attachBtn = document.getElementById('attach-btn');

const contextMenu = document.getElementById('context-menu');
const ctxPin = document.getElementById('ctx-pin');
const ctxPinText = document.getElementById('ctx-pin-text');
const ctxDelete = document.getElementById('ctx-delete');
const ctxClear = document.getElementById('ctx-clear');
let contextChatId = null;

const groupModal = document.getElementById('group-modal');
const groupNameInput = document.getElementById('group-name');
const groupMemberSearch = document.getElementById('group-member-search');
const groupMemberList = document.getElementById('group-member-list');
const selectedMembersContainer = document.getElementById('selected-members');
const createGroupBtn = document.getElementById('create-group-btn');
const closeGroupModal = document.getElementById('close-group-modal');
const cancelGroupModal = document.getElementById('cancel-group-modal');
let selectedGroupMembers = [];
let groupSearchResults = [];


function formatDate(timestamp) {
    const date = new Date(timestamp);
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const msgDate = new Date(date.getFullYear(), date.getMonth(), date.getDate());
    const diffDays = Math.floor((today - msgDate) / (1000 * 60 * 60 * 24));
    if (diffDays === 0) return 'Сегодня';
    if (diffDays === 1) return 'Вчера';
    if (diffDays < 7) {
        const weekdays = ['Воскресенье', 'Понедельник', 'Вторник', 'Среда', 'Четверг', 'Пятница', 'Суббота'];
        return weekdays[date.getDay()];
    }
    return date.toLocaleDateString('ru-RU');
}

async function hashPassword(password) {
    const data = new TextEncoder().encode(password);
    const buf = await crypto.subtle.digest('SHA-256', data);
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function normalizeUsername(raw) {
    return raw.trim().replace(/^@+/, '').toLowerCase();
}

function isValidUsername(username) {
    return /^[a-z0-9_]{3,20}$/.test(username);
}

function getInitials(name) {
    if (!name) return '?';
    const parts = name.trim().split(' ');
    if (parts.length === 1) return name.slice(0, 2).toUpperCase();
    return parts.map((p) => p[0]).join('').slice(0, 2).toUpperCase();
}

function getAvatarColor(id) {
    if (!id) return AVATAR_COLORS[0];
    let hash = 0;
    for (let i = 0; i < id.length; i++) hash = id.charCodeAt(i) + ((hash << 5) - hash);
    return AVATAR_COLORS[Math.abs(hash) % AVATAR_COLORS.length];
}

function getStoredAvatar() {
    try { return localStorage.getItem(`shade_avatar_${currentUser?.username || 'default'}`) || null; } catch { return null; }
}

function setStoredAvatar(data) {
    try { localStorage.setItem(`shade_avatar_${currentUser?.username || 'default'}`, data); } catch { }
}

function createAvatarEl(name, id, sizeClass = '', online = false) {
    const el = document.createElement('div');
    el.className = `avatar ${sizeClass} ${online ? 'online' : ''}`.trim();
    const color = getAvatarColor(id);
    const initials = getInitials(name);
    
    // Только для текущего пользователя показываем сохранённую аватарку
    if (id === currentUser?.username) {
        const storedAvatar = getStoredAvatar();
        if (storedAvatar) {
            el.style.background = 'transparent';
            const img = document.createElement('img');
            img.src = storedAvatar;
            img.alt = initials;
            img.draggable = false;
            el.appendChild(img);
            return el;
        }
    }
    el.style.background = color;
    el.textContent = initials;
    return el;
}

function updateAvatarElement(el, name, id) {
    if (!el) return;
    const color = getAvatarColor(id);
    const initials = getInitials(name);
    el.innerHTML = '';
    el.style.background = 'transparent';
    
    if (id === currentUser?.username) {
        const storedAvatar = getStoredAvatar();
        if (storedAvatar) {
            const img = document.createElement('img');
            img.src = storedAvatar;
            img.alt = initials;
            img.draggable = false;
            el.appendChild(img);
            return;
        }
    }
    el.style.background = color;
    el.textContent = initials;
}

function updateSidebarProfile() {
    if (!currentUser) return;
    updateAvatarElement(sidebarAvatar, currentUser.nickname || currentUser.username, currentUser.username);
    sidebarNickname.textContent = currentUser.nickname || currentUser.username;
    sidebarUsername.textContent = `@${currentUser.username}`;
}

function isHashEnabled() {
    return currentUser?.settings?.hashEnabled !== false;
}

function lockIcon() {
    return `<span class="lock-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>`;
}

function getHashText(text, cacheKey) {
    if (hashCache.has(cacheKey)) return hashCache.get(cacheKey);
    let result = '';
    for (let i = 0; i < text.length; i++) {
        if (text[i] === ' ') result += ' ';
        else if (text[i] === '\n') result += '\n';
        else result += HASH_CHARS[Math.floor(Math.random() * HASH_CHARS.length)];
    }
    hashCache.set(cacheKey, result);
    return result;
}

function displayText(text, msgKey, forceReveal = false) {
    if (!isHashEnabled() || forceReveal || revealedMessages.has(msgKey)) return text;
    return getHashText(text, msgKey);
}

function getLastMessage(chat) {
    const msgs = chat.messages.filter(m => m && m.text);
    return msgs[msgs.length - 1];
}

function formatPreview(text, msgKey) {
    const max = 40;
    const shown = displayText(text, msgKey);
    return shown.length > max ? `${shown.slice(0, max)}…` : shown;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function updatePageTitle() {
    const totalUnread = chats.reduce((sum, c) => sum + (c.unread || 0), 0);
    document.title = totalUnread > 0 ? `(${totalUnread}) Shade` : 'Shade';
}


function removeAllDuplicates() {
    chats.forEach(chat => {
        const uniqueMessages = new Map();
        chat.messages.forEach(msg => {
            if (!msg || !msg.text) return;
            const key = msg.id || `${msg.text}-${msg.timestamp}-${msg.from}`;
            if (!uniqueMessages.has(key)) uniqueMessages.set(key, msg);
        });
        chat.messages = Array.from(uniqueMessages.values());
        chat.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    });
}


function togglePinChat(chatId) {
    const chat = chats.find(c => c.id === chatId);
    if (!chat) return;
    chat.pinned = !chat.pinned;
    saveChatsToStorage();
    renderChatList(searchInput.value);
}

function isChatPinned(chatId) {
    const chat = chats.find(c => c.id === chatId);
    return chat ? chat.pinned === true : false;
}


function loadChatsFromStorage(username) {
    try {
        const saved = localStorage.getItem(`shade_chats_${username}`);
        if (saved) {
            chats = JSON.parse(saved);
            chats = chats.map(c => ({
                ...c,
                online: false,
                unread: c.unread || 0,
                messages: (c.messages || []).filter(msg => msg && msg.text)
            }));
            removeAllDuplicates();
        } else {
            chats = [];
        }
    } catch { chats = []; }
}

function saveChatsToStorage() {
    if (!currentUser) return;
    removeAllDuplicates();
    localStorage.setItem(`shade_chats_${currentUser.username}`, JSON.stringify(chats));
}


function getWebSocketUrl() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname || 'localhost';
    return `${protocol}//${host}:8765`;
}

function connectWebSocket() {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) return;
    const url = getWebSocketUrl();
    console.log(`[WS] Подключение к ${url}`);
    try {
        ws = new WebSocket(url);
    } catch (e) {
        console.error('[WS] Ошибка:', e);
        scheduleReconnect();
        return;
    }
    ws.onopen = function() {
        console.log('[WS] ✅ Подключено');
        wsConnected = true;
        reconnectAttempts = 0;
        while (messageQueue.length > 0) {
            const msg = messageQueue.shift();
            if (ws.readyState === WebSocket.OPEN) ws.send(msg);
        }
        const session = localStorage.getItem(STORAGE_SESSION);
        if (session && currentUser) {
            sendAuth(session, currentUser.passwordHash || '', currentUser.publicKey || '');
        }
        setTimeout(() => sendToServer({ type: 'get_history', data: {} }), 500);
    };
    ws.onmessage = function(event) {
        try {
            const data = JSON.parse(event.data);
            handleServerMessage(data);
        } catch (e) {
            console.error('[WS] Ошибка парсинга:', e);
        }
    };
    ws.onclose = function() {
        console.log('[WS] ❌ Соединение закрыто');
        wsConnected = false;
        ws = null;
        scheduleReconnect();
    };
    ws.onerror = function(error) {
        console.error('[WS] Ошибка:', error);
        wsConnected = false;
    };
}

function scheduleReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        console.log('[WS] ❌ Превышено количество попыток');
        return;
    }
    const delay = Math.min(3000 * Math.pow(1.5, reconnectAttempts), 30000);
    reconnectAttempts++;
    console.log(`[WS] Переподключение через ${delay/1000} сек...`);
    if (reconnectTimeout) clearTimeout(reconnectTimeout);
    reconnectTimeout = setTimeout(() => {
        if (!wsConnected) connectWebSocket();
    }, delay);
}

function sendToServer(data) {
    const message = JSON.stringify(data);
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(message);
        return true;
    } else {
        messageQueue.push(message);
        if (!ws || ws.readyState === WebSocket.CLOSED) connectWebSocket();
        return false;
    }
}

function sendAuth(username, passwordHash, publicKey, nickname) {
    sendToServer({
        type: 'auth',
        data: {
            username: username,
            password_hash: passwordHash,
            public_key: publicKey || '',
            nickname: nickname || ''
        }
    });
}


let lastHistoryCheck = 0;
const HISTORY_CHECK_INTERVAL = 3000;

function forceCheckHistory() {
    if (!currentUser || !wsConnected) return;
    const now = Date.now();
    if (now - lastHistoryCheck < HISTORY_CHECK_INTERVAL) return;
    lastHistoryCheck = now;
    sendToServer({ type: 'get_history', data: {} });
}

setInterval(forceCheckHistory, HISTORY_CHECK_INTERVAL);


function handleServerMessage(data) {
    console.log('[WS] Получено:', data.type);
    switch(data.type) {
        case 'auth_success':
            currentUser = data.data;
            localStorage.setItem(STORAGE_SESSION, currentUser.username);
            if (currentUser.settings) {
                document.getElementById('setting-hash').checked = currentUser.settings.hashEnabled !== false;
            }
            loadChatsFromStorage(currentUser.username);
            updateSidebarProfile();
            updateHashHint();
            showApp();
            break;
        case 'auth_error':
            loginError.textContent = data.data.message || 'Ошибка авторизации';
            loginError.classList.remove('hidden');
            break;
        case 'history':
            loadHistoryFromServer(data.data);
            break;
        case 'message':
            handleNewMessage(data.data);
            break;
        case 'user_online':
            handleUserOnline(data.data.username);
            break;
        case 'user_offline':
            handleUserOffline(data.data.username);
            break;
        case 'profile_updated':
            if (currentUser) {
                currentUser.nickname = data.data.nickname;
                currentUser.settings = data.data.settings;
                updateSidebarProfile();
                updateHashHint();
                document.getElementById('profile-success').classList.remove('hidden');
                document.getElementById('profile-nickname-display').textContent = data.data.nickname;
            }
            break;
        case 'account_deleted':
            showAuth();
            break;
        case 'search_results':
            handleSearchResults(data.data);
            break;
        case 'public_key_response':
            if (data.data && data.data.public_key) {
                publicKeyCache[data.data.username] = data.data.public_key;
            }
            break;
        default:
            console.log('[WS] Неизвестный тип:', data.type);
    }
}


async function loadHistoryFromServer(messages) {
    console.log(`Загрузка ${messages.length} сообщений`);
    let newMessagesCount = 0;
    
    for (const msg of messages) {
        const from = msg.from;
        const to = msg.to;
        const isMe = from === currentUser?.username;
        let chatPartner = isMe ? to : from;
        if (chatPartner === currentUser?.username) continue;
        
        let text = msg.content;
        if (!isMe) {
            const privateKey = localStorage.getItem(STORAGE_PRIVATE_KEY);
            if (privateKey && text) {
                try {
                    const decrypted = await decryptWithPrivateKey(text, privateKey);
                    if (decrypted) text = decrypted;
                } catch (e) { }
            }
        }
        
        let chat = chats.find(c => c.id === chatPartner);
        if (!chat) {
            chat = { id: chatPartner, name: chatPartner, online: false, unread: 0, lastTime: '—', messages: [] };
            chats.push(chat);
        }
        
        const msgId = msg.id || `msg_${msg.timestamp}_${from}`;
        if (chat.messages.some(m => m.id === msgId)) continue;
        newMessagesCount++;
        
        let timestamp = msg.timestamp || Math.floor(Date.now() / 1000);
        chat.messages.push({
            id: msgId,
            text: text || ' ',
            from: isMe ? 'me' : 'them',
            time: new Date(timestamp * 1000).toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'}),
            date: formatDate(timestamp * 1000),
            timestamp: timestamp,
            delivered: msg.delivered || false,
            encrypted: !isMe
        });
        chat.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
        if (chat.messages.length > 0) chat.lastTime = chat.messages[chat.messages.length - 1].time || '—';
    }
    
    if (newMessagesCount > 0) {
        console.log(`Добавлено ${newMessagesCount} новых сообщений`);
        removeAllDuplicates();
        saveChatsToStorage();
        renderChatList(searchInput.value);
        if (activeChatId) {
            const chat = chats.find(c => c.id === activeChatId);
            if (chat) {
                renderMessages(chat);
                messagesEl.scrollTop = messagesEl.scrollHeight;
            }
        }
    }
}


async function handleNewMessage(msg) {
    const from = msg.from;
    if (from === currentUser?.username) return;
    
    let text = msg.content;
    const privateKey = localStorage.getItem(STORAGE_PRIVATE_KEY);
    if (privateKey && text) {
        try {
            const decrypted = await decryptWithPrivateKey(text, privateKey);
            if (decrypted) text = decrypted;
        } catch (e) { }
    }
    
    let chat = chats.find(c => c.id === from);
    if (!chat) {
        chat = { id: from, name: from, online: false, unread: 0, lastTime: '—', messages: [] };
        chats.push(chat);
    }
    
    let timestamp = msg.timestamp || Math.floor(Date.now() / 1000);
    const msgId = msg.id || `msg_${timestamp}_${from}`;
    if (chat.messages.some(m => m.id === msgId)) return;
    
    chat.messages.push({
        id: msgId,
        text: text || ' ',
        from: 'them',
        time: new Date(timestamp * 1000).toLocaleTimeString('ru-RU', {hour: '2-digit', minute: '2-digit'}),
        date: formatDate(timestamp * 1000),
        timestamp: timestamp,
        delivered: msg.delivered || false,
        encrypted: true
    });
    chat.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    chat.lastTime = chat.messages[chat.messages.length - 1].time || '—';
    
    if (activeChatId !== from) {
        chat.unread = (chat.unread || 0) + 1;
        updatePageTitle();
    }
    
    saveChatsToStorage();
    renderChatList(searchInput.value);
    
    if (activeChatId === from) {
        renderMessages(chat);
        messagesEl.scrollTop = messagesEl.scrollHeight;
    }
}


function handleUserOnline(username) {
    const chat = chats.find(c => c.id === username);
    if (chat) {
        chat.online = true;
        renderChatList(searchInput.value);
        if (activeChatId === username) {
            chatStatus.classList.remove('offline');
            chatStatusText.textContent = 'онлайн';
        }
    }
}

function handleUserOffline(username) {
    const chat = chats.find(c => c.id === username);
    if (chat) {
        chat.online = false;
        renderChatList(searchInput.value);
        if (activeChatId === username) {
            chatStatus.classList.add('offline');
            chatStatusText.textContent = 'был(а) недавно';
        }
    }
}


function searchUsers(query) {
    if (!query || query.length < 2) {
        isSearchMode = false;
        renderChatList('');
        return;
    }
    isSearchMode = true;
    sendToServer({ type: 'search_users', data: { query: query.toLowerCase().trim() } });
}

function handleSearchResults(results) {
    const filtered = results.filter(user => user.username !== currentUser?.username);
    renderSearchResults(filtered);
}

function renderSearchResults(results) {
    chatList.innerHTML = '';
    if (results.length === 0) {
        chatList.innerHTML = `<div style="padding:40px 20px;text-align:center;color:var(--text-secondary);"><div style="font-size:48px;margin-bottom:16px;">🔍</div><div style="font-weight:600;margin-bottom:8px;">Ничего не найдено</div><div style="font-size:14px;">Попробуйте изменить запрос</div></div>`;
        return;
    }
    results.forEach(user => {
        const item = document.createElement('button');
        item.className = 'chat-item';
        item.type = 'button';
        const avatar = createAvatarEl(user.nickname || user.username, user.username, 'sm');
        item.appendChild(avatar);
        const info = document.createElement('div');
        info.className = 'chat-item-info';
        info.innerHTML = `
            <div class="chat-item-top">
                <span class="chat-item-name">${user.nickname || user.username}</span>
                <span class="chat-item-time" style="color:var(--accent);font-size:11px;">@${user.username}</span>
            </div>
            <div class="chat-item-preview" style="color:var(--text-muted);">${user.online ? '🟢 Онлайн' : '⚪ Не в сети'}</div>
        `;
        item.appendChild(info);
        const writeBtn = document.createElement('span');
        writeBtn.style.cssText = 'background:var(--accent);color:white;padding:4px 12px;border-radius:20px;font-size:12px;font-weight:600;flex-shrink:0;cursor:pointer;transition:transform 0.15s;';
        writeBtn.textContent = 'Написать';
        writeBtn.onmouseover = () => writeBtn.style.transform = 'scale(1.05)';
        writeBtn.onmouseout = () => writeBtn.style.transform = 'scale(1)';
        item.appendChild(writeBtn);
        item.addEventListener('click', () => createOrOpenChat(user.username, user.nickname || user.username, user.public_key));
        chatList.appendChild(item);
    });
}


async function getPublicKey(username) {
    if (publicKeyCache[username]) return publicKeyCache[username];
    return new Promise((resolve) => {
        const handler = (data) => {
            if (data.type === 'public_key_response' && data.data.username === username) {
                ws.removeEventListener('message', handler);
                resolve(data.data.public_key);
            }
        };
        ws.addEventListener('message', handler);
        sendToServer({ type: 'get_public_key', data: { username: username } });
        setTimeout(() => {
            ws.removeEventListener('message', handler);
            resolve(null);
        }, 5000);
    });
}

function createOrOpenChat(username, nickname, publicKey) {
    if (username === currentUser?.username) { alert('Нельзя написать самому себе!'); return; }
    let chat = chats.find(c => c.id === username);
    if (!chat) {
        chat = { id: username, name: nickname || username, online: false, unread: 0, lastTime: '—', messages: [] };
        chats.push(chat);
        saveChatsToStorage();
    }
    if (publicKey) publicKeyCache[username] = publicKey;
    else getPublicKey(username).then(key => { if (key) publicKeyCache[username] = key; });
    openChat(username);
    isSearchMode = false;
    searchInput.value = '';
    renderChatList('');
}


function setupClickReveal(bubble, msgKey, realText) {
    if (!isHashEnabled() || revealedMessages.has(msgKey)) return;
    let timer = null, progress = null, isRevealed = false;
    const createTimer = () => {
        const oldProgress = bubble.querySelector('.hold-progress');
        if (oldProgress) oldProgress.remove();
        progress = document.createElement('div');
        progress.className = 'hold-progress';
        progress.style.transition = `width ${HASH_HOLD_MS}ms linear`;
        bubble.appendChild(progress);
        bubble.classList.add('revealing');
        requestAnimationFrame(() => { progress.style.width = '100%'; });
        timer = setTimeout(() => hideMessage(), HASH_HOLD_MS);
    };
    const showMessage = () => {
        if (isRevealed) return;
        isRevealed = true;
        revealedMessages.add(msgKey);
        bubble.textContent = realText;
        bubble.classList.remove('hashed');
        bubble.classList.add('revealed');
        createTimer();
        const meta = bubble.parentElement?.querySelector('.message-meta');
        if (meta) {
            const hint = meta.querySelector('.hold-hint');
            if (hint) { hint.textContent = 'закроется через 10 сек'; hint.style.color = 'var(--danger)'; }
        }
    };
    const hideMessage = () => {
        if (!isRevealed) return;
        isRevealed = false;
        revealedMessages.delete(msgKey);
        bubble.textContent = getHashText(realText, msgKey);
        bubble.classList.add('hashed');
        bubble.classList.remove('revealed', 'revealing');
        if (progress) {
            progress.style.transition = 'none';
            progress.style.width = '0';
            setTimeout(() => { if (progress && progress.parentNode) progress.remove(); }, 50);
        }
        clearTimeout(timer);
        timer = null;
        const meta = bubble.parentElement?.querySelector('.message-meta');
        if (meta) {
            const hint = meta.querySelector('.hold-hint');
            if (hint) { hint.textContent = 'нажми чтобы прочитать'; hint.style.color = 'var(--accent)'; }
        }
    };
    bubble.addEventListener('click', (e) => {
        e.stopPropagation();
        if (isRevealed) hideMessage();
        else showMessage();
    });
    document.addEventListener('click', (e) => {
        if (isRevealed && !bubble.contains(e.target)) hideMessage();
    });
}


function openChat(id) {
    const chat = chats.find((c) => c.id === id);
    if (!chat) return;
    activeChatId = id;
    chat.unread = 0;
    updatePageTitle();
    emptyState.classList.add('hidden');
    activeChat.classList.remove('hidden');
    const newAvatar = createAvatarEl(chat.name, chat.id, '', chat.online);
    newAvatar.id = 'chat-avatar';
    chatAvatar.replaceWith(newAvatar);
    chatName.textContent = chat.name;
    chatStatus.classList.toggle('offline', !chat.online);
    chatStatusText.textContent = chat.online ? 'онлайн' : 'был(а) недавно';
    renderMessages(chat);
    renderChatList(searchInput.value);
    saveChatsToStorage();
    messageInput.focus();
}

function updateHashHint() {
    if (hashHint) {
        hashHint.textContent = isHashEnabled() ? 'Нажми на зашифрованное сообщение, чтобы прочитать' : 'Режим хеша отключён';
        hashHint.classList.toggle('hidden', false);
    }
}


function renderChatList(filter = '') {
    chatList.innerHTML = '';
    const query = filter.toLowerCase().trim();
    let filteredChats = chats.filter(chat => chat.id !== currentUser?.username && chat.messages.some(m => m && m.text));
    if (query) filteredChats = filteredChats.filter(chat => chat.name.toLowerCase().includes(query) || chat.id.includes(query));
    const pinnedChats = filteredChats.filter(c => c.pinned === true);
    const unpinnedChats = filteredChats.filter(c => c.pinned !== true);
    const sortByTime = (a, b) => {
        const timeA = a.messages.length > 0 ? a.messages[a.messages.length - 1].timestamp || 0 : 0;
        const timeB = b.messages.length > 0 ? b.messages[b.messages.length - 1].timestamp || 0 : 0;
        return timeB - timeA;
    };
    const sortedPinned = [...pinnedChats].sort(sortByTime);
    const sortedUnpinned = [...unpinnedChats].sort(sortByTime);
    if (sortedPinned.length > 0 && !query) {
        const divider = document.createElement('div');
        divider.className = 'pinned-divider';
        divider.textContent = 'Закреплённые';
        chatList.appendChild(divider);
        sortedPinned.forEach(chat => renderChatItem(chat, true));
    }
    if (sortedUnpinned.length > 0) {
        if (sortedPinned.length > 0 && !query) {
            const divider = document.createElement('div');
            divider.className = 'pinned-divider';
            divider.textContent = 'Чаты';
            chatList.appendChild(divider);
        }
        sortedUnpinned.forEach(chat => renderChatItem(chat, false));
    }
    if (filteredChats.length === 0 && !query) {
        chatList.innerHTML = `<div style="padding:40px 20px;text-align:center;color:var(--text-secondary);"><div style="font-size:48px;margin-bottom:16px;">💬</div><div style="font-weight:600;margin-bottom:8px;">Нет чатов</div><div style="font-size:14px;">Найдите пользователей через поиск</div></div>`;
    } else if (filteredChats.length === 0 && query) {
        chatList.innerHTML = `<div style="padding:40px 20px;text-align:center;color:var(--text-secondary);"><div style="font-size:48px;margin-bottom:16px;">🔍</div><div style="font-weight:600;margin-bottom:8px;">Ничего не найдено</div><div style="font-size:14px;">Попробуйте изменить запрос</div></div>`;
    }
}

function renderChatItem(chat, isPinned) {
    const last = getLastMessage(chat);
    if (!last) return;
    const previewKey = `${chat.id}-${last?.id || 'empty'}-preview`;
    const item = document.createElement('button');
    item.className = `chat-item ${chat.id === activeChatId ? 'active' : ''} ${isPinned ? 'pinned-chat' : ''}`;
    item.type = 'button';
    item.dataset.chatId = chat.id;
    const avatarEl = createAvatarEl(chat.name, chat.id, 'sm', chat.online);
    item.appendChild(avatarEl);
    const info = document.createElement('div');
    info.className = 'chat-item-info';
    const previewText = last ? formatPreview(last.text, previewKey) : 'Нет сообщений';
    const hasLock = isHashEnabled() && last && !revealedMessages.has(previewKey);
    const pinIcon = isPinned ? `<span class="pinned-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:14px;height:14px;"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg></span>` : '';
    info.innerHTML = `<div class="chat-item-top"><span class="chat-item-name">${pinIcon}${chat.name}</span><span class="chat-item-time">${chat.lastTime || '—'}</span></div><div class="chat-item-preview ${isHashEnabled() ? 'hashed-preview' : ''}">${hasLock ? lockIcon() : ''}${previewText}</div>`;
    item.appendChild(info);
    if (chat.unread > 0) {
        const badge = document.createElement('span');
        badge.className = 'unread-badge';
        badge.textContent = chat.unread;
        item.appendChild(badge);
    }
    item.addEventListener('click', () => openChat(chat.id));
    item.addEventListener('contextmenu', (e) => {
        e.preventDefault();
        e.stopPropagation();
        showContextMenu(e, chat.id);
    });
    chatList.appendChild(item);
}

function showContextMenu(e, chatId) {
    contextChatId = chatId;
    const isPinned = isChatPinned(chatId);
    ctxPinText.textContent = isPinned ? 'Открепить' : 'Закрепить';
    const x = e.clientX || e.touches?.[0]?.clientX || 0;
    const y = e.clientY || e.touches?.[0]?.clientY || 0;
    contextMenu.style.left = Math.min(x, window.innerWidth - 200) + 'px';
    contextMenu.style.top = Math.min(y, window.innerHeight - 120) + 'px';
    contextMenu.classList.remove('hidden');
}


document.addEventListener('click', (e) => {
    if (contextMenu && !contextMenu.contains(e.target)) contextMenu.classList.add('hidden');
});
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') contextMenu.classList.add('hidden'); });

ctxPin.addEventListener('click', () => {
    if (contextChatId) { togglePinChat(contextChatId); contextMenu.classList.add('hidden'); }
});

ctxClear.addEventListener('click', () => {
    if (contextChatId) {
        const chat = chats.find(c => c.id === contextChatId);
        if (chat && chat.messages.length > 0) {
            if (confirm(`Очистить все сообщения в чате "${chat.name}"?`)) {
                chat.messages = [];
                chat.lastTime = '—';
                saveChatsToStorage();
                if (activeChatId === contextChatId) renderMessages(chat);
                renderChatList(searchInput.value);
            }
        } else {
            alert('В чате нет сообщений для очистки');
        }
        contextMenu.classList.add('hidden');
    }
});

ctxDelete.addEventListener('click', () => {
    if (contextChatId) {
        if (confirm(`Удалить чат "${chats.find(c => c.id === contextChatId)?.name}"?`)) {
            chats = chats.filter(c => c.id !== contextChatId);
            saveChatsToStorage();
            if (activeChatId === contextChatId) {
                activeChatId = null;
                activeChat.classList.add('hidden');
                emptyState.classList.remove('hidden');
            }
            renderChatList(searchInput.value);
        }
        contextMenu.classList.add('hidden');
    }
});


function renderMessages(chat) {
    messagesEl.innerHTML = '';
    let lastDate = null;
    const uniqueMessages = new Map();
    chat.messages.forEach(msg => {
        if (!msg || !msg.text || msg.text === 'undefined' || msg.text === null) return;
        const key = msg.id || `${msg.text}-${msg.timestamp}-${msg.from}`;
        if (!uniqueMessages.has(key)) uniqueMessages.set(key, msg);
    });
    chat.messages = Array.from(uniqueMessages.values());
    const sortedMessages = [...chat.messages].filter(msg => msg && msg.timestamp && msg.timestamp > 0 && msg.text).sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    sortedMessages.forEach((msg) => {
        if (!msg || !msg.text) return;
        if (msg.date !== lastDate) {
            lastDate = msg.date;
            const divider = document.createElement('div');
            divider.className = 'date-divider';
            divider.textContent = msg.date || 'Сегодня';
            messagesEl.appendChild(divider);
        }
        if (msg.isSystem) {
            const wrap = document.createElement('div');
            wrap.className = 'message system';
            wrap.style.cssText = 'align-self:center;max-width:80%;';
            const bubble = document.createElement('div');
            bubble.className = 'message-bubble system';
            bubble.textContent = msg.text;
            wrap.appendChild(bubble);
            messagesEl.appendChild(wrap);
            return;
        }
        if (msg.isInvite) {
            const wrap = document.createElement('div');
            wrap.className = 'message them';
            const card = document.createElement('div');
            card.className = 'invite-card';
            card.innerHTML = `
                <div class="invite-header">
                    <div class="invite-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
                    <div><div class="invite-title">Приглашение в группу</div><div class="invite-subtitle">${msg.invitedBy || 'Кто-то'} приглашает вас</div></div>
                </div>
                <div style="font-weight:600;font-size:1.05rem;margin-bottom:4px;">${msg.groupName || 'Группа'}</div>
                <div style="font-size:0.65rem;color:var(--text-muted);margin-top:8px;">${msg.time || ''}</div>
            `;
            wrap.appendChild(card);
            messagesEl.appendChild(wrap);
            return;
        }
        const msgKey = `${chat.id}-${msg.id}`;
        const wrap = document.createElement('div');
        wrap.className = `message ${msg.from || 'them'}`;
        const bubble = document.createElement('div');
        bubble.className = 'message-bubble';
        const revealed = revealedMessages.has(msgKey);
        const hashed = isHashEnabled() && !revealed && msg.from === 'them';
        const displayTextContent = msg.text || ' ';
        if (hashed) {
            bubble.classList.add('hashed');
            bubble.textContent = displayText(displayTextContent, msgKey);
            setupClickReveal(bubble, msgKey, displayTextContent);
        } else {
            bubble.textContent = displayTextContent;
        }
        const meta = document.createElement('div');
        meta.className = 'message-meta';
        meta.innerHTML = `<span class="encrypted-icon">${lockIcon()}</span>${hashed ? '<span class="hold-hint">нажми чтобы прочитать</span>' : ''}${revealed ? '<span class="hold-hint" style="color:var(--danger);">закроется через 10 сек</span>' : ''}<span>${msg.time || ''}</span>`;
        wrap.appendChild(bubble);
        wrap.appendChild(meta);
        messagesEl.appendChild(wrap);
    });
    messagesEl.scrollTop = messagesEl.scrollHeight;
}

messageForm.addEventListener('submit', (e) => {
    e.preventDefault();
    if (isSending) return;
    const text = messageInput.value.trim();
    if (!text || !activeChatId) return;
    const chat = chats.find((c) => c.id === activeChatId);
    if (!chat) return;
    isSending = true;
    const sendBtn = document.querySelector('.send-btn');
    if (sendBtn) sendBtn.disabled = true;
    const now = new Date();
    const time = now.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    const timestamp = Math.floor(now.getTime() / 1000);
    const msg = {
        id: Date.now() + Math.random(),
        text: text,
        encrypted: false,
        from: 'me',
        time: time,
        date: formatDate(now.getTime()),
        timestamp: timestamp,
        delivered: false
    };
    chat.messages.push(msg);
    chat.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    chat.lastTime = time;
    messageInput.value = '';
    renderMessages(chat);
    renderChatList(searchInput.value);
    saveChatsToStorage();
    (async () => {
        try {
            let encryptedText = text;
            let pubKey = publicKeyCache[activeChatId];
            if (!pubKey) pubKey = await getPublicKey(activeChatId);
            if (pubKey) {
                const encrypted = await encryptWithPublicKey(text, pubKey);
                if (encrypted) encryptedText = encrypted;
            }
            sendToServer({ type: 'message', data: { to: activeChatId, content: encryptedText } });
            setTimeout(forceCheckHistory, 500);
        } catch (e) { console.error('Ошибка отправки:', e); } finally {
            isSending = false;
            if (sendBtn) sendBtn.disabled = false;
        }
    })();
});

function sendFile(file, chatId) {
    const chat = chats.find(c => c.id === chatId);
    if (!chat) return;
    const now = new Date();
    const time = now.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
    const timestamp = Math.floor(now.getTime() / 1000);
    const text = `${file.name} (${formatFileSize(file.size)})`;
    const msg = {
        id: Date.now() + Math.random(),
        text: text,
        encrypted: false,
        from: 'me',
        time: time,
        date: formatDate(now.getTime()),
        timestamp: timestamp,
        delivered: false
    };
    chat.messages.push(msg);
    chat.messages.sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0));
    chat.lastTime = time;
    renderMessages(chat);
    renderChatList(searchInput.value);
    saveChatsToStorage();
    (async () => {
        let encryptedText = text;
        let pubKey = publicKeyCache[chatId];
        if (!pubKey) pubKey = await getPublicKey(chatId);
        if (pubKey) {
            const encrypted = await encryptWithPublicKey(text, pubKey);
            if (encrypted) encryptedText = encrypted;
        }
        sendToServer({ type: 'message', data: { to: chatId, content: encryptedText } });
        setTimeout(forceCheckHistory, 500);
    })();
}

attachBtn.addEventListener('click', () => {
    if (!activeChatId) { alert('Сначала выберите чат'); return; }
    fileInput.click();
});

fileInput.addEventListener('change', async (e) => {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    for (const file of files) {
        await sendFile(file, activeChatId);
    }
    fileInput.value = '';
});


document.getElementById('profile-avatar').addEventListener('click', () => {
    avatarInput.click();
});

avatarInput.addEventListener('change', (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) { alert('Пожалуйста, выберите изображение'); return; }
    if (file.size > 5 * 1024 * 1024) { alert('Размер файла не должен превышать 5MB'); return; }
    const reader = new FileReader();
    reader.onload = function(event) {
        const dataUrl = event.target.result;
        setStoredAvatar(dataUrl);
        updateSidebarProfile();
        const profileAvatar = document.getElementById('profile-avatar');
        if (profileAvatar) {
            profileAvatar.innerHTML = '';
            const img = document.createElement('img');
            img.src = dataUrl;
            img.alt = getInitials(currentUser?.nickname || currentUser?.username);
            img.draggable = false;
            profileAvatar.appendChild(img);
        }
        if (activeChatId) {
            const chat = chats.find(c => c.id === activeChatId);
            if (chat) {
                const newAvatar = createAvatarEl(chat.name, chat.id, '', chat.online);
                newAvatar.id = 'chat-avatar';
                chatAvatar.replaceWith(newAvatar);
            }
        }
        renderChatList(searchInput.value);
    };
    reader.readAsDataURL(file);
    avatarInput.value = '';
});


createGroupBtn.addEventListener('click', () => {
    groupNameInput.value = '';
    selectedGroupMembers = [];
    groupSearchResults = [];
    renderSelectedMembers();
    groupMemberList.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:14px;">Введите имя для поиска</div>`;
    groupModal.classList.remove('hidden');
});

closeGroupModal.addEventListener('click', () => groupModal.classList.add('hidden'));
cancelGroupModal.addEventListener('click', () => groupModal.classList.add('hidden'));
groupModal.addEventListener('click', (e) => { if (e.target === groupModal) groupModal.classList.add('hidden'); });

groupMemberSearch.addEventListener('input', (e) => {
    const query = e.target.value.trim();
    if (query.length >= 2) {
        const originalHandler = handleSearchResults;
        handleSearchResults = (results) => {
            groupSearchResults = results.filter(user => user.username !== currentUser?.username && !selectedGroupMembers.some(m => m.username === user.username));
            renderGroupMemberList();
            handleSearchResults = originalHandler;
        };
        searchUsers(query);
    } else {
        groupSearchResults = [];
        groupMemberList.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:14px;">Введите минимум 2 символа</div>`;
    }
});

function renderGroupMemberList() {
    if (groupSearchResults.length === 0) {
        groupMemberList.innerHTML = `<div style="padding:20px;text-align:center;color:var(--text-muted);font-size:14px;">Пользователи не найдены</div>`;
        return;
    }
    groupMemberList.innerHTML = groupSearchResults.map(user => `
        <div class="group-member-item" data-username="${user.username}">
            <div class="avatar sm" style="background:${getAvatarColor(user.username)};">${getInitials(user.nickname || user.username)}</div>
            <div><div style="font-weight:500;font-size:0.9rem;">${user.nickname || user.username}</div><div style="font-size:0.75rem;color:var(--text-muted);">@${user.username}</div></div>
            <span class="member-check"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:18px;height:18px;color:var(--accent);"><path d="M12 5v14M5 12h14"/></svg></span>
        </div>
    `).join('');
    groupMemberList.querySelectorAll('.group-member-item').forEach(el => {
        el.addEventListener('click', () => {
            const username = el.dataset.username;
            const user = groupSearchResults.find(u => u.username === username);
            if (user && !selectedGroupMembers.some(m => m.username === username)) {
                selectedGroupMembers.push(user);
                renderSelectedMembers();
                groupSearchResults = groupSearchResults.filter(u => u.username !== username);
                renderGroupMemberList();
            }
        });
    });
}

function renderSelectedMembers() {
    if (selectedGroupMembers.length === 0) {
        selectedMembersContainer.innerHTML = `<span style="color:var(--text-muted);font-size:0.8rem;">Участники не выбраны</span>`;
        return;
    }
    selectedMembersContainer.innerHTML = selectedGroupMembers.map(user => `
        <span class="selected-member-tag">${user.nickname || user.username}<span class="remove-member" data-username="${user.username}">✕</span></span>
    `).join('');
    selectedMembersContainer.querySelectorAll('.remove-member').forEach(el => {
        el.addEventListener('click', () => {
            const username = el.dataset.username;
            selectedGroupMembers = selectedGroupMembers.filter(m => m.username !== username);
            renderSelectedMembers();
            if (groupMemberSearch.value.trim().length >= 2) {
                const originalHandler = handleSearchResults;
                handleSearchResults = (results) => {
                    groupSearchResults = results.filter(user => user.username !== currentUser?.username && !selectedGroupMembers.some(m => m.username === user.username));
                    renderGroupMemberList();
                    handleSearchResults = originalHandler;
                };
                searchUsers(groupMemberSearch.value.trim());
            }
        });
    });
}

document.getElementById('confirm-create-group').addEventListener('click', () => {
    const name = groupNameInput.value.trim();
    if (!name) { alert('Введите название группы'); return; }
    if (selectedGroupMembers.length === 0) { alert('Выберите хотя бы одного участника'); return; }
    const groupId = `group_${Date.now()}`;
    const allMembers = [currentUser.username, ...selectedGroupMembers.map(m => m.username)];
    const groupChat = {
        id: groupId,
        name: name,
        online: true,
        unread: 0,
        lastTime: '—',
        messages: [],
        isGroup: true,
        members: allMembers,
        createdBy: currentUser.username
    };
    chats.push(groupChat);
    saveChatsToStorage();
    selectedGroupMembers.forEach(member => {
        const inviteText = `Приглашение в группу "${name}" от ${currentUser.nickname || currentUser.username}`;
        let chat = chats.find(c => c.id === member.username);
        if (!chat) {
            chat = { id: member.username, name: member.username, online: false, unread: 0, lastTime: '—', messages: [] };
            chats.push(chat);
        }
        const now = new Date();
        const msg = {
            id: Date.now() + Math.random(),
            text: inviteText,
            from: 'me',
            time: now.toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
            date: formatDate(now.getTime()),
            timestamp: Math.floor(now.getTime() / 1000),
            isInvite: true,
            groupId: groupId,
            groupName: name,
            invitedBy: currentUser.nickname || currentUser.username
        };
        chat.messages.push(msg);
        saveChatsToStorage();
        // here is a bug like just a messenge not like invite
        (async () => {
            let encryptedText = inviteText;
            let pubKey = await getPublicKey(member.username);
            if (pubKey) {
                const encrypted = await encryptWithPublicKey(inviteText, pubKey);
                if (encrypted) encryptedText = encrypted;
            }
            sendToServer({ type: 'message', data: { to: member.username, content: encryptedText } });
        })();
    });
    const systemMsg = {
        id: `system_${Date.now()}`,
        type: 'system',
        text: `👤 ${currentUser.nickname || currentUser.username} создал(а) группу "${name}"`,
        from: 'me',
        time: new Date().toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' }),
        date: formatDate(Date.now()),
        timestamp: Math.floor(Date.now() / 1000),
        isSystem: true
    };
    groupChat.messages.push(systemMsg);
    groupModal.classList.add('hidden');
    renderChatList(searchInput.value);
    openChat(groupId);
});


document.getElementById('open-profile').addEventListener('click', () => {
    if (!currentUser) return;
    document.getElementById('profile-nickname').value = currentUser.nickname || '';
    document.getElementById('profile-username').value = currentUser.username;
    document.getElementById('profile-new-password').value = '';
    document.getElementById('setting-hash').checked = isHashEnabled();
    document.getElementById('profile-success').classList.add('hidden');
    document.getElementById('profile-error').classList.add('hidden');
    updateAvatarElement(document.getElementById('profile-avatar'), currentUser.nickname || currentUser.username, currentUser.username);
    document.getElementById('profile-nickname-display').textContent = currentUser.nickname || currentUser.username;
    document.getElementById('profile-username-display').textContent = `@${currentUser.username}`;
    profileOverlay.classList.remove('hidden');
});

document.getElementById('close-profile').addEventListener('click', () => profileOverlay.classList.add('hidden'));
profileOverlay.addEventListener('click', (e) => { if (e.target === profileOverlay) profileOverlay.classList.add('hidden'); });

document.getElementById('profile-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const nickname = document.getElementById('profile-nickname').value.trim();
    const hashEnabled = document.getElementById('setting-hash').checked;
    const newPassword = document.getElementById('profile-new-password').value;
    const successEl = document.getElementById('profile-success');
    const errorEl = document.getElementById('profile-error');
    successEl.classList.add('hidden');
    errorEl.classList.add('hidden');
    if (!nickname || nickname.length < 2) {
        errorEl.textContent = 'Ник должен быть минимум 2 символа';
        errorEl.classList.remove('hidden');
        return;
    }
    let passwordHash = null;
    if (newPassword) {
        if (newPassword.length < 6) {
            errorEl.textContent = 'Новый пароль минимум 6 символов';
            errorEl.classList.remove('hidden');
            return;
        }
        passwordHash = await hashPassword(newPassword);
    }
    sendToServer({ type: 'profile_update', data: { nickname: nickname, settings: { hashEnabled: hashEnabled }, password_hash: passwordHash } });
    if (currentUser) {
        currentUser.nickname = nickname;
        currentUser.settings = { hashEnabled: hashEnabled };
        if (passwordHash) currentUser.passwordHash = passwordHash;
        updateSidebarProfile();
        updateHashHint();
        document.getElementById('profile-nickname-display').textContent = nickname;
        chats.forEach(chat => { if (chat.id === currentUser.username) chat.name = nickname; });
        renderChatList(searchInput.value);
        if (activeChatId) {
            const chat = chats.find(c => c.id === activeChatId);
            if (chat) chatName.textContent = chat.name;
        }
    }
    successEl.classList.remove('hidden');
});

document.getElementById('delete-account').addEventListener('click', () => {
    document.getElementById('confirm-username').textContent = `@${currentUser?.username}`;
    confirmOverlay.classList.remove('hidden');
});

document.getElementById('cancel-delete').addEventListener('click', () => confirmOverlay.classList.add('hidden'));
document.getElementById('confirm-delete').addEventListener('click', () => {
    sendToServer({ type: 'delete_account' });
    confirmOverlay.classList.add('hidden');
});
document.getElementById('setting-hash').addEventListener('change', () => { revealedMessages.clear(); });


authTabs.forEach((tab) => {
    tab.addEventListener('click', () => switchAuthTab(tab.dataset.tab));
});

function switchAuthTab(tab) {
    const loginFormEl = document.getElementById('login-form');
    const registerFormEl = document.getElementById('register-form');
    authTabs.forEach((btn) => btn.classList.toggle('active', btn.dataset.tab === tab));
    if (tab === 'login') {
        loginFormEl.classList.remove('hidden');
        registerFormEl.classList.add('hidden');
    } else {
        registerFormEl.classList.remove('hidden');
        loginFormEl.classList.add('hidden');
    }
    loginError.classList.add('hidden');
    registerError.classList.add('hidden');
}

loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = normalizeUsername(document.getElementById('login-username').value);
    const password = document.getElementById('login-password').value;
    if (!username || !password) {
        loginError.textContent = 'Заполните все поля';
        loginError.classList.remove('hidden');
        return;
    }
    const passwordHash = await hashPassword(password);
    const privateKey = localStorage.getItem(STORAGE_PRIVATE_KEY);
    const publicKey = localStorage.getItem(STORAGE_PUBLIC_KEY);
    currentUser = { username, passwordHash, publicKey: publicKey || '' };
    sendAuth(username, passwordHash, publicKey || '');
    loginError.classList.add('hidden');
});

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const nickname = document.getElementById('reg-nickname').value.trim();
    const username = normalizeUsername(document.getElementById('reg-username').value);
    const password = document.getElementById('reg-password').value;
    const password2 = document.getElementById('reg-password2').value;
    if (!nickname || nickname.length < 2) {
        registerError.textContent = 'Ник должен быть минимум 2 символа';
        registerError.classList.remove('hidden');
        return;
    }
    if (!isValidUsername(username)) {
        registerError.textContent = 'Юзернейм: 3–20 символов, латиница, цифры, _';
        registerError.classList.remove('hidden');
        return;
    }
    if (password.length < 6) {
        registerError.textContent = 'Пароль минимум 6 символов';
        registerError.classList.remove('hidden');
        return;
    }
    if (password !== password2) {
        registerError.textContent = 'Пароли не совпадают';
        registerError.classList.remove('hidden');
        return;
    }
    const passwordHash = await hashPassword(password);
    let publicKey = localStorage.getItem(STORAGE_PUBLIC_KEY);
    let privateKey = localStorage.getItem(STORAGE_PRIVATE_KEY);
    if (!publicKey || !privateKey) {
        try {
            const keys = await generateRSAKeys();
            publicKey = keys.publicKey;
            privateKey = keys.privateKey;
            localStorage.setItem(STORAGE_PUBLIC_KEY, publicKey);
            localStorage.setItem(STORAGE_PRIVATE_KEY, privateKey);
        } catch (e) { }
    }
    currentUser = { username, passwordHash, nickname, publicKey: publicKey || '' };
    sendAuth(username, passwordHash, publicKey || '', nickname);
    registerError.classList.add('hidden');
});

document.querySelectorAll('.toggle-password').forEach((btn) => {
    btn.addEventListener('click', () => {
        const input = document.getElementById(btn.dataset.target);
        input.type = input.type === 'password' ? 'text' : 'password';
    });
});

logoutBtn.addEventListener('click', showAuth);


searchInput.addEventListener('input', (e) => {
    const query = e.target.value.trim();
    if (query.length >= 2) searchUsers(query);
    else if (query.length === 0) { isSearchMode = false; renderChatList(''); }
    else { isSearchMode = false; renderChatList(query); }
});

searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') { searchInput.value = ''; isSearchMode = false; renderChatList(''); searchInput.blur(); }
});


function showApp() {
    authScreen.classList.add('hidden');
    app.classList.remove('hidden');
    updateSidebarProfile();
    updateHashHint();
    renderChatList();
    if (activeChatId) {
        const chat = chats.find(c => c.id === activeChatId);
        if (chat) openChat(activeChatId);
    }
}

function showAuth() {
    authScreen.classList.remove('hidden');
    app.classList.add('hidden');
    profileOverlay.classList.add('hidden');
    confirmOverlay.classList.add('hidden');
    activeChatId = null;
    currentUser = null;
    localStorage.removeItem(STORAGE_SESSION);
    loginForm.reset();
    registerForm.reset();
    loginError.classList.add('hidden');
    registerError.classList.add('hidden');
    chats = [];
    chatList.innerHTML = '';
}


document.addEventListener('DOMContentLoaded', function() {
    connectWebSocket();
    const session = localStorage.getItem(STORAGE_SESSION);
    if (session) loadChatsFromStorage(session);
});

document.addEventListener('visibilitychange', function() {
    if (!document.hidden) {
        if (activeChatId) {
            const chat = chats.find(c => c.id === activeChatId);
            if (chat) {
                renderMessages(chat);
                chat.unread = 0;
                renderChatList(searchInput.value);
                updatePageTitle();
            }
        }
        if (!wsConnected) connectWebSocket();
    }
});

console.log('SHADE');
