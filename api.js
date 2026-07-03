// ============================================================
// 云端数据服务模块
// 基于 jsdelivr CDN (读取) + GitHub API (写入) + AES-GCM 加密
// ============================================================

let CONFIG = null;

// ===== 二进制/字符串工具函数 =====
function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex) {
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substr(i, 2), 16));
    return new Uint8Array(bytes);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
}

function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

// ===== 读取仓库配置（从同目录 config.json，仅初始化时调用一次） =====
async function readConfig() {
    try {
        const resp = await fetch('config.json');
        if (!resp.ok) throw new Error('HTTP ' + resp.status);
        CONFIG = await resp.json();
        return CONFIG;
    } catch (e) {
        console.error('[api.js] 读取配置失败:', e);
        return null;
    }
}

// ===== PAT 管理 (localStorage) =====
function getPAT() {
    return localStorage.getItem('github_pat');
}

function setPAT(pat) {
    localStorage.setItem('github_pat', pat);
}

// ===== 从 jsdelivr CDN 读取文件（有缓存，适合显示器轮询） =====
async function readFileFromCDN(path) {
    if (!CONFIG) await readConfig();
    const url = `https://cdn.jsdelivr.net/gh/${CONFIG.githubOwner}/${CONFIG.githubRepo}@${CONFIG.githubBranch}/${path}`;
    const resp = await fetch(url);
    if (!resp.ok) return null;
    return await resp.text();
}

// ===== 从 GitHub API 直读文件（无缓存，实时，适合编辑器） =====
async function readFileFromRaw(path) {
    if (!CONFIG) await readConfig();
    const pat = getPAT();
    if (!pat) return null;
    const url = `https://api.github.com/repos/${CONFIG.githubOwner}/${CONFIG.githubRepo}/contents/${path}`;
    const resp = await fetch(url, { headers: { Authorization: `Bearer ${pat}` } });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data.content) return null;
    return atob(data.content.replace(/\n/g, ''));
}

// ===== 通过 GitHub API 写入文件 =====
async function writeFileToGitHub(path, content, message) {
    const pat = getPAT();
    if (!pat) return { ok: false, reason: '未设置 PAT' };

    const url = `https://api.github.com/repos/${CONFIG.githubOwner}/${CONFIG.githubRepo}/contents/${path}`;
    const contentBase64 = bytesToBase64(new TextEncoder().encode(content));

    let sha = null;
    const getResp = await fetch(url, { headers: { Authorization: `Bearer ${pat}` } });
    if (getResp.ok) {
        const info = await getResp.json();
        sha = info.sha;
    }

    const body = {
        message: message || `更新 ${path}`,
        content: contentBase64,
        branch: CONFIG.githubBranch
    };
    if (sha) body.sha = sha;

    const resp = await fetch(url, {
        method: 'PUT',
        headers: { Authorization: `Bearer ${pat}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
    });

    if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        console.error('[api.js] GitHub API PUT 写入失败:', resp.status, err.message || JSON.stringify(err));
        return { ok: false, reason: err.message || `HTTP ${resp.status}` };
    }
    return { ok: true };
}

// ===== AES-GCM 密钥派生 (PBKDF2) =====
async function deriveKey(password, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

// ===== 加密/解密 =====
async function encryptData(plaintext, password) {
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const key = await deriveKey(password, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);

    const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(ciphertext), salt.length + iv.length);

    return bytesToBase64(combined);
}

async function decryptData(encryptedBase64, password) {
    const combined = base64ToBytes(encryptedBase64);
    const salt = combined.slice(0, 32);
    const iv = combined.slice(32, 44);
    const ciphertext = combined.slice(44);

    const key = await deriveKey(password, salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
}

// ===== 用户认证（直读 GitHub raw，无缓存） =====
async function readUsers() {
    const text = await readFileFromRaw('users.json');
    if (!text) return { version: 1, users: {} };
    return JSON.parse(text);
}

async function authenticate(username, password) {
    const usersData = await readUsers();
    const user = usersData.users[username];
    if (!user) return { ok: false, reason: '用户不存在' };

    const encoder = new TextEncoder();
    const salt = hexToBytes(user.salt);
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, 256
    );
    const hash = bytesToHex(new Uint8Array(derivedBits));

    if (hash !== user.hash) return { ok: false, reason: '密码错误' };
    return { ok: true, displayName: user.displayName };
}

// ===== 注册用户 =====
async function registerUser(username, password, displayName) {
    const usersData = await readUsers();
    if (usersData.users[username]) return { ok: false, reason: '用户名已存在' };

    if (username.length < 2) return { ok: false, reason: '用户名至少2个字符' };
    if (password.length < 4) return { ok: false, reason: '密码至少4个字符' };

    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, 256
    );
    const hash = bytesToHex(new Uint8Array(derivedBits));

    usersData.users[username] = {
        displayName: displayName || username,
        salt: bytesToHex(salt),
        hash
    };

    const writeResult = await writeFileToGitHub(
        'users.json',
        JSON.stringify(usersData, null, 2),
        '添加用户 ' + username
    );
    if (!writeResult.ok) return { ok: false, reason: '写入 users.json 失败: ' + writeResult.reason };

    const emptyData = {
        version: '2.0',
        updatedAt: new Date().toISOString(),
        students: [],
        groups: [],
        individualPointsRules: [],
        groupPointsRules: [],
        settings: {}
    };
    const encrypted = await encryptData(JSON.stringify(emptyData), password);
    const dataResult = await writeFileToGitHub(
        `data_${username}.json.enc`,
        encrypted,
        '初始化用户数据 ' + username
    );
    if (!dataResult.ok) return { ok: false, reason: '创建数据文件失败: ' + dataResult.reason };

    return { ok: true };
}

// ===== 业务数据读写 =====

// 从 GitHub raw 直读（编辑器登录用，实时无缓存）
async function readUserData(username, password) {
    const encrypted = await readFileFromRaw(`data_${username}.json.enc`);
    if (!encrypted) return null;
    try {
        const decrypted = await decryptData(encrypted, password);
        return JSON.parse(decrypted);
    } catch (e) {
        console.error('[api.js] 解密失败:', e);
        return null;
    }
}

// 从 CDN 读取（显示器轮询用，有缓存但省流量）
async function readUserDataFromCDN(username, password) {
    const encrypted = await readFileFromCDN(`data_${username}.json.enc`);
    if (!encrypted) return null;
    try {
        const decrypted = await decryptData(encrypted, password);
        return JSON.parse(decrypted);
    } catch (e) {
        console.error('[api.js] 解密失败:', e);
        return null;
    }
}

async function writeUserData(username, password, data) {
    const plaintext = JSON.stringify(data, null, 2);
    const encrypted = await encryptData(plaintext, password);
    const result = await writeFileToGitHub(
        `data_${username}.json.enc`,
        encrypted,
        '更新 ' + username + ' 的数据'
    );
    return result.ok;
}

// ===== 删除文件（通过 GitHub API） =====
async function deleteFileFromGitHub(path, message) {
    const pat = getPAT();
    if (!pat) return { ok: false, reason: '未设置 PAT' };

    const url = `https://api.github.com/repos/${CONFIG.githubOwner}/${CONFIG.githubRepo}/contents/${path}`;

    const getResp = await fetch(url, { headers: { Authorization: `Bearer ${pat}` } });
    if (!getResp.ok) return { ok: true };
    const info = await getResp.json();

    const resp = await fetch(url, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${pat}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message || `删除 ${path}`, sha: info.sha, branch: CONFIG.githubBranch })
    });

    if (!resp.ok) {
        const err = await resp.json().catch(() => ({}));
        console.error('[api.js] GitHub API DELETE 删除失败:', resp.status, err.message || JSON.stringify(err));
        return { ok: false, reason: err.message || `HTTP ${resp.status}` };
    }
    return { ok: true };
}

// ===== 审批制：读取待审批用户列表（直读 GitHub raw，无缓存） =====
async function readPendingUsers() {
    const text = await readFileFromRaw('pending_users.json');
    if (!text) return [];
    try { return JSON.parse(text); } catch { return []; }
}

// ===== 审批制：提交注册申请 =====
async function submitRegistration(username, password, displayName) {
    if (username.length < 2) return { ok: false, reason: '用户名至少2个字符' };
    if (password.length < 4) return { ok: false, reason: '密码至少4个字符' };

    const existing = await readUsers();
    if (existing.users[username]) return { ok: false, reason: '用户名已存在' };

    const isFirstUser = Object.keys(existing.users).length === 0;

    if (!isFirstUser) {
        const pending = await readPendingUsers();
        if (pending.some(u => u.username === username)) return { ok: false, reason: '该用户名已有待审批的申请' };
    }

    const encoder = new TextEncoder();
    const salt = crypto.getRandomValues(new Uint8Array(32));
    const keyMaterial = await crypto.subtle.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits']);
    const derivedBits = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, 256
    );
    const hash = bytesToHex(new Uint8Array(derivedBits));

    const emptyData = {
        version: '2.0',
        updatedAt: new Date().toISOString(),
        students: [],
        groups: [],
        individualPointsRules: [],
        groupPointsRules: [],
        settings: {}
    };
    const encrypted = await encryptData(JSON.stringify(emptyData), password);

    if (isFirstUser) {
        existing.users[username] = {
            displayName: displayName || username,
            salt: bytesToHex(salt),
            hash
        };
        const userOk = await writeFileToGitHub('users.json', JSON.stringify(existing, null, 2), '添加首位用户 ' + username);
        if (!userOk.ok) return { ok: false, reason: '创建用户失败: ' + userOk.reason };

        const dataOk = await writeFileToGitHub(`data_${username}.json.enc`, encrypted, '初始化用户数据 ' + username);
        if (!dataOk.ok) return { ok: false, reason: '创建数据文件失败: ' + dataOk.reason };

        return { ok: true, autoApproved: true };
    }

    const dataResult = await writeFileToGitHub(
        `data_${username}.json.enc`,
        encrypted,
        '初始化用户数据 ' + username
    );
    if (!dataResult.ok) return { ok: false, reason: '创建数据文件失败: ' + dataResult.reason };

    const pending = await readPendingUsers();
    pending.push({
        username,
        displayName: displayName || username,
        salt: bytesToHex(salt),
        hash,
        submittedAt: new Date().toISOString()
    });

    const result = await writeFileToGitHub(
        'pending_users.json',
        JSON.stringify(pending, null, 2),
        '提交注册申请 ' + username
    );
    if (!result.ok) {
        await deleteFileFromGitHub(`data_${username}.json.enc`, '清理未完成的注册数据');
        return { ok: false, reason: '提交注册申请失败: ' + result.reason };
    }

    return { ok: true, autoApproved: false };
}

// ===== 审批制：批准用户 =====
async function approveUser(username) {
    const pending = await readPendingUsers();
    const idx = pending.findIndex(u => u.username === username);
    if (idx === -1) return { ok: false, reason: '未找到待审批的申请' };
    const entry = pending[idx];

    const usersData = await readUsers();
    if (usersData.users[username]) return { ok: false, reason: '用户已存在' };

    usersData.users[username] = {
        displayName: entry.displayName,
        salt: entry.salt,
        hash: entry.hash
    };

    const writeOk = await writeFileToGitHub('users.json', JSON.stringify(usersData, null, 2), '批准用户 ' + username);
    if (!writeOk.ok) return { ok: false, reason: '写入 users.json 失败: ' + writeOk.reason };

    pending.splice(idx, 1);
    const pendingOk = await writeFileToGitHub('pending_users.json', JSON.stringify(pending, null, 2), '审批完成 ' + username);
    if (!pendingOk.ok) return { ok: false, reason: '更新待审批列表失败: ' + pendingOk.reason };

    return { ok: true, displayName: entry.displayName };
}

// ===== 审批制：拒绝用户 =====
async function rejectUser(username) {
    const pending = await readPendingUsers();
    const idx = pending.findIndex(u => u.username === username);
    if (idx === -1) return { ok: false, reason: '未找到待审批的申请' };

    pending.splice(idx, 1);
    const result = await writeFileToGitHub('pending_users.json', JSON.stringify(pending, null, 2), '拒绝注册 ' + username);
    if (!result.ok) return { ok: false, reason: '更新待审批列表失败' };

    await deleteFileFromGitHub(`data_${username}.json.enc`, '清理被拒绝的用户数据');
    return { ok: true };
}

// ===== 获取 Turnstile 站点密钥 =====
function getTurnstileSiteKey() {
    return CONFIG ? CONFIG.turnstileSiteKey : '0x4AAAAAADuhuj9OBQ-fmvWN';
}
