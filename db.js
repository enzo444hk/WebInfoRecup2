// db.js
const fs = require('fs');
const path = require('path');

const DATA_FILE = path.join(__dirname, 'data', 'db.json');

function loadDB() {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    
    if (!fs.existsSync(DATA_FILE)) return { users: [], events: [], captures: [], messages: [], visits: [], fingerprints: [] };
    try {
        return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    } catch {
        return { users: [], events: [], captures: [], messages: [], visits: [], fingerprints: [] };
    }
}

function saveDB(db) {
    const dir = path.dirname(DATA_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
}

module.exports = { loadDB, saveDB };
