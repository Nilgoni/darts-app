const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_123';

// CORS für alle erlauben
app.use(cors());

// Body Parser
app.use(bodyParser.json());

// Statische Dateien mit korrektem MIME-Type servieren
app.use(express.static(path.join(__dirname, 'public'), {
  extensions: ['html'],
  setHeaders: (res, path) => {
    if (path.endsWith('.html')) {
      res.setHeader('Content-Type', 'text/html');
    }
  }
}));

// Root-Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Root-Route: Login-Seite laden
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// MongoDB Verbindung
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB verbunden!'))
  .catch(err => console.error('MongoDB Fehler:', err));

// Modelle (wie vorher)
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  isAdmin: { type: Boolean, default: false }
});
const User = mongoose.model('User', userSchema);

const spieltagSchema = new mongoose.Schema({
  datum: { type: Date, default: Date.now },
  ersteller: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  teilnehmer: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  modus: { type: String, enum: ['best_of', 'first_to'], default: 'best_of' },
  runden: { type: Number, default: 3 },
  rundenTyp: { type: String, enum: ['hin', 'hin_rueck'], default: 'hin' },
  matches: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Match' }],
  abgeschlossen: { type: Boolean, default: false }
});
const Spieltag = mongoose.model('Spieltag', spieltagSchema);

const matchSchema = new mongoose.Schema({
  spieltag: { type: mongoose.Schema.Types.ObjectId, ref: 'Spieltag' },
  spieler1: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  spieler2: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  starter: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  legsSpieler1: { type: Number, default: 0 },
  legsSpieler2: { type: Number, default: 0 },
  abgeschlossen: { type: Boolean, default: false }
});
const Match = mongoose.model('Match', matchSchema);

// Auth Middleware
const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Kein Token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = await User.findOne({ username: decoded.username });
    if (!user) return res.status(401).json({ error: 'User nicht gefunden' });
    req.user = user;
    next();
  } catch (err) {
    res.status(403).json({ error: 'Ungültiger Token' });
  }
};

// Alle API-Routen (wie vorher – unverändert)
app.post('/make-admin', async (req, res) => { /* ... dein Code ... */ });
app.post('/register', async (req, res) => { /* ... dein Code ... */ });
app.post('/login', async (req, res) => { /* ... dein Code ... */ });
app.get('/api/protected', authenticate, (req, res) => { /* ... dein Code ... */ });
app.get('/api/users', authenticate, async (req, res) => { /* ... dein Code ... */ });
app.post('/api/spieltag/create', authenticate, async (req, res) => { /* ... dein Code ... */ });
app.get('/api/spieltag/:id', authenticate, async (req, res) => { /* ... dein Code ... */ });
app.post('/api/match/update', authenticate, async (req, res) => { /* ... dein Code ... */ });
app.get('/api/tabelle/:spieltagId', authenticate, async (req, res) => { /* ... dein Code ... */ });

// KEINE Wildcard-Route mehr – express.static reicht!

// Server starten
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
