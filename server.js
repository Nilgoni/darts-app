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

// CORS für alle erlauben (lokal + online)
app.use(cors());

// Body Parser
app.use(bodyParser.json());

// Statische Dateien aus public servieren – das reicht für alle HTML-Dateien
app.use(express.static(path.join(__dirname, 'public')));

// Root-Route: Login-Seite laden
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// MongoDB Verbindung
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB verbunden!'))
  .catch(err => console.error('MongoDB Fehler:', err));

// Modelle
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

// API-Routen mit Logging

app.post('/make-admin', async (req, res) => {
  console.log('make-admin Anfrage:', req.body);
  try {
    const { username } = req.body;
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User nicht gefunden' });
    user.isAdmin = true;
    await user.save();
    res.json({ message: `${username} ist jetzt Admin` });
  } catch (err) {
    console.error('Fehler bei make-admin:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.post('/register', async (req, res) => {
  console.log('Registrierung Anfrage:', req.body);
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username und Passwort erforderlich' });
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Username existiert bereits' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    console.log('User erfolgreich erstellt:', username);
    res.status(201).json({ message: 'Registrierung erfolgreich' });
  } catch (err) {
    console.error('Fehler bei Registrierung:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.post('/login', async (req, res) => {
  console.log('Login Anfrage:', req.body);
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ error: 'Falscher Username oder Passwort' });
    }
    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
  } catch (err) {
    console.error('Fehler bei Login:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.get('/api/protected', authenticate, (req, res) => {
  res.json({ message: 'Willkommen auf der geschützten Seite!' });
});

app.get('/api/users', authenticate, async (req, res) => {
  console.log('api/users Anfrage von:', req.user.username);
  try {
    const users = await User.find({}, 'username _id');
    res.json(users);
  } catch (err) {
    console.error('Fehler bei /api/users:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.post('/api/spieltag/create', authenticate, async (req, res) => {
  console.log('spieltag/create Anfrage von:', req.user.username, req.body);
  const { teilnehmerIds, modus, runden, rundenTyp } = req.body;

  if (!teilnehmerIds || teilnehmerIds.length < 2) return res.status(400).json({ error: 'Mindestens 2 Teilnehmer erforderlich' });
  if (!['best_of', 'first_to'].includes(modus)) return res.status(400).json({ error: 'Ungültiger Modus' });
  if (![2, 3, 4, 5, 7].includes(runden)) return res.status(400).json({ error: 'Ungültige Runden-Anzahl' });
  if (!['hin', 'hin_rueck'].includes(rundenTyp)) return res.status(400).json({ error: 'Ungültiger Runden-Typ' });

  try {
    const spieltag = new Spieltag({
      ersteller: req.user._id,
      teilnehmer: teilnehmerIds,
      modus,
      runden,
      rundenTyp
    });
    await spieltag.save();

    let pairings = [];
    for (let i = 0; i < teilnehmerIds.length; i++) {
      for (let j = i + 1; j < teilnehmerIds.length; j++) {
        pairings.push({ spieler1: teilnehmerIds[i], spieler2: teilnehmerIds[j] });
        if (rundenTyp === 'hin_rueck') {
          pairings.push({ spieler1: teilnehmerIds[j], spieler2: teilnehmerIds[i] });
        }
      }
    }

    const matches = [];
    const lastPlayed = new Map(teilnehmerIds.map(id => [id.toString(), -1]));

    for (let round = 0; round < pairings.length; round++) {
      let available = pairings.filter(p => 
        !matches.some(m => 
          (m.spieler1.toString() === p.spieler1.toString() && m.spieler2.toString() === p.spieler2.toString()) ||
          (m.spieler1.toString() === p.spieler2.toString() && m.spieler2.toString() === p.spieler1.toString())
        )
      );

      if (available.length === 0) break;

      let candidates = available.map(pair => ({
        pair,
        maxWait: Math.max(round - lastPlayed.get(pair.spieler1.toString()), round - lastPlayed.get(pair.spieler2.toString()))
      }));

      const maxWait = Math.max(...candidates.map(c => c.maxWait));
      let best = candidates.filter(c => c.maxWait === maxWait);
      const chosen = best[Math.floor(Math.random() * best.length)].pair;

      const starter = (matches.length % 2 === 0) ? chosen.spieler1 : chosen.spieler2;

      const match = new Match({
        spieltag: spieltag._id,
        spieler1: chosen.spieler1,
        spieler2: chosen.spieler2,
        starter
      });
      await match.save();

      matches.push(match);
      spieltag.matches.push(match._id);

      lastPlayed.set(chosen.spieler1.toString(), round);
      lastPlayed.set(chosen.spieler2.toString(), round);
    }

    await spieltag.save();
    res.json({ message: 'Spieltag erfolgreich angelegt', spieltagId: spieltag._id });
  } catch (err) {
    console.error('Fehler bei Spieltag erstellen:', err);
    res.status(500).json({ error: 'Serverfehler beim Anlegen' });
  }
});

app.get('/api/spieltag/:id', authenticate, async (req, res) => {
  console.log('spieltag/:id Anfrage:', req.params.id);
  try {
    const spieltag = await Spieltag.findById(req.params.id)
      .populate('teilnehmer', 'username')
      .populate('matches');

    if (!spieltag) return res.status(404).json({ error: 'Spieltag nicht gefunden' });

    const populatedMatches = await Match.populate(spieltag.matches, [
      { path: 'spieler1', select: 'username' },
      { path: 'spieler2', select: 'username' },
      { path: 'starter', select: 'username' }
    ]);

    res.json({
      spieltag: {
        _id: spieltag._id,
        datum: spieltag.datum,
        modus: spieltag.modus,
        runden: spieltag.runden,
        rundenTyp: spieltag.rundenTyp,
        teilnehmer: spieltag.teilnehmer
      },
      matches: populatedMatches
    });
  } catch (err) {
    console.error('Fehler bei Spieltag laden:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.post('/api/match/update', authenticate, async (req, res) => {
  console.log('match/update Anfrage:', req.body);
  const { matchId, legs1, legs2 } = req.body;
  try {
    const match = await Match.findById(matchId);
    if (!match) return res.status(404).json({ error: 'Match nicht gefunden' });

    match.legsSpieler1 = legs1;
    match.legsSpieler2 = legs2;
    match.abgeschlossen = true;
    await match.save();

    res.json({ message: 'Ergebnis gespeichert' });
  } catch (err) {
    console.error('Fehler bei Match update:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

app.get('/api/tabelle/:spieltagId', authenticate, async (req, res) => {
  console.log('tabelle/:spieltagId Anfrage:', req.params.spieltagId);
  try {
    const currentSpieltag = await Spieltag.findById(req.params.spieltagId)
      .populate({
        path: 'matches',
        populate: [
          { path: 'spieler1', select: 'username' },
          { path: 'spieler2', select: 'username' }
        ]
      });

    const allMatches = await Match.find({ abgeschlossen: true })
      .populate('spieler1', 'username')
      .populate('spieler2', 'username')
      .populate('spieltag');

    const calcPoints = (legsWin, legsLose) => {
      if (legsWin > legsLose) return (legsWin - legsLose >= 2) ? 3 : 2;
      return 0;
    };

    const stats = new Map();

    const addMatchToStats = (match, isCurrentOnly = false) => {
      if (!match.abgeschlossen) return;

      const p1 = match.spieler1._id.toString();
      const p2 = match.spieler2._id.toString();

      if (!stats.has(p1)) stats.set(p1, { user: match.spieler1, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, currentOnly: { spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0 } });
      if (!stats.has(p2)) stats.set(p2, { user: match.spieler2, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, currentOnly: { spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0 } });

      const s1 = stats.get(p1);
      const s2 = stats.get(p2);

      s1.spiele += 1;
      s2.spiele += 1;
      s1.legsFor += match.legsSpieler1;
      s1.legsAgainst += match.legsSpieler2;
      s2.legsFor += match.legsSpieler2;
      s2.legsAgainst += match.legsSpieler1;

      if (match.legsSpieler1 > match.legsSpieler2) s1.punkte += calcPoints(match.legsSpieler1, match.legsSpieler2);
      else if (match.legsSpieler2 > match.legsSpieler1) s2.punkte += calcPoints(match.legsSpieler2, match.legsSpieler1);

      if (!isCurrentOnly) {
        s1.currentOnly.spiele += 1;
        s2.currentOnly.spiele += 1;
        s1.currentOnly.legsFor += match.legsSpieler1;
        s1.currentOnly.legsAgainst += match.legsSpieler2;
        s2.currentOnly.legsFor += match.legsSpieler2;
        s2.currentOnly.legsAgainst += match.legsSpieler1;

        if (match.legsSpieler1 > match.legsSpieler2) s1.currentOnly.punkte += calcPoints(match.legsSpieler1, match.legsSpieler2);
        else if (match.legsSpieler2 > match.legsSpieler1) s2.currentOnly.punkte += calcPoints(match.legsSpieler2, match.legsSpieler1);
      }
    };

    currentSpieltag.matches.forEach(m => addMatchToStats(m, true));
    allMatches.forEach(m => addMatchToStats(m));

    const makeTable = (data) => {
      return Array.from(stats.values())
        .map(s => ({
          username: s.user.username,
          spiele: data ? s.currentOnly.spiele : s.spiele,
          punkte: data ? s.currentOnly.punkte : s.punkte,
          legsFor: data ? s.currentOnly.legsFor : s.legsFor,
          legsAgainst: data ? s.currentOnly.legsAgainst : s.legsAgainst,
          diff: (data ? s.currentOnly.legsFor - s.currentOnly.legsAgainst : s.legsFor - s.legsAgainst)
        }))
        .sort((a, b) => b.punkte - a.punkte || b.diff - a.diff || b.legsFor - a.legsFor);
    };

    res.json({ current: makeTable(true), overall: makeTable(false) });
  } catch (err) {
    console.error('Fehler bei Tabelle:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});

// Server starten
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
