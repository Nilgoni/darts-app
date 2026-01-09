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
app.use(cors());
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log('MongoDB verbunden!'))
  .catch(err => console.error('MongoDB Fehler:', err));
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
const strafeSchema = new mongoose.Schema({
  spieltag: { type: mongoose.Schema.Types.ObjectId, ref: 'Spieltag' },
  werfer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  typeId: { type: mongoose.Schema.Types.ObjectId, ref: 'StrafeType' },
  datum: { type: Date, default: Date.now }
});
const Strafe = mongoose.model('Strafe', strafeSchema);
const strafeTypeSchema = new mongoose.Schema({
  title: { type: String, required: true },
  whoPays: { type: String, enum: ['werfer', 'alle_anderen'], required: true },
  betrag: { type: Number, required: true }
});
const StrafeType = mongoose.model('StrafeType', strafeTypeSchema);
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
app.post('/make-admin', async (req, res) => {
  const { username } = req.body;
  try {
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
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username und Passwort erforderlich' });
  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ error: 'Username existiert bereits' });
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ username, password: hashedPassword });
    await newUser.save();
    res.status(201).json({ message: 'Registrierung erfolgreich' });
  } catch (err) {
    console.error('Fehler bei Registrierung:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
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
  try {
    const users = await User.find({}, 'username _id');
    res.json(users);
  } catch (err) {
    console.error('Fehler bei /api/users:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.post('/api/spieltag/create', authenticate, async (req, res) => {
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
          m.spieler1.toString() === p.spieler1.toString() && m.spieler2.toString() === p.spieler2.toString()
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
      const starter = chosen.spieler1;
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
app.post('/api/reset-all', authenticate, async (req, res) => {
  if (req.user.username !== 'Bernd') {
    return res.status(403).json({ error: 'Nur Bernd darf das ausführen' });
  }
  try {
    // Lösche alle Matches
    await Match.deleteMany({});
    // Lösche alle Spieltage
    await Spieltag.deleteMany({});
    // Lösche alle Strafen
    await Strafe.deleteMany({});
    res.json({ message: 'Alles zurückgesetzt!' });
  } catch (err) {
    console.error('Fehler beim Reset:', err);
    res.status(500).json({ error: 'Serverfehler beim Reset' });
  }
});
app.get('/api/spieltag/:id', authenticate, async (req, res) => {
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
        teilnehmer: spieltag.teilnehmer,
        abgeschlossen: spieltag.abgeschlossen
      },
      matches: populatedMatches
    });
  } catch (err) {
    console.error('Fehler bei Spieltag laden:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.post('/api/match/update', authenticate, async (req, res) => {
  const { matchId, legs1, legs2 } = req.body;
  try {
    const match = await Match.findById(matchId)
      .populate('spieler1')
      .populate('spieler2');
    if (!match) return res.status(404).json({ error: 'Match nicht gefunden' });
    const spieltag = await Spieltag.findById(match.spieltag);
    if (spieltag.abgeschlossen) return res.status(400).json({ error: 'Spieltag ist beendet – Ergebnisse nicht mehr änderbar' });
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
app.get('/api/user', authenticate, (req, res) => {
  res.json({ username: req.user.username, isAdmin: req.user.isAdmin });
});
app.post('/api/spieltag/:id/close', authenticate, async (req, res) => {
  try {
    const spieltag = await Spieltag.findById(req.params.id);
    if (!spieltag) return res.status(404).json({ error: 'Spieltag nicht gefunden' });
    if (spieltag.abgeschlossen) return res.status(400).json({ error: 'Spieltag bereits beendet' });
    spieltag.abgeschlossen = true;
    await spieltag.save();
    res.json({ message: 'Spieltag beendet' });
  } catch (err) {
    console.error('Fehler beim Beenden:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.post('/api/spieltag/:id/delete', authenticate, async (req, res) => {
  try {
    const spieltag = await Spieltag.findById(req.params.id);
    if (!spieltag) return res.status(404).json({ error: 'Spieltag nicht gefunden' });
    if (spieltag.abgeschlossen) return res.status(400).json({ error: 'Nur offene Spieltage können gelöscht werden' });
    // Lösche alle Matches des Spieltages
    await Match.deleteMany({ _id: { $in: spieltag.matches } });
    // Lösche alle Strafen des Spieltages
    await Strafe.deleteMany({ spieltag: spieltag._id });
    // Lösche den Spieltag
    await spieltag.deleteOne();
    res.json({ message: 'Spieltag gelöscht' });
  } catch (err) {
    console.error('Fehler beim Löschen:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.get('/api/spieltage', authenticate, async (req, res) => {
  try {
    const spieltage = await Spieltag.find({})
      .populate('ersteller', 'username')
      .populate('teilnehmer', 'username')
      .sort({ datum: -1 });
    res.json(spieltage);
  } catch (err) {
    console.error('Fehler bei /api/spieltage:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.post('/api/strafe/add', authenticate, async (req, res) => {
  const { spieltagId, werferId, typeId } = req.body;
  try {
    const strafe = new Strafe({
      spieltag: spieltagId,
      werfer: werferId,
      typeId
    });
    await strafe.save();
    res.json({ message: 'Strafe eingetragen', strafeId: strafe._id });
  } catch (err) {
    console.error('Fehler beim Hinzufügen der Strafe:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.delete('/api/strafe/:id', authenticate, async (req, res) => {
  try {
    await Strafe.findByIdAndDelete(req.params.id);
    res.json({ message: 'Strafe gelöscht' });
  } catch (err) {
    console.error('Fehler beim Löschen der Strafe:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.get('/api/strafetypes', authenticate, async (req, res) => {
  try {
    const types = await StrafeType.find({});
    res.json(types);
  } catch (err) {
    console.error('Fehler bei StrafeTypes laden:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.post('/api/strafetype/add', authenticate, async (req, res) => {
  const { title, whoPays, betrag } = req.body;
  try {
    const type = new StrafeType({ title, whoPays, betrag });
    await type.save();
    res.json({ message: 'StrafeType angelegt' });
  } catch (err) {
    console.error('Fehler beim Anlegen:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.put('/api/strafetype/:id', authenticate, async (req, res) => {
  const { title, whoPays, betrag } = req.body;
  try {
    await StrafeType.findByIdAndUpdate(req.params.id, { title, whoPays, betrag });
    res.json({ message: 'StrafeType geändert' });
  } catch (err) {
    console.error('Fehler beim Ändern:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.delete('/api/strafetype/:id', authenticate, async (req, res) => {
  try {
    await StrafeType.findByIdAndDelete(req.params.id);
    res.json({ message: 'StrafeType gelöscht' });
  } catch (err) {
    console.error('Fehler beim Löschen:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.get('/api/gesamtsumme', authenticate, async (req, res) => {
  try {
    const strafen = await Strafe.find({}).populate('spieltag').populate('typeId');
    let total = 0;
    for (const strafe of strafen) {
      const betrag = strafe.typeId.betrag;
      if (strafe.typeId.whoPays === 'werfer') {
        total += betrag;
      } else if (strafe.typeId.whoPays === 'alle_anderen') {
        const teilnehmerCount = strafe.spieltag ? strafe.spieltag.teilnehmer.length : 0;
        total += betrag * (teilnehmerCount - 1);
      }
    }
    res.json({ total });
  } catch (err) {
    console.error('Fehler bei Gesamtsumme:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.get('/api/overall-tabelle', authenticate, async (req, res) => {
  try {
    const closedSpieltage = await Spieltag.find({ abgeschlossen: true }).populate('teilnehmer');
    const closedIds = closedSpieltage.map(s => s._id);
    const allMatches = await Match.find({ abgeschlossen: true, spieltag: { $in: closedIds } })
      .populate('spieler1', 'username')
      .populate('spieler2', 'username');
    const allStrafen = await Strafe.find({ spieltag: { $in: closedIds } })
      .populate('werfer', 'username')
      .populate('typeId');

    const calcPoints = (legsWin, legsLose) => {
      if (legsWin > legsLose) return (legsWin - legsLose >= 2) ? 3 : 2;
      return 0;
    };

    const overallStats = new Map();

    allMatches.forEach(m => {
      const p1Id = m.spieler1._id.toString();
      const p2Id = m.spieler2._id.toString();
      const s1 = overallStats.get(p1Id) || { user: m.spieler1, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, strafen: 0 };
      const s2 = overallStats.get(p2Id) || { user: m.spieler2, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, strafen: 0 };
      s1.spiele += 1;
      s2.spiele += 1;
      s1.legsFor += m.legsSpieler1;
      s1.legsAgainst += m.legsSpieler2;
      s2.legsFor += m.legsSpieler2;
      s2.legsAgainst += m.legsSpieler1;
      if (m.legsSpieler1 > m.legsSpieler2) s1.punkte += calcPoints(m.legsSpieler1, m.legsSpieler2);
      else if (m.legsSpieler2 > m.legsSpieler1) s2.punkte += calcPoints(m.legsSpieler2, m.legsSpieler1);
      overallStats.set(p1Id, s1);
      overallStats.set(p2Id, s2);
    });

    allStrafen.forEach(s => {
      const werferId = s.werfer._id.toString();
      const betrag = s.typeId.betrag;
      const spieltag = closedSpieltage.find(sp => sp._id.equals(s.spieltag));
      if (spieltag) {
        if (s.typeId.whoPays === 'werfer') {
          const ws = overallStats.get(werferId) || { strafen: 0, user: s.werfer };
          ws.strafen += betrag;
          overallStats.set(werferId, ws);
        } else if (s.typeId.whoPays === 'alle_anderen') {
          spieltag.teilnehmer.forEach(t => {
            const tId = t._id.toString();
            if (tId !== werferId) {
              const ts = overallStats.get(tId) || { strafen: 0, user: t };
              ts.strafen += betrag;
              overallStats.set(tId, ts);
            }
          });
        }
      }
    });

    const makeTable = (statsMap) => {
      return Array.from(statsMap.values())
        .map(s => ({
          username: s.user.username,
          spiele: s.spiele,
          punkte: s.punkte,
          legsFor: s.legsFor,
          legsAgainst: s.legsAgainst,
          diff: s.legsFor - s.legsAgainst,
          strafen: s.strafen
        }))
        .sort((a, b) => b.punkte - a.punkte || b.diff - a.diff || b.legsFor - a.legsFor);
    };

    res.json(makeTable(overallStats));
  } catch (err) {
    console.error('Fehler bei Overall-Tabelle:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.get('/api/tabelle/:spieltagId', authenticate, async (req, res) => {
  try {
    const currentSpieltag = await Spieltag.findById(req.params.spieltagId)
      .populate('teilnehmer')
      .populate({
        path: 'matches',
        populate: [
          { path: 'spieler1', select: 'username' },
          { path: 'spieler2', select: 'username' }
        ]
      });
    if (!currentSpieltag) return res.status(404).json({ error: 'Spieltag nicht gefunden' });

    const closedSpieltage = await Spieltag.find({ abgeschlossen: true }).populate('teilnehmer');
    const closedIds = closedSpieltage.map(s => s._id);
    const allMatches = await Match.find({ abgeschlossen: true, spieltag: { $in: closedIds } })
      .populate('spieler1', 'username')
      .populate('spieler2', 'username');
    const allStrafen = await Strafe.find({ spieltag: { $in: closedIds } })
      .populate('werfer', 'username')
      .populate('typeId');
    const currentStrafen = await Strafe.find({ spieltag: req.params.spieltagId })
      .populate('werfer', 'username')
      .populate('typeId');

    const calcPoints = (legsWin, legsLose) => {
      if (legsWin > legsLose) return (legsWin - legsLose >= 2) ? 3 : 2;
      return 0;
    };

    const currentStats = new Map();
    currentSpieltag.teilnehmer.forEach(t => {
      currentStats.set(t._id.toString(), { user: t, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, strafen: 0 });
    });
    currentSpieltag.matches.forEach(m => {
      const p1Id = m.spieler1._id.toString();
      const p2Id = m.spieler2._id.toString();
      const s1 = currentStats.get(p1Id);
      const s2 = currentStats.get(p2Id);
      if (s1) s1.spiele += 1;
      if (s2) s2.spiele += 1;
      if (s1) s1.legsFor += m.legsSpieler1;
      if (s1) s1.legsAgainst += m.legsSpieler2;
      if (s2) s2.legsFor += m.legsSpieler2;
      if (s2) s2.legsAgainst += m.legsSpieler1;
      if (m.legsSpieler1 > m.legsSpieler2 && s1) s1.punkte += calcPoints(m.legsSpieler1, m.legsSpieler2);
      else if (m.legsSpieler2 > m.legsSpieler1 && s2) s2.punkte += calcPoints(m.legsSpieler2, m.legsSpieler1);
    });
    currentStrafen.forEach(s => {
      const werferId = s.werfer._id.toString();
      const betrag = s.typeId.betrag;
      if (s.typeId.whoPays === 'werfer') {
        const ws = currentStats.get(werferId);
        if (ws) ws.strafen += betrag;
      } else if (s.typeId.whoPays === 'alle_anderen') {
        currentSpieltag.teilnehmer.forEach(t => {
          const tId = t._id.toString();
          if (tId !== werferId) {
            const ts = currentStats.get(tId);
            if (ts) ts.strafen += betrag;
          }
        });
      }
    });

    const overallStats = new Map();
    allMatches.forEach(m => {
      const p1Id = m.spieler1._id.toString();
      const p2Id = m.spieler2._id.toString();
      const s1 = overallStats.get(p1Id) || { user: m.spieler1, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, strafen: 0 };
      const s2 = overallStats.get(p2Id) || { user: m.spieler2, spiele: 0, punkte: 0, legsFor: 0, legsAgainst: 0, strafen: 0 };
      s1.spiele += 1;
      s2.spiele += 1;
      s1.legsFor += m.legsSpieler1;
      s1.legsAgainst += m.legsSpieler2;
      s2.legsFor += m.legsSpieler2;
      s2.legsAgainst += m.legsSpieler1;
      if (m.legsSpieler1 > m.legsSpieler2) s1.punkte += calcPoints(m.legsSpieler1, m.legsSpieler2);
      else if (m.legsSpieler2 > m.legsSpieler1) s2.punkte += calcPoints(m.legsSpieler2, m.legsSpieler1);
      overallStats.set(p1Id, s1);
      overallStats.set(p2Id, s2);
    });
    allStrafen.forEach(s => {
      const werferId = s.werfer._id.toString();
      const betrag = s.typeId.betrag;
      const spieltag = closedSpieltage.find(sp => sp._id.equals(s.spieltag));
      if (spieltag) {
        if (s.typeId.whoPays === 'werfer') {
          const ws = overallStats.get(werferId) || { strafen: 0, user: s.werfer };
          ws.strafen += betrag;
          overallStats.set(werferId, ws);
        } else if (s.typeId.whoPays === 'alle_anderen') {
          spieltag.teilnehmer.forEach(t => {
            const tId = t._id.toString();
            if (tId !== werferId) {
              const ts = overallStats.get(tId) || { strafen: 0, user: t };
              ts.strafen += betrag;
              overallStats.set(tId, ts);
            }
          });
        }
      }
    });

    const makeTable = (statsMap) => {
      return Array.from(statsMap.values())
        .map(s => ({
          username: s.user.username,
          spiele: s.spiele,
          punkte: s.punkte,
          legsFor: s.legsFor,
          legsAgainst: s.legsAgainst,
          diff: s.legsFor - s.legsAgainst,
          strafen: s.strafen
        }))
        .sort((a, b) => b.punkte - a.punkte || b.diff - a.diff || b.legsFor - a.legsFor);
    };

    res.json({ current: makeTable(currentStats), overall: makeTable(overallStats) });
  } catch (err) {
    console.error('Fehler bei Tabelle:', err);
    res.status(500).json({ error: 'Serverfehler' });
  }
});
app.listen(PORT, () => {
  console.log(`Server läuft auf Port ${PORT}`);
});
