const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  isAdmin: Boolean
});

const strafeTypeSchema = new mongoose.Schema({
  name: String,
  betrag: Number,
  whoPays: { type: String, enum: ['werfer', 'alle_anderen'] }
});

const spieltagSchema = new mongoose.Schema({
  datum: Date,
  teilnehmer: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  ergebnisse: [{
    spieler: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    punkte: Number,
    legs: { gewonnene: Number, verlorene: Number }
  }],
  abgeschlossen: { type: Boolean, default: false }
});

const strafeSchema = new mongoose.Schema({
  type: { type: mongoose.Schema.Types.ObjectId, ref: 'StrafeType' },
  werfer: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  spieltag: { type: mongoose.Schema.Types.ObjectId, ref: 'Spieltag' }
});

const User = mongoose.model('User', userSchema);
const StrafeType = mongoose.model('StrafeType', strafeTypeSchema);
const Spieltag = mongoose.model('Spieltag', spieltagSchema);
const Strafe = mongoose.model('Strafe', strafeSchema);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

const authenticateToken = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.redirect('/');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.redirect('/');
    req.user = user;
    next();
  });
};

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/register', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

app.get('/spieltag-create', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'spieltag-create.html'));
});

app.get('/spieltag-view/:id', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'spieltag-view.html'));
});

app.get('/strafen-manage', authenticateToken, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'strafen-manage.html'));
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashedPassword, isAdmin: false });
  await user.save();
  res.redirect('/');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.redirect('/');
  }
  const token = jwt.sign({ username: user.username, isAdmin: user.isAdmin }, process.env.JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.redirect('/dashboard');
});

app.get('/logout', (req, res) => {
  res.clearCookie('token');
  res.redirect('/');
});

app.get('/api/users', authenticateToken, async (req, res) => {
  res.json(await User.find());
});

app.get('/api/spieltage', authenticateToken, async (req, res) => {
  res.json(await Spieltag.find().populate('teilnehmer').sort({ datum: -1 }));
});

app.get('/api/spieltag/:id', authenticateToken, async (req, res) => {
  res.json(await Spieltag.findById(req.params.id).populate('teilnehmer').populate('ergebnisse.spieler'));
});

app.post('/api/spieltag', authenticateToken, async (req, res) => {
  const { datum, teilnehmer } = req.body;
  const spieltag = new Spieltag({ datum, teilnehmer });
  await spieltag.save();
  res.json(spieltag);
});

app.put('/api/spieltag/:id', authenticateToken, async (req, res) => {
  const { ergebnisse, abgeschlossen } = req.body;
  const spieltag = await Spieltag.findById(req.params.id);
  spieltag.ergebnisse = ergebnisse;
  spieltag.abgeschlossen = abgeschlossen;
  await spieltag.save();
  res.json(spieltag);
});

app.delete('/api/spieltag/:id', authenticateToken, async (req, res) => {
  await Spieltag.findByIdAndDelete(req.params.id);
  res.sendStatus(200);
});

app.get('/api/strafentypes', authenticateToken, async (req, res) => {
  res.json(await StrafeType.find());
});

app.post('/api/strafentype', authenticateToken, async (req, res) => {
  const { name, betrag, whoPays } = req.body;
  const type = new StrafeType({ name, betrag, whoPays });
  await type.save();
  res.json(type);
});

app.delete('/api/strafentype/:id', authenticateToken, async (req, res) => {
  await StrafeType.findByIdAndDelete(req.params.id);
  res.sendStatus(200);
});

app.get('/api/strafen', authenticateToken, async (req, res) => {
  res.json(await Strafe.find()
    .populate('type')
    .populate('werfer')
    .populate({
      path: 'spieltag',
      populate: { path: 'teilnehmer' }
    }));
});

app.post('/api/strafe', authenticateToken, async (req, res) => {
  const { type, werfer, spieltag } = req.body;
  const strafe = new Strafe({ type, werfer, spieltag });
  await strafe.save();
  res.json(strafe);
});

app.post('/api/reset-all', authenticateToken, async (req, res) => {
  await Strafe.deleteMany({});
  await Spieltag.deleteMany({});
  res.sendStatus(200);
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
