// server.js (final with IP restriction)
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'mysupersecret';

// Enable trust proxy for correct IP detection behind NAT/proxies
app.set('trust proxy', true);

// --- MongoDB Connection ---
mongoose.connect('mongodb://127.0.0.1:27017/attendanceApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('MongoDB Connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
  name: String,
  usn: String,
  password: String, // plain-text
  role: { type: String, default: 'student' }
});
const attendanceSchema = new mongoose.Schema({
  usn: String,
  date: { type: Date, default: Date.now },
  status: String
});

const User = mongoose.model('User', userSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// --- Routes ---

// root -> login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Login route
app.post('/api/login', async (req, res) => {
  try {
    const { usn, password } = req.body;
    console.log('Login attempt:', { usn, passwordProvided: !!password });

    if (!usn || !password) {
      return res.status(400).json({ error: 'USN and password required' });
    }

    const user = await User.findOne({ usn });

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (user.password !== password) {
      console.log(`Password mismatch for usn=${usn}`);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user._id, usn: user.usn, role: user.role, name: user.name },
      JWT_SECRET,
      { expiresIn: '1d' }
    );

    console.log(`Login success for usn=${usn}`);
    return res.json({ token, role: user.role, name: user.name, usn: user.usn });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Middleware to protect routes
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Get current user info
app.get('/api/me', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });
  res.json({ name: me.name, usn: me.usn, role: me.role });
});

// Mark attendance — IP restriction here
app.post('/api/attendance', authMiddleware, async (req, res) => {
  // Allowed public IPs (college Wi-Fi + localhost for testing)
  const allowedIPs = ['49.37.250.52', '124.0.0.1', '::1'];

  // Get client IP (normalize IPv4/IPv6)
  let clientIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  clientIP = clientIP.split(',')[0].replace('::ffff:', '').trim();

  console.log('Attendance marking request from IP:', clientIP);

  if (!allowedIPs.includes(clientIP)) {
    return res.status(403).json({ error: 'Attendance can only be marked from campus Wi-Fi' });
  }

  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const existing = await Attendance.findOne({ usn: me.usn, date: { $gte: today } });
  if (existing) return res.json({ message: 'Attendance already marked today' });

  await Attendance.create({ usn: me.usn, status: req.body.status });
  res.json({ message: 'Attendance marked' });
});

// Admin view
app.get('/api/admin/today', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const list = await Attendance.find({ date: { $gte: today }, status: 'present' });
  res.json({ total: list.length, usns: list.map(x => x.usn) });
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
