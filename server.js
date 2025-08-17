// server.js (Render + Local Friendly + Device Lock with Admin Exemption)
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'mysupersecret';

// Enable trust proxy (important for Render / proxies)
app.set('trust proxy', true);

// --- MongoDB Connection ---
mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/attendanceApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// --- Mongoose Schemas ---
const userSchema = new mongoose.Schema({
  name: String,
  usn: String,
  password: String, // plain-text (hash later for security)
  role: { type: String, default: 'student' },
  deviceId: String
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
app.use(express.static('public')); // serve login.html, attendance.html, css, js

// --- Routes ---

// root -> login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- Login with Device Lock ---
app.post('/api/login', async (req, res) => {
  const { usn, password, deviceId } = req.body;

  if (!usn || !password) {
    return res.status(400).json({ error: 'USN and password required' });
  }

  try {
    const user = await User.findOne({ usn });
    if (!user) return res.status(400).json({ error: 'Invalid USN or password' });
    if (user.password !== password) return res.status(400).json({ error: 'Invalid USN or password' });

    // ✅ Device lock only for students
    if (user.role !== 'admin') {
      if (!deviceId) return res.status(400).json({ error: 'Device ID required for students' });

      if (!user.deviceId) {
        user.deviceId = deviceId;
        await user.save();
      } else if (user.deviceId !== deviceId) {
        return res.status(403).json({ error: 'This account can only be accessed from the registered device.' });
      }

      // Prevent same device used by another student
      const otherUser = await User.findOne({ usn: { $ne: usn }, deviceId });
      if (otherUser) {
        return res.status(403).json({ error: 'This device is already registered to another student.' });
      }
    }

    // ✅ Create JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET || JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// --- Auth middleware ---
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// --- Current user info ---
app.get('/api/me', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });

  res.json({ name: me.name, usn: me.usn, role: me.role });
});

// --- Attendance marking (with IP restriction + one per day) ---
app.post('/api/attendance', authMiddleware, async (req, res) => {
  const allowedIPs = ['49.37.250.172', '117.230.5.171', '152.57.115.200', '127.0.0.1', '::1'];

  let clientIP = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress || '';
  clientIP = clientIP.replace('::ffff:', '').trim();
  console.log('📌 Client IP:', clientIP);

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
  res.json({ message: `Attendance marked as ${req.body.status}` });
});

// --- Admin: view today’s attendance ---
app.get('/api/admin/today', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const today = new Date();
  today.setHours(0, 0, 0, 0);

  const list = await Attendance.find({ date: { $gte: today }, status: 'present' });
  res.json({ total: list.length, usns: list.map(x => x.usn) });
});

// --- Start server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

