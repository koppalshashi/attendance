require('dotenv').config();

// server.js (with Admin Reset, Device Lock, IP Range & Email)
const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const ipRangeCheck = require("ip-range-check");
const nodemailer = require('nodemailer');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'mysupersecret';

// Enable trust proxy
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
  password: String,
  role: { type: String, default: 'student' },
  deviceId: String
});

const attendanceSchema = new mongoose.Schema({
  usn: String,
  date: { type: String },
  status: String,
  markedBy: { type: String, default: 'student' }
});

const User = mongoose.model('User', userSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);

// --- Middleware ---
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// --- Nodemailer setup ---
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'shashistudy2125@gmail.com',
    pass: process.env.EMAIL_PASS || 'xweh opxh bcgi yhjr' // Gmail App Password
  }
});

// --- Routes ---

// root -> login.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- Login with Device Lock ---
app.post('/api/login', async (req, res) => {
  const { usn, password, deviceId } = req.body;

  if (!usn || !password) return res.status(400).json({ error: 'USN and password required' });

  try {
    const user = await User.findOne({ usn });
    if (!user || user.password !== password) return res.status(400).json({ error: 'Invalid USN or password' });

    if (user.role !== 'admin') {
      if (!deviceId) return res.status(400).json({ error: 'Device ID required for students' });

      const otherUser = await User.findOne({ usn: { $ne: usn }, deviceId });
      if (otherUser) return res.status(403).json({ error: `This device is already registered to another student (${otherUser.usn}).` });

      if (!user.deviceId) {
        user.deviceId = deviceId;
        await user.save();
      } else if (user.deviceId !== deviceId) {
        return res.status(403).json({ error: 'This account can only be accessed from the registered device.' });
      }
    }

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
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

// --- Attendance marking ---
app.post('/api/attendance', authMiddleware, async (req, res) => {
  const allowedIPs = [
    '49.37.250.175', '117.230.5.171', '152.57.115.200', '152.57.74.97',
    '127.0.0.1', '::1',
    '117.230.0.0/16', '152.57.0.0/16', '49.37.0.0/16'
  ];

  let clientIP = req.ip?.replace('::ffff:', '') || '';
  console.log('📌 Client IP:', clientIP);

  if (!ipRangeCheck(clientIP, allowedIPs)) {
    console.log('❌ Blocked IP:', clientIP);
    return res.status(403).json({ error: 'Attendance can only be marked from campus Wi-Fi' });
  }

  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });

  const today = new Date().toISOString().split("T")[0];
  const existing = await Attendance.findOne({ usn: me.usn, date: today });
  if (existing) return res.json({ message: 'Attendance already marked today' });

  await Attendance.create({ usn: me.usn, date: today, status: req.body.status, markedBy: "student" });
  res.json({ message: `Attendance marked as ${req.body.status}` });
});

// --- Admin: view today’s attendance ---
app.get('/api/admin/today', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const today = new Date().toISOString().split("T")[0];
  const list = await Attendance.find({ date: today, status: 'present' });
  res.json({ total: list.length, usns: list.map(x => x.usn) });
});

// --- Admin: reset ALL attendance + device IDs ---
app.post('/api/admin/reset-all', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  try {
    await Attendance.deleteMany({});
    await User.updateMany({ role: 'student' }, { $set: { deviceId: null } });
    res.json({ message: '✅ All attendance records and student device IDs have been cleared.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error during reset' });
  }
});

// --- Admin: send today's attendance via email ---
app.post('/api/admin/send-email', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });

  const today = new Date().toISOString().split("T")[0];
  const list = await Attendance.find({ date: today, status: 'present' });

  const total = list.length;
  const usns = list.map(x => x.usn).join(', ') || 'No students present today';

  const mailOptions = {
    from: process.env.EMAIL_USER || 'youremail@gmail.com',
    to: email,
    subject: `Today's Attendance - ${today}`,
    text: `📅 Attendance Report\nTotal Present: ${total}\nUSNs: ${usns}`
  };

  try {
    await transporter.sendMail(mailOptions);
    res.json({ message: `✅ Attendance sent to ${email}` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// --- Start server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
