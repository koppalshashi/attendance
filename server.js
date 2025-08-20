require('dotenv').config();

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

// 🔹 Campus location schema
const campusSchema = new mongoose.Schema({
  latitude: Number,
  longitude: Number,
  radius: Number
});

const User = mongoose.model('User', userSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);
const Campus = mongoose.model('Campus', campusSchema);

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

// --- Root (Login page) ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// --- Register ---
app.post('/api/register', async (req, res) => {
  const { name, usn, password, role } = req.body;

  if (!name || !usn || !password) {
    return res.status(400).json({ error: "All fields required" });
  }

  try {
    const existing = await User.findOne({ usn });
    if (existing) return res.status(400).json({ error: "USN already registered" });

    const newUser = new User({ name, usn, password, role: role || 'student' });
    await newUser.save();
    res.json({ message: "✅ Registration successful, please login" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
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

// --- Helper: GPS distance check (Haversine) ---
function isWithinRadius(lat1, lon1, lat2, lon2, radiusMeters) {
  const toRad = (value) => (value * Math.PI) / 180;
  const R = 6371e3; 
  const φ1 = toRad(lat1);
  const φ2 = toRad(lat2);
  const Δφ = toRad(lat2 - lat1);
  const Δλ = toRad(lon2 - lon1);

  const a =
    Math.sin(Δφ / 2) ** 2 +
    Math.cos(φ1) * Math.cos(φ2) * Math.sin(Δλ / 2) ** 2;

  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  const d = R * c;
  return d <= radiusMeters;
}

// --- Attendance marking (IP + GPS) ---
app.post('/api/attendance', authMiddleware, async (req, res) => {
  const allowedIPs = [
    '49.37.250.175', '117.230.5.171', '152.57.115.200', '152.57.74.97',
    '127.0.0.1', '::1',
    '117.230.0.0/16', '152.57.0.0/16', '49.37.0.0/16','119.161.0.0/16'
  ];

  let clientIP = req.ip?.replace('::ffff:', '') || '';
  if (!ipRangeCheck(clientIP, allowedIPs)) {
    return res.status(403).json({ error: 'Attendance can only be marked from campus Wi-Fi' });
  }

  const { latitude, longitude, status } = req.body;
  if (!latitude || !longitude) return res.status(400).json({ error: 'GPS location required' });

  const campus = await Campus.findOne({});
  const campusLat = campus?.latitude || 15.36549;
  const campusLon = campus?.longitude || 75.12685;
  const allowedRadius = campus?.radius || 20;

  if (!isWithinRadius(latitude, longitude, campusLat, campusLon, allowedRadius)) {
    return res.status(403).json({ error: 'Attendance can only be marked inside campus area' });
  }

  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });

  const today = new Date().toISOString().split("T")[0];
  const existing = await Attendance.findOne({ usn: me.usn, date: today });
  if (existing) return res.json({ message: 'Attendance already marked today' });

  await Attendance.create({ usn: me.usn, date: today, status, markedBy: "student" });
  res.json({ message: `Attendance marked as ${status}` });
});

// --- Admin: view today’s attendance ---
app.get('/api/admin/today', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const today = new Date().toISOString().split("T")[0];
  const list = await Attendance.find({ date: today, status: 'present' });
  const sortedUsns = list.map(x => x.usn).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));

  res.json({ total: sortedUsns.length, usns: sortedUsns });
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
  const sortedUsns = list.map(x => x.usn).sort((a,b)=>a.localeCompare(b, undefined, {numeric:true}));
  const total = sortedUsns.length;

  let rows = "";
  for(let i=0;i<sortedUsns.length;i+=2){
    rows += `<tr>
      <td style="padding:6px; border:1px solid #ddd; text-align:center; color:#2C3E50;">${i+1}. ${sortedUsns[i]}</td>
      <td style="padding:6px; border:1px solid #ddd; text-align:center; color:#2C3E50;">${sortedUsns[i+1] ? i+2 + ". "+sortedUsns[i+1] : ""}</td>
    </tr>`;
  }

  const message = `
    <div style="font-family: Arial, sans-serif; padding: 15px; background: #f9fafb;">
      <h2 style="color: #2E86C1; text-align: center;">📘 Attendance Report</h2>
      <p><b>Date:</b> ${today}</p>
      <p style="color: #117A65;"><b>Total Present:</b> ${total}</p>
      <table style="border-collapse: collapse; width: 80%; margin: auto; font-size:14px;">
        <thead>
          <tr style="background: #2E86C1; color: white;">
            <th style="padding:6px; border:1px solid #ddd;">USN ROW 1</th>
            <th style="padding:6px; border:1px solid #ddd;">USN ROW 2</th>
          </tr>
        </thead>
        <tbody>
          ${rows}
        </tbody>
      </table>
      <p style="margin-top:15px; color:#7f8c8d; font-size:12px; text-align:center;">✅ Automated attendance report</p>
    </div>
  `;

  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER || 'youremail@gmail.com',
      to: email,
      subject: `Today's Attendance - ${today}`,
      html: message
    });
    res.json({ message: `✅ Attendance sent to ${email}` });
  } catch(err) {
    console.error(err);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// --- Admin: set/get campus location ---
app.post('/api/admin/campus-location', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

  const {latitude, longitude, radius} = req.body;
  if(!latitude || !longitude || !radius) return res.status(400).json({error:'Latitude, longitude and radius required'});

  try {
    let campus = await Campus.findOne({});
    if(!campus){
      campus = new Campus({latitude, longitude, radius});
    } else {
      campus.latitude = latitude;
      campus.longitude = longitude;
      campus.radius = radius;
    }
    await campus.save();
    res.json({message:'✅ Campus location updated'});
  } catch(err){
    console.error(err);
    res.status(500).json({error:'Failed to update campus location'});
  }
});

app.get('/api/admin/campus-location', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

  const campus = await Campus.findOne({});
  res.json(campus || {latitude:15.36549, longitude:75.12685, radius:20});
});

// --- Start server ---
const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
