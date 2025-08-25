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

app.set('trust proxy', true);

mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/attendanceApp', {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('✅ MongoDB Connected'))
.catch(err => console.error('❌ MongoDB connection error:', err));

// Schemas
const userSchema = new mongoose.Schema({
  name: String,
  usn: String,
  password: String,
  role: { type: String, default: 'student' },
  deviceId: String,
  email: { type: String, required: true }  // 👈 add this
});


const attendanceSchema = new mongoose.Schema({
  usn: String,
  date: { type: String },
  status: { type: String, enum: ['present', 'absent', 'pending'], default: 'pending' },
  markedBy: { type: String, default: 'student' },   // student or admin
  approvalRequested: { type: Boolean, default: false },
  approvedByAdmin: { type: Boolean, default: false }
});


const campusSchema = new mongoose.Schema({
  latitude: Number,
  longitude: Number,
  radius: Number
});

const User = mongoose.model('User', userSchema);
const Attendance = mongoose.model('Attendance', attendanceSchema);
const Campus = mongoose.model('Campus', campusSchema);

app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER || 'shashistudy2125@gmail.com',
    pass: process.env.EMAIL_PASS || 'xweh opxh bcgi yhjr'
  }
});

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));

// Register
app.post('/api/register', async (req, res) => {
  const { name, usn, password, role, email } = req.body;
  if (!name || !usn || !password || !email) 
    return res.status(400).json({ error: "All fields required" });

  try {
    const existing = await User.findOne({ usn });
    if (existing) return res.status(400).json({ error: "USN already registered" });

    const newUser = new User({ name, usn, password, role: role || 'student', email });
    await newUser.save();
    res.json({ message: "✅ Registration successful, please login" });
  } catch (err) { 
    console.error(err); 
    res.status(500).json({ error: "Server error" }); 
  }
});

// Login with Device Lock
app.post('/api/login', async (req, res) => {
  const { usn, password, deviceId } = req.body;
  if (!usn || !password) return res.status(400).json({ error: 'USN and password required' });

  try {
    const user = await User.findOne({ usn });
    if (!user || user.password !== password) return res.status(400).json({ error: 'Invalid USN or password' });

    if (user.role !== 'admin') {
      if (!deviceId) return res.status(400).json({ error: 'Device ID required for students' });

      const otherUser = await User.findOne({ usn: { $ne: usn }, deviceId });
      if (otherUser) return res.status(403).json({ error: `Device registered to another student (${otherUser.usn})` });

      if (!user.deviceId) { user.deviceId = deviceId; await user.save(); }
      else if (user.deviceId !== deviceId) return res.status(403).json({ error: 'This account can only be accessed from the registered device.' });
    }

    const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token });
  } catch (err) { console.error(err); res.status(500).json({ error: 'Server error' }); }
});

// Auth middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'No token' });

  try { req.user = jwt.verify(authHeader.split(' ')[1], JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Invalid token' }); }
}

// Current user
app.get('/api/me', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });
  res.json({ name: me.name, usn: me.usn, role: me.role });
});

// GPS distance check
function isWithinRadius(lat1, lon1, lat2, lon2, radiusMeters) {
  const toRad = (v) => (v * Math.PI)/180;
  const R = 6371e3;
  const φ1 = toRad(lat1), φ2 = toRad(lat2);
  const Δφ = toRad(lat2 - lat1), Δλ = toRad(lon2 - lon1);
  const a = Math.sin(Δφ/2)**2 + Math.cos(φ1)*Math.cos(φ2)*Math.sin(Δλ/2)**2;
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
  const d = R * c;
  return d <= radiusMeters;
}

// Attendance marking
app.post('/api/attendance', authMiddleware, async (req, res) => {
  const allowedIPs = ['49.37.250.175','117.230.5.171','152.57.115.200','152.57.74.97','127.0.0.1','::1','117.230.0.0/16','152.57.0.0/16','49.37.0.0/16','119.161.0.0/16'];
  const clientIP = req.ip?.replace('::ffff:', '') || '';
  if (!ipRangeCheck(clientIP, allowedIPs)) return res.status(403).json({ error: 'Attendance only from campus Wi-Fi' });

  const { latitude, longitude, status } = req.body;
  if (!latitude || !longitude) return res.status(400).json({ error: 'GPS location required' });

  const campuses = await Campus.find({});
  const withinAnyCampus = campuses.some(c => isWithinRadius(latitude, longitude, c.latitude, c.longitude, c.radius));
  if (!withinAnyCampus) return res.status(403).json({ error: 'Attendance can only be marked inside campus area' });

  const me = await User.findById(req.user.id).lean();
  if (!me) return res.status(404).json({ error: 'User not found' });

  const today = new Date().toISOString().split("T")[0];
  const existing = await Attendance.findOne({ usn: me.usn, date: today });
  if (existing) return res.json({ message: 'Attendance already marked today' });

  await Attendance.create({ usn: me.usn, date: today, status, markedBy: "student" });
  res.json({ message: `Attendance marked as ${status}` });
});

// Admin today
app.get('/api/admin/today', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

  const today = new Date().toISOString().split("T")[0];
  const list = await Attendance.find({ date: today, status: 'present' });
  const sortedUsns = list.map(x=>x.usn).sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
  res.json({ total: sortedUsns.length, usns: sortedUsns });
});

// Admin reset
app.post('/api/admin/reset-all', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});
  try{
    await Attendance.deleteMany({});
    await User.updateMany({ role:'student' }, { $set:{ deviceId:null } });
    res.json({ message: '✅ All attendance records and student device IDs cleared.' });
  }catch(err){ console.error(err); res.status(500).json({error:'Server error during reset'}); }
});

// Admin send email
app.post('/api/admin/send-email', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

  const { email } = req.body;
  if(!email) return res.status(400).json({error:'Email required'});

  const today = new Date().toISOString().split("T")[0];
  const list = await Attendance.find({ date: today, status:'present' });
  const sortedUsns = list.map(x=>x.usn).sort((a,b)=>a.localeCompare(b,undefined,{numeric:true}));
  const total = sortedUsns.length;

  let rows = "";
  for(let i=0;i<sortedUsns.length;i+=2){
    rows += `<tr><td>${i+1}. ${sortedUsns[i]}</td><td>${sortedUsns[i+1]?i+2+". "+sortedUsns[i+1]:""}</td></tr>`;
  }

  const message = `<div style="font-family: Arial;padding:15px;background:#f9fafb;">
    <h2 style="text-align:center;">📘 Attendance Report</h2>
    <p><b>Date:</b> ${today}</p>
    <p><b>Total Present:</b> ${total}</p>
    <table style="border-collapse: collapse;width:80%;margin:auto;font-size:14px;">
      <thead><tr style="background:#2E86C1;color:white;"><th>USN ROW 1</th><th>USN ROW 2</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
  </div>`;

  try{
    await transporter.sendMail({ from: process.env.EMAIL_USER, to: email, subject:`Today's Attendance - ${today}`, html: message });
    res.json({ message: `✅ Attendance sent to ${email}` });
  }catch(err){ console.error(err); res.status(500).json({ error:'Failed to send email' }); }
});

// --- Admin: add new campus location ---
app.post('/api/admin/campus-location', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

  const { latitude, longitude, radius } = req.body;
  if(!latitude || !longitude || !radius) return res.status(400).json({error:'Latitude, longitude and radius required'});

  try {
    const campus = new Campus({ latitude, longitude, radius });
    await campus.save();
    res.json({ message:'✅ Campus location added' });
  } catch(err){ console.error(err); res.status(500).json({error:'Failed to save campus location'}); }
});

// --- Admin: get all campus locations ---
app.get('/api/admin/campus-locations', authMiddleware, async (req,res)=>{
  const me = await User.findById(req.user.id).lean();
  if(!me || me.role!=='admin') return res.status(403).json({error:'Access denied'});

  const locations = await Campus.find({});
  res.json(locations);
});

// --- Admin: delete a campus location ---
app.delete('/api/admin/campus-location/:id', authMiddleware, async (req, res) => {
    const me = await User.findById(req.user.id).lean();
    if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

    try {
        const id = req.params.id;
        await Campus.findByIdAndDelete(id);
        res.json({ message: '✅ Campus location removed' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to remove campus location' });
    }
});

// Student requests approval
app.post('/api/request-approval', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'student') return res.status(403).json({ error: 'Only students can request approval' });

  const today = new Date().toISOString().split("T")[0];

  // check if already marked
  const existing = await Attendance.findOne({ usn: me.usn, date: today });
  if (existing) return res.json({ message: 'Attendance already recorded today' });

  await Attendance.create({
    usn: me.usn,
    date: today,
    status: 'pending',
    approvalRequested: true
  });

  res.json({ message: 'Approval requested, wait for admin.' });
});

// Admin: get all pending approvals
// Admin: get all pending approvals (with student details)
app.get('/api/admin/pending-approvals', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const today = new Date().toISOString().split("T")[0];
  const requests = await Attendance.find({ date: today, status: 'pending', approvalRequested: true }).lean();

  // Attach student info (name + usn) from User collection
  const withStudentInfo = await Promise.all(requests.map(async (reqItem) => {
    const student = await User.findOne({ usn: reqItem.usn }).lean();
    return {
      ...reqItem,
      name: student ? student.name : "Unknown",
      usn: student ? student.usn : reqItem.usn
    };
  }));

  res.json(withStudentInfo);
});


// Admin: approve student
app.post('/api/admin/approve', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const { id } = req.body;
  const updated = await Attendance.findByIdAndUpdate(id, { 
    status: 'present', 
    approvedByAdmin: true, 
    markedBy: 'admin' 
  }, { new: true });

  if (!updated) return res.status(404).json({ error: 'Request not found' });

  // fetch student email
  const student = await User.findOne({ usn: updated.usn });
  if (student && student.email) {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: student.email,
      subject: "✅ Attendance Approved",
      html: `<p>Hi ${student.name},</p>
             <p>Your attendance for <b>${updated.date}</b> has been <span style="color:green">approved</span>.</p>
             <p>Regards,<br>Admin</p>`
    });
  }

  res.json({ message: '✅ Attendance approved and email sent' });
});

// Admin: reject student
app.post('/api/admin/reject', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'admin') return res.status(403).json({ error: 'Access denied' });

  const { id } = req.body;
  const updated = await Attendance.findByIdAndUpdate(id, { 
    status: 'absent', 
    approvedByAdmin: false, 
    markedBy: 'admin' 
  }, { new: true });

  if (!updated) return res.status(404).json({ error: 'Request not found' });

  // fetch student email
  const student = await User.findOne({ usn: updated.usn });
  if (student && student.email) {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: student.email,
      subject: "❌ Attendance Rejected",
      html: `<p>Hi ${student.name},</p>
             <p>Your attendance for <b>${updated.date}</b> has been <span style="color:red">rejected</span>.</p>
             <p>Regards,<br>Admin</p>`
    });
  }

  res.json({ message: '❌ Attendance rejected and email sent' });
});


const approvalSchema = new mongoose.Schema({
  studentName: String,
  studentId: String,
  date: { type: Date, default: Date.now },
  status: { type: String, enum: ["pending", "approved", "rejected"], default: "pending" }
});

const Approval = mongoose.model("Approval", approvalSchema);

// Alias for frontend: /api/attendance/request-approval
app.post('/api/attendance/request-approval', authMiddleware, async (req, res) => {
  const me = await User.findById(req.user.id).lean();
  if (!me || me.role !== 'student') return res.status(403).json({ error: 'Only students can request approval' });

  const today = new Date().toISOString().split("T")[0];

  // check if already marked
  const existing = await Attendance.findOne({ usn: me.usn, date: today });
  if (existing) return res.json({ message: 'Attendance already recorded today' });

  await Attendance.create({
    usn: me.usn,
    date: today,
    status: 'pending',
    approvalRequested: true
  });

  res.json({ message: 'Approval requested, wait for admin.' });
});


app.get("/api/attendance/approvals", async (req, res) => {
  try {
    const approvals = await Approval.find({ status: "pending" });
    res.json(approvals);
  } catch (err) {
    res.status(500).json({ success: false, message: "Error fetching approvals" });
  }
});

app.post("/api/attendance/update-approval", async (req, res) => {
  try {
    const { id, status } = req.body;
    await Approval.findByIdAndUpdate(id, { status });

    res.json({ success: true, message: "Approval updated" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Error updating approval" });
  }
});


const PORT = process.env.PORT || 5000;
app.listen(PORT, ()=>console.log(`🚀 Server running on port ${PORT}`));
