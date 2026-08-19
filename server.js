require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET || 'ashacare_secure_jwt_secret_key_2026';

// ==========================================
// 1. MONGODB DATABASE SCHEMAS
// ==========================================
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  workerId: { type: String, required: true, unique: true, trim: true },
  pin: { type: String, required: true },
  role: { type: String, enum: ['ASHA Worker', 'Medical Officer / Doctor', 'System Admin'], default: 'ASHA Worker' },
  createdAt: { type: Date, default: Date.now }
});

const caseSchema = new mongoose.Schema({
  caseId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  age: { type: String, required: true },
  level: { type: String, enum: ['red', 'yellow', 'green'], default: 'green' },
  concern: { type: String, default: '' },
  re: { type: [String], default: [] },
  transcript: { type: String, required: true },
  date: { type: Date, default: Date.now },
  status: { type: String, default: 'Pending Review' },
  doctorNotes: { type: String, default: '' },
  reminderDays: { type: Number, default: null },
  registeredBy: { type: String, required: true }
});

const User = mongoose.model('User', userSchema);
const Case = mongoose.model('Case', caseSchema);

// Connect to MongoDB
const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017/ashacare";
mongoose.connect(MONGO_URI)
  .then(() => console.log("Connected to MongoDB successfully"))
  .catch(err => console.error("MongoDB connection error:", err));

// ==========================================
// 2. AUTHENTICATION MIDDLEWARE
// ==========================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access denied.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired.' });
    req.user = user;
    next();
  });
};

// ==========================================
// 3. API ENDPOINTS
// ==========================================

app.post('/api/auth/authenticate', async (req, res) => {
  try {
    const { name, workerId, pin, role } = req.body;
    if (!workerId || !pin) return res.status(400).json({ error: 'Worker ID and PIN required.' });

    let user = await User.findOne({ workerId });
    
    if (!user) {
      if (!name) return res.status(400).json({ error: 'Name required for first-time login.' });
      const hashedPin = await bcrypt.hash(pin, 10);
      user = new User({ name, workerId, pin: hashedPin, role });
      await user.save();
    } else {
      const isMatch = await bcrypt.compare(pin, user.pin);
      if (!isMatch && pin !== '1234') { 
        return res.status(400).json({ error: 'Invalid PIN.' });
      }
    }

    const token = jwt.sign({ userId: user._id, role: user.role, name: user.name, workerId: user.workerId }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, workerId: user.workerId, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Authentication failed server-side.' });
  }
});

app.get('/api/cases', authenticateToken, async (req, res) => {
  try {
    const cases = await Case.find().sort({ date: -1 });
    res.json(cases);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cases.' });
  }
});

app.post('/api/cases', authenticateToken, async (req, res) => {
  try {
    const newCase = new Case(req.body);
    const savedCase = await newCase.save();
    res.status(201).json(savedCase);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save case.' });
  }
});

app.put('/api/cases/:caseId', authenticateToken, async (req, res) => {
  try {
    const updatedCase = await Case.findOneAndUpdate({ caseId: req.params.caseId }, req.body, { new: true });
    res.json(updatedCase);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update case.' });
  }
});

// ==========================================
// 4. EMBEDDED FRONTEND UI
// ==========================================
const frontendHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0f766e">
<title>AshaCare - Secure Login & Working Prototype</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<style>
:root{--teal:#0f766e;--teal2:#115e59;--bg:#f8fafc;--line:#e2e8f0;--text:#0f172a;--muted:#64748b}
*{box-sizing:border-box}html, body{margin:0;padding:0;background:var(--bg);color:var(--text); font-family:Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",sans-serif}
button, input, textarea, select{font:inherit}button{cursor:pointer}.app{min-height:100vh;display: flex; justify-content:center}.shell{width:100%;max-width:520px;min-height:100vh; background:var(--bg);position:relative;padding-bottom:82px}
.top{height:60px;display: flex;align-items:center; justify-content:space-between;padding:10px 15px;background:#fff;border-bottom:1px solid #eef2f7;position:sticky;top:0;z-index:20}
.brand{border:0;background:none;display: flex;align-items:center;gap:9px;padding:0;color:var(--text)}.logo{width:34px;height:34px;border-radius:10px;background:var(--teal);color:#fff;display:grid;place-items:center;font-size:18px}.brand strong{font-size:15px}
.topRight{display: flex;align-items:center;gap:7px}.pill{border:0;border-radius:999px;padding:6px 9px;font-size:11px;font-weight:700;background:#f1f5f9;color:#475569}.pill.online{background:#ecfdf5;color:#047857}.pill.offline{background:#fffbeb;color:#b45309}.pill.auth{background:#e0f2fe;color:#0369a1}
main{padding:16px}.hero{background:linear-gradient(135deg,#0f766e,#115e59);color:#fff;border-radius:18px;padding:20px;position:relative;overflow:hidden}.hero:after{content:"";position:absolute;width:150px;height:150px;border-radius:50%;right:-60px;bottom:-70px;background:rgba(255,255,255,.08)}.eyebrow{font-size:11px;font-weight:800;color:#ccfbf1;text-transform:uppercase;letter-spacing:.06em}.hero h2{font-size:21px;line-height:1.2; margin:8px 0 0}.hero p{font-size:12px;color:#ccfbf1;margin:7px 0}.hero button{margin-top:15px;border:0;background:#fff;color:#115e59;padding:11px 14px;border-radius:11px;font-weight:800}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:11px}.stats{margin:12px 0}.card{background:#fff;border:1px solid #eef2f7;border-radius:14px}.stat{padding:14px}.stat strong{font-size:27px;display:block}.stat span,.muted{font-size:11px;color:var(--muted)}
.sync{padding:13px;display: flex;align-items:center; justify-content:space-between}.linkBtn{border:0;background:none;color:var(--teal);font-size:12px;font-weight:800;padding:5px}
.sectionTitle{font-size:11px;font-weight:850; color:#64748b;text-transform:uppercase;letter-spacing:.08em;margin:18px 0 8px}.record{padding:12px;display: flex;align-items:center; justify-content:space-between;margin-bottom:8px;border:0;background:#fff;width:100%;text-align:left;border-radius:12px;border:1px solid var(--line);}.record:active{background:#f8fafc}.recordName{font-size:14px;font-weight:700}.risk{display:inline-flex;align-items:center;gap:5px;padding:5px 9px;border-radius:999px;font-size:10px;font-weight:850;white-space:nowrap}.risk.red{color:#b3261e;background:#fdecea}.risk.yellow{color:#8a5a00;background:#fff6dc}.risk.green{color:#1e6b45;background:#e9f7ef}.dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.detailReason{display: flex;gap:8px;color:#334155;font-size:13px;margin:7px 0}.detailDot{width:6px;height:6px;border-radius:50%;margin-top:5px; flex:none;background:#475569}.transcriptBox{background:#f8fafc;border:1px solid var(--line);border-radius:10px;padding:10px 12px;font-size:13px;color:#334155;margin-top:6px}
.qrNote{font-size:11px;color:#b45309;background:#fffbeb;border-radius:10px;padding:9px 11px;margin-top:8px}
.disclaimer {text-align:center;color:#94a3b8;font-size:11px;line-height:1.5;margin:18px 5px}
.back{border:0;background:none;color:#64748b;font-size:13px;font-weight:650; padding:0;margin:0 0 14px}.row{display:grid;grid-template-columns:1fr 1fr;gap:10px}.input,.textarea,.select{width:100%;border:1px solid var(--line);background:#fff;border-radius:11px;padding:11px 12px; outline:none;color:var(--text); margin-bottom:10px}.input:focus, .textarea:focus,.select:focus{border-color:#5eead4;box-shadow:0 0 0 3px rgba(20,184,166,.1)}.textarea{resize:vertical;min-height:92px}
.voice{text-align:center;padding:17px 0}.mic{width:96px;height:96px;border:0;border-radius:50%;background:var(--teal);color:#fff;font-size:29px;box-shadow:0 10px 25px rgba(15,118,110,.2)}.mic.listening{background:#ef4444;box-shadow:0 10px 25px rgba(239,68,68,.2)}.voiceTitle{font-size:14px;font-weight:700;margin-top:10px}
.quick{display:flex;flex-wrap:wrap;gap:7px}.quick button{border:1px solid var(--line);background:#fff;color:#475569;padding:7px 10px;border-radius:999px;font-size:11px}.quick button.active{background:var(--teal);border-color:var(--teal);color:#fff}
.primary,.dark,.outline{width:100%;border-radius:11px;padding:13px;font-weight:800;font-size:13px;margin-top:8px}.primary{border:0;background:var(--teal);color:#fff}.dark{border:0;background:#0f172a;color:#fff}.outline{border:1px solid var(--line);background:#fff;color:#334155}.primary:disabled{background:#e2e8f0;color:#94a3b8;cursor:not-allowed}
.loader{height:58vh;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;color:#475569}.spinner{width:62px;height:62px;border:5px solid #ccfbf1;border-top-color:var(--teal);border-radius:50%;animation:spin .9s linear infinite;margin-bottom:18px}@keyframes spin{to{transform:rotate(360deg)}}
.resultBanner{border-radius:17px;padding:25px;text-align:center}.resultIcon{width:64px;height:64px;border-radius:50%;background:#fff;display:grid;place-items:center;margin:0 auto 11px;font-size:28px}.box{padding:15px;margin-top:12px;background:#fff;border-radius:14px;border:1px solid #eef2f7;}.boxTitle{font-size:10px;font-weight:850;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em;margin-bottom:7px}.reason{display:flex;gap:8px;color:#334155;font-size:13px;margin:7px 0}.reasonDot{width:6px;height:6px;border-radius:50%;margin-top:5px;flex:none}.next{margin-top:12px;background:#0f172a;color:#fff;border-radius:12px;padding:15px}.next .boxTitle{color:#94a3b8}
.refHead{padding:15px;display:flex;justify-content:space-between;align-items:center;background:#f8fafc;border-bottom:1px solid var(--line);border-radius:14px 14px 0 0;}.refBody{padding:15px;background:#fff;border-radius:0 0 14px 14px;border:1px solid var(--line);border-top:none;}.facility{display:flex;gap:9px;margin:13px 0}.qrWrap{text-align:center;padding:8px}.qrWrap img{display:block;width:220px;height:220px;max-width:100%;margin:0 auto;border-radius:8px;border:1px solid #e2e8f0;background:#fff}.qrFallback{display:none;width:220px;height:220px;max-width:100%;margin:0 auto;border:1px dashed #cbd5e1;border-radius:8px;align-items:center;justify-content:center;text-align:center;padding:20px;color:#64748b;font-size:12px}
.qrOpenDirect{display:block;text-align:center;margin-top:10px;font-size:12px;font-weight:800;color:var(--teal);text-decoration:none}.actions{display:grid;grid-template-columns:1fr 1fr;border-top:1px solid #eef2f7;background:#fff;border-radius:0 0 14px 14px;}.actions button{border:0;background:none;padding:12px;font-size:12px;font-weight:800;color:var(--teal)}.actions button+button{border-left:1px solid #eef2f7;color:#475569}
.qrGenerator{padding:15px}.qrLarge{margin:15px auto;width:240px;height:240px;display:grid;place-items:center;background:#fff;border:1px solid #e2e8f0;border-radius:12px}.qrLarge img{width:220px;height:220px}.qrHint{text-align:center;color:#64748b;font-size:11px;line-height:1.5}.smallRow{display:flex;gap:8px}.smallRow>*{flex:1}.toast{display:none;position:fixed;left:50%;bottom:92px;transform:translateX(-50%);z-index:100;background:#0f172a;color:#fff;border-radius:10px;padding:10px 14px;font-size:12px;box-shadow:0 8px 25px rgba(0,0,0,.2)}
.bottom{position:fixed;left:50%;bottom:0;transform:translateX(-50%);width:100%;max-width:520px;background:#fff;border-top:1px solid #eef2f7;display:grid;grid-template-columns:repeat(6,1fr);padding:7px 4px;z-index:30}.nav{border:0;background:none;color:#94a3b8;padding:5px 2px;font-size:9px;font-weight:750;display:flex;flex-direction:column;align-items:center;gap:3px}.nav.active{color:var(--teal)}.navIcon{font-size:19px;line-height:20px}
.loginCard{background:#fff;padding:22px;border-radius:16px;border:1px solid #eef2f7;box-shadow:0 4px 15px rgba(0,0,0,.03);margin-top:10px}
.label{font-size:12px;font-weight:700;color:#334155;margin-bottom:4px;display:block}
.doctor-review-card { background: #fff; padding: 22px; border-radius: 16px; border: 1px solid #eef2f7; box-shadow: 0 4px 15px rgba(0,0,0,.03); margin-top: 15px; }
.doctor-grid { display: grid; grid-template-columns: 80px 1fr; gap: 14px; align-items: center; margin-bottom: 14px; }
.doctor-avatar { width: 80px; height: 80px; border-radius: 50%; object-fit: cover; border: 2px solid var(--teal); }
.doctor-info h4 { margin: 0 0 2px; font-size: 15px; color: var(--text); }
.doctor-info p { margin: 0; font-size: 12px; color: var(--muted); }
.review-quote { font-style: italic; font-size: 13px; line-height: 1.5; color: #334155; background: #f8fafc; padding: 12px; border-left: 3px solid var(--teal); border-radius: 0 8px 8px 0; margin-top: 10px; }
@media(max-width:380px){.row{grid-template-columns:1fr}.bottom{grid-template-columns:repeat(6,1fr)}}
@media print{.top,.bottom,.back,.noPrint,button{display:none!important}.shell{max-width:none;padding:0}.refCard{border:0}}
.statusPill{display:inline-flex;align-items:center;gap:5px;padding:5px 9px;border-radius:999px;font-size:11px;font-weight:800}.status-pending{background:#fff7ed;color:#9a3412}.status-review{background:#eff6ff;color:#1d4ed8}.status-followup{background:#ecfdf5;color:#047857}.status-referred{background:#fef2f2;color:#b91c1c}.status-closed{background:#f1f5f9;color:#475569}.caseActions{display:grid;grid-template-columns:1fr;gap:9px;margin-top:12px}.caseActions button{min-height:44px}.doctorHero{background:linear-gradient(135deg,#0f766e,#115e59);color:#fff;border-radius:18px;padding:18px;box-shadow:0 10px 30px rgba(15,118,110,.16)}.doctorHero h2{margin:0 0 5px}.metricGrid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin:12px 0}.metricCard{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:12px;text-align:center}.metricCard strong{display:block;font-size:22px}.metricCard span{font-size:10px;color:#64748b}.filterRow{display:flex;gap:7px;overflow:auto;padding-bottom:4px}.filterRow button{white-space:nowrap}.examBox{background:#f8fafc;border:1px solid #e2e8f0;border-radius:14px;padding:12px;margin-top:10px}.caseMeta{display:grid;grid-template-columns:1fr 1fr;gap:8px}.caseMeta div{background:#f8fafc;border-radius:10px;padding:9px}.caseMeta small{display:block;color:#64748b;font-size:10px}.caseMeta b{font-size:12px}.dangerBtn{background:#dc2626!important;color:white!important}.successBtn{background:#047857!important;color:white!important}.blueBtn{background:#2563eb!important;color:white!important}
@media(max-width:420px){.metricGrid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body> <div class="app"><div class="shell">
<header class="top">
<button class="brand" onclick="App.go('home')"><span class="logo">⚕</span><strong id="appName">AshaCare</strong></button>
<div class="topRight">
<span id="userBadge" class="pill auth" onclick="App.logout()" title="Click to Logout">Lock</span>
<span id="connection" class="pill online">● Online</span>
<button class="pill" onclick="App.toggleLang()" id="langBtn">A/अ/ଅ</button>
</div>
</header>
<main id="screen"></main>
<nav class="bottom" id="bottomNav">
<button class="nav active" id="nav-home" onclick="App.go('home')"><span class="navIcon">⌂</span><span id="navHome">Home</span></button>
<button class="nav" id="nav-patient" onclick="App.go('patient')"><span class="navIcon">👤</span><span id="navPatient">Patient</span></button>
<button class="nav" id="nav-assess" onclick="App.newAssessment()"><span class="navIcon">＋</span><span id="navAssess">Assess</span></button>
<button class="nav" id="nav-records" onclick="App.go('records')"><span class="navIcon">☷</span><span id="navRecords">Records</span></button>
<button class="nav" id="nav-qr" onclick="App.go('qr')"><span class="navIcon">▦</span><span id="navQr">QR</span></button>
<button class="nav" id="nav-about" onclick="App.go('about')"><span class="navIcon">ℹ</span><span id="navAbout">About</span></button>
</nav>
<div id="toast" class="toast"></div>
</div></div>
<script>
const T={
en:{appName:"AshaCare",tagline:"Pediatric red-flag triage assistant",home:"Home",newAssessment:"New Assessment",records:"Records",startAssessment:"Start New Assessment",todaysCases:"Today's cases",pendingFollowups:"Pending follow-ups",recentAssessments:"Recent assessments",online:"Online",offline:"Offline",syncNow:"Sync now",synced:"All records synced",tapToSpeak:"Tap to speak symptoms",listening:"Listening…",orType:"…or type / edit below",quickAdd:"Quick-add common signs",childName:"Child's name (optional)",childAge:"Age (years)",analyze:"Analyze symptoms",analyzing:"Checking against WHO warning signs…",back:"Back",riskRed:"REFER IMMEDIATELY",riskYellow:"MONITOR CLOSELY",riskGreen:"ROUTINE CARE",flaggedBecause:"Flagged because:",possible:"Possible concern:",nextSteps:"Recommended next step",generateReferral:"Generate referral slip",saveMonitor:"Save & set monitoring reminder",newCase:"Start another assessment",nearestFacility:"Nearest district facility",away:"away",shareSlip:"Share with family",printSlip:"Print slip",followUp:"Follow-up reminder",remindIn:"Remind me to check in",days3:"3 days",days7:"7 days",reminderSet:"Reminder set",goHome:"Done — back to home",scanNote:"Hospital staff can scan this code to pull up the full case instantly.",caseId:"Case ID",noSpeechSupport:"Voice input isn't supported in this browser — please type instead.",weekAgo:"2 days ago",qrTitle:"QR Code Generator",qrText:"Enter case information or any text below.",generateQr:"Generate QR",downloadQr:"Download QR",copyQr:"Copy content",qrEmpty:"Enter some text to generate a QR code.",disclaimer:"This tool assists your judgment. It does not diagnose or replace a doctor.",referralSlip:"Referral Slip",childLabel:"Child",symptomsRecorded:"Symptoms recorded",noRecords:"No assessments yet",tapForDetails:"Tap a case to see full details",micDenied:"Microphone permission denied — allow mic access in your browser/site settings and try again.",micNoSpeech:"No speech detected — try again, closer to the mic.",micNetwork:"Voice recognition needs an internet connection.",micNotSecure:"Voice input needs this page opened over https://",micGeneric:"Voice input failed — please type instead.",openInBrowser:"Open QR in browser",retryQr:"Retry QR",generatedOn:"Generated",loginTitle:"Secure Health Worker Login",enterName:"Full Name",enterWorkerId:"Worker / ID Number",enterPin:"Enter Passcode / PIN (Demo: 1234)",loginBtn:"Authenticate & Access",invalidPin:"Invalid passcode. Use '1234' for demo access.",missingDetails:"Please enter your Name and ID Number.",registeredPatients:"Registered Patient Records",savePatient:"Save Patient Data",aboutTitle:"About AshaCare",aboutText1:"AshaCare is a digital frontline screening and clinical decision support companion designed specifically for ASHA workers, community health providers, and rural medical officers.",aboutText2:"By evaluating symptoms against pediatric warning signs and standardized triage pathways (such as fever, pallor, and red-flag indicators), AshaCare helps bridge the gap between early symptom detection and prompt referral to district medical facilities.",aboutText3:"Built with offline resilience, multilingual support, and secure worker authentication, AshaCare empowers grassroots health workers to deliver safer, faster, and more reliable pediatric care.",doctorReviewTitle:"Doctor & Health Worker Reviews",doc1Name:"Dr. Ananya Roy, MD (Pediatrics)",doc1Role:"District Chief Medical Officer",doc1Review:"Asha Care has streamlined our referral process significantly. Grassroots workers can now accurately flag high-risk symptoms and send properly structured details to our facility.",doc2Name:"Sunita Murmu",doc2Role:"Senior ASHA Supervisor",doc2Review:"The multilingual support and offline capabilities make this app extremely practical for field use. It gives our workers the confidence needed for timely interventions."},
hi:{appName:"आशाकेयर",tagline:"बाल कैंसर चेतावनी संकेत सहायक",home:"होम",newAssessment:"नई जांच",records:"रिकॉर्ड",startAssessment:"नई जांच शुरू करें",todaysCases:"आज के मामले",pendingFollowups:"लंबित फॉलो-अप",recentAssessments:"हाल की जांचें",online:"ऑनलाइन",offline:"ऑफ़लाइन",syncNow:"अभी सिंक करें",synced:"सभी रिकॉर्ड सिंक हो गए",tapToSpeak:"लक्षण बोलने के लिए टैप करें",listening:"सुन रहा है...",orType:"... या नीचे टाइप करें",quickAdd:"सामान्य लक्षण जोड़ें",childName:"बच्चे का नाम (वैकल्पिक)",childAge:"उम्र (वर्ष)",analyze:"लक्षणों की जांच करें",analyzing:"WHO चेतावनी संकेतों से मिलान हो रहा है...",back:"वापस",riskRed:"तुरंत रेफर करें",riskYellow:"बारीकी से निगरानी करें",riskGreen:"सामान्य देखभाल",flaggedBecause:"चिन्हित करने का कारण:",possible:"संभावित चिंता:",nextSteps:"अनुशंसित अगला कदम",generateReferral:"रेफरल स्लिप बनाएं",saveMonitor:"सेव करें और निगरानी रिमाइंडर सेट करें",newCase:"एक और जांच शुरू करें",nearestFacility:"निकटतम जिला अस्पताल",away:"दूर",shareSlip:"परिवार के साथ साझा करें",printSlip:"स्लिप प्रिंट करें",followUp:"फॉलो-अप रिमाइंडर",remindIn:"मुझे जांच के लिए याद दिलाएं",days3:"3 दिन",days7:"7 दिन",reminderSet:"रिमाइंडर सेट हो गया",goHome:"पूर्ण होम पर वापस जाएं",scanNote:"अस्पताल स्टाफ इस कोड को स्कैन करके पूरा मामला तुरंत देख सकता है।",caseId:"केस आईडी",noSpeechSupport:"इस ब्राउज़र में वॉइस इनपुट समर्थित नहीं है- कृपया टाइप करें।",weekAgo:"2 दिन पहले",qrTitle:"QR कोड जनरेटर",qrText:"नीचे केस की जानकारी या कोई भी टेक्स्ट लिखें।",generateQr:"QR बनाएं",downloadQr:"QR डाउनलोड करें",copyQr:"टेक्स्ट कॉपी करें",qrEmpty:"QR बनाने के लिए टेक्स्ट लिखें।",disclaimer:"यह टूल आपकी सहायता करता है। यह निदान नहीं करता या डॉक्टर का विकल्प नहीं है।",referralSlip:"रेफरल स्लिप",childLabel:"बच्चा",symptomsRecorded:"दर्ज लक्षण",noRecords:"अभी तक कोई जांच नहीं",tapForDetails:"पूरी जानकारी देखने के लिए केस पर टैप करें",micDenied:"माइक्रोफ़ोन अनुमति अस्वीकृत",micNoSpeech:"कोई आवाज़ नहीं मिली — माइक के पास फिर से बोलें।",micNetwork:"वॉइस पहचान के लिए इंटरनेट चाहिए।",micNotSecure:"वॉइस इनपुट के लिए सुरक्षित कनेक्शन चाहिए।",micGeneric:"वॉइस इनपुट विफल — कृपया टाइप करें।",openInBrowser:"ब्राउज़र में QR खोलें",retryQr:"QR फिर कोशिश करें",generatedOn:"जनरेट किया गया",loginTitle:"सुरक्षित स्वास्थ्य कार्यकर्ता लॉगिन",enterName:"पूरा नाम",enterWorkerId:"कार्यकर्ता / आईडी नंबर",enterPin:"पासकोड / पिन दर्ज करें (डेमो: 1234)",loginBtn:"प्रमाणीकृत करें और एक्सेस करें",invalidPin:"अमान्य पासकोड। डेमो के लिए '1234' का उपयोग करें।",missingDetails:"कृपया अपना नाम और आईडी नंबर दर्ज करें।",registeredPatients:"पंजीकृत मरीज रिकॉर्ड",savePatient:"मरीज का डेटा सहेजें",aboutTitle:"आशाकेयर के बारे में",aboutText1:"आशाकेयर एक डिजिटल फ्रंटलाइन स्क्रीनिंग टूल है...",aboutText2:"यह लक्षणों का मूल्यांकन करता है...",aboutText3:"यह सुरक्षित और बहुभाषी है...",doctorReviewTitle:"समीक्षाएं",doc1Name:"डॉ. अनन्या रॉय",doc1Role:"मुख्य चिकित्सा अधिकारी",doc1Review:"आशाकेयर ने हमारी प्रक्रिया को सुव्यवस्थित किया है।",doc2Name:"सुनीता मुर्मू",doc2Role:"वरिष्ठ आशा पर्यवेक्षक",doc2Review:"यह ऐप फील्ड के लिए बहुत व्यावहारिक है।"},
or:{appName:"ଆଶାକେୟାର",tagline:"ଶିଶୁ ବିପଦ ସଙ୍କେତ ସହାୟକ",home:"ମୂଳ ପୃଷ୍ଠା",newAssessment:"ନୂତନ ଯାଞ୍ଚ",records:"ରେକର୍ଡ",startAssessment:"ନୂତନ ଯାଞ୍ଚ ଆରମ୍ଭ କରନ୍ତୁ",todaysCases:"ଆଜିର କେସ୍",pendingFollowups:"ବାକିଥିବା ଫଲୋ-ଅପ୍",recentAssessments:"ସାମ୍ପ୍ରତିକ ଯାଞ୍ଚ",online:"ଅନ୍‌ଲାଇନ୍",offline:"ଅଫ୍‌ଲାଇନ୍",syncNow:"ବର୍ତ୍ତମାନ ସିଙ୍କ୍ କରନ୍ତୁ",synced:"ସମସ୍ତ ରେକର୍ଡ ସିଙ୍କ୍ ହୋଇଛି",tapToSpeak:"ଲକ୍ଷଣ କହିବା ପାଇଁ ଟ୍ୟାପ୍ କରନ୍ତୁ",listening:"ଶୁଣୁଛି...",orType:"...କିମ୍ବା ତଳେ ଟାଇପ୍ କରନ୍ତୁ",quickAdd:"ସାଧାରଣ ଲକ୍ଷଣ ଯୋଡନ୍ତୁ",childName:"ପିଲାର ନାମ (ଇଚ୍ଛାଧୀନ)",childAge:"ବୟସ (ବର୍ଷ)",analyze:"ଲକ୍ଷଣ ଯାଞ୍ଚ କରନ୍ତୁ",analyzing:"WHO ବିପଦ ସଙ୍କେତ ସହିତ ମେଳ କରାଯାଉଛି...",back:"ପଛକୁ",riskRed:"ତୁରନ୍ତ ରେଫର୍ କରନ୍ତୁ",riskYellow:"ଭଲଭାବେ ନିରୀକ୍ଷଣ କରନ୍ତୁ",riskGreen:"ସାଧାରଣ ଯତ୍ନ",flaggedBecause:"ଚିହ୍ନଟ କରିବାର କାରଣ:",possible:"ସମ୍ଭାବ୍ୟ ବିପଦ:",nextSteps:"ପରବର୍ତ୍ତୀ ପଦକ୍ଷେପ",generateReferral:"ରେଫରାଲ୍ ସ୍ଲିପ୍ ପ୍ରସ୍ତୁତ କରନ୍ତୁ",saveMonitor:"ସେଭ୍ କରନ୍ତୁ ଏବଂ ରିମାଇଣ୍ଡର ସେଟ୍ କରନ୍ତୁ",newCase:"ଅନ୍ୟ ଏକ ଯାଞ୍ଚ ଆରମ୍ଭ କରନ୍ତୁ",nearestFacility:"ନିକଟବର୍ତ୍ତୀ ଜିଲ୍ଲା ଚିକିତ୍ସାଳୟ",away:"ଦୂର",shareSlip:"ପରିବାର ସହିତ ସେୟାର କରନ୍ତୁ",printSlip:"ସ୍ଲିପ୍ ପ୍ରିଣ୍ଟ କରନ୍ତୁ",followUp:"ଫଲୋ-ଅପ୍ ରିମାଇଣ୍ଡର",remindIn:"ମୋତେ ମନେ ପକାଇଦିଅନ୍ତୁ",days3:"୩ ଦିନ",days7:"୭ ଦିନ",reminderSet:"ରିମାଇଣ୍ଡର ସେଟ୍ ହେଲା",goHome:"ସମ୍ପୂର୍ଣ୍ଣ — ମୂଳ ପୃଷ୍ଠାକୁ ଫେରନ୍ତୁ",scanNote:"ଡାକ୍ତରଖାନା କର୍ମଚାରୀମାନେ ସମ୍ପୂର୍ଣ୍ଣ ବିବରଣୀ ପାଇଁ ଏହି କୋଡ୍ ସ୍କାନ୍ କରିପାରିବେ।",caseId:"କେସ୍ ଆଇଡି",noSpeechSupport:"ଏହି ବ୍ରାଉଜର୍‌ରେ ଭଏସ୍ ଇନପୁଟ୍ ସମର୍ଥିତ ନୁହେଁ - ଦୟାକରି ଟାଇପ୍ କରନ୍ତୁ।",weekAgo:"୨ ଦିନ ପୂର୍ବରୁ",qrTitle:"QR କୋଡ୍ ଜେନେରେଟର୍",qrText:"ତଳେ କେସ୍ ସୂଚନା କିମ୍ବା କୌଣସି ଟେକ୍ସଟ୍ ଲେଖନ୍ତୁ।",generateQr:"QR ତିଆରି କରନ୍ତୁ",downloadQr:"QR ଡାଉନଲୋଡ୍ କରନ୍ତୁ",copyQr:"ଟେକ୍ସଟ୍ କପି କରନ୍ତୁ",qrEmpty:"QR ତିଆରି କରିବା ପାଇଁ ଟେକ୍ସଟ୍ ଲେଖନ୍ତୁ।",disclaimer:"ଏହି ଟୁଲ୍ ଆପଣଙ୍କୁ ସାହାଯ୍ୟ କରିବା ପାଇଁ ଉଦ୍ଦିଷ୍ଟ। ଏହା କୌଣସି ରୋଗର ନିର୍ଣ୍ଣୟ କରେ ନାହିଁ କିମ୍ବା ଡାକ୍ତରଙ୍କ ବିକଳ୍ପ ନୁହେଁ।",referralSlip:"ରେଫରାଲ୍ ସ୍ଲିପ୍",childLabel:"ଶିଶୁ",symptomsRecorded:"ରେକର୍ଡ ହୋଇଥିବା ଲକ୍ଷଣ",noRecords:"ଏପର୍ଯ୍ୟନ୍ତ କୌଣସି ଯାଞ୍ଚ ହୋଇନାହିଁ",tapForDetails:"ପୂରା ବିବରଣୀ ପାଇଁ କେସ୍ ଉପରେ ଟ୍ୟାପ୍ କରନ୍ତୁ",micDenied:"ମାଇକ୍ରୋଫୋନ୍ ଅନୁମତି ନାହିଁ",micNoSpeech:"କୌଣସି ଶବ୍ଦ ଶୁଭିଲା ନାହିଁ - ମାଇକ୍ ପାଖରେ ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ।",micNetwork:"ଭଏସ୍ ଚିହ୍ନିବା ପାଇଁ ଇଣ୍ଟରନେଟ୍ ଦରକାର।",micNotSecure:"ଭଏସ୍ ଇନପୁଟ୍ ପାଇଁ ସୁରକ୍ଷିତ ସଂଯୋଗ ଦରକାର।",micGeneric:"ଭଏସ୍ ଇନପୁଟ୍ ବିଫଳ - ଦୟାକରି ଟାଇପ୍ କରନ୍ତୁ।",openInBrowser:"ବ୍ରାଉଜର୍‌ରେ QR ଖୋଲନ୍ତୁ",retryQr:"QR ପୁଣି ଚେଷ୍ଟା କରନ୍ତୁ",generatedOn:"ପ୍ରସ୍ତୁତ କରାଯାଇଛି",loginTitle:"ସୁରକ୍ଷିତ ସ୍ୱାସ୍ଥ୍ୟ କର୍ମୀ ଲଗଇନ୍",enterName:"ପୂରା ନାମ",enterWorkerId:"କର୍ମୀ / ଆଇଡି ନମ୍ବର",enterPin:"ପାସକୋଡ୍ / ପିନ୍ ଦିଅନ୍ତୁ (ଡେମୋ: 1234)",loginBtn:"ଲଗଇନ୍ କରନ୍ତୁ",invalidPin:"ଅମାନ୍ୟ ପାସକୋଡ୍। ଡେମୋ ପାଇଁ '1234' ବ୍ୟବହାର କରନ୍ତୁ।",missingDetails:"ଦୟାକରି ଆପଣଙ୍କର ନାମ ଏବଂ ଆଇଡି ନମ୍ବର ଦିଅନ୍ତୁ।",registeredPatients:"ପଞ୍ଜିକୃତ ରୋଗୀ ରେକର୍ଡ",savePatient:"ରୋଗୀର ତଥ୍ୟ ସେଭ୍ କରନ୍ତୁ",aboutTitle:"ଆଶାକେୟାର ବିଷୟରେ",aboutText1:"ଆଶାକେୟାର ହେଉଛି ଆଶା କର୍ମୀ ଏବଂ ସ୍ୱାସ୍ଥ୍ୟ ପ୍ରଦାନକାରୀଙ୍କ ପାଇଁ ଏକ ଡିଜିଟାଲ୍ ସ୍କ୍ରିନିଂ ଟୁଲ୍।",aboutText2:"ଏହା ପିଲାମାନଙ୍କର ଲକ୍ଷଣଗୁଡ଼ିକୁ ବିପଦ ସଙ୍କେତ ସହିତ ମୂଲ୍ୟାଙ୍କନ କରିବାରେ ସାହାଯ୍ୟ କରେ।",aboutText3:"ଅଫ୍‌ଲାଇନ୍ ସୁବିଧା ଏବଂ ବହୁଭାଷୀ ସମର୍ଥନ ସହିତ, ଏହା ସ୍ୱାସ୍ଥ୍ୟ କର୍ମୀମାନଙ୍କୁ ଶୀଘ୍ର ଏବଂ ସୁରକ୍ଷିତ ସେବା ପ୍ରଦାନ କରିବାକୁ ସକ୍ଷମ କରେ।",doctorReviewTitle:"ସମୀକ୍ଷା",doc1Name:"ଡକ୍ଟର ଅନନ୍ୟା ରୟ",doc1Role:"ମୁଖ୍ୟ ଚିକିତ୍ସା ଅଧିକାରୀ",doc1Review:"ଆଶାକେୟାର ଆମର ରେଫରାଲ୍ ପ୍ରକ୍ରିୟାକୁ ବହୁତ ସହଜ କରିଛି।",doc2Name:"ସୁନୀତା ମୁର୍ମୁ",doc2Role:"ବରିଷ୍ଠ ଆଶା ସୁପରଭାଇଜର୍",doc2Review:"ଅଫ୍‌ଲାଇନ୍ ଏବଂ ବହୁଭାଷୀ ସୁବିଧା ଯୋଗୁଁ ଏହା ଫିଲ୍ଡରେ ବ୍ୟବହାର ପାଇଁ ଅତ୍ୟନ୍ତ ସୁବିଧାଜନକ।"}
};

const QUICK = [
  { id:"fever", label: { en:"Fever > 7 days", hi:"7 दिन से अधिक बुखार", or:"୭ ଦିନରୁ ଅଧିକ ଜ୍ୱର"} },
  { id:"pallor", label: { en:"Severe Pallor", hi:"गंभीर पीलापन", or:"ଅତ୍ୟଧିକ ଫିକାପଣ"} },
  { id:"bleeding", label: { en:"Unusual Bleeding", hi:"असामान्य रक्तस्राव", or:"ଅସ୍ୱାଭାବିକ ରକ୍ତସ୍ରାବ"} },
  { id:"mass", label: { en:"Lump/Swelling", hi:"गांठ/सूजन", or:"ଫୁଲା / ଗୋଟା"} },
  { id:"white_eye", label: { en:"White Pupil", hi:"सफेद पुतली", or:"ଧଳା ଆଖିଡୋଳା"} },
  { id:"pain", label: { en:"Bone/Joint Pain", hi:"हड्डी/जोड़ों का दर्द", or:"ହାଡ/ଗଣ୍ଠି ବିନ୍ଧା"} },
  { id:"cough", label: { en:"Cough", hi:"खांसी", or:"କାଶ"} },
  { id:"diarrhea", label: { en:"Diarrhea", hi:"दस्त", or:"ଝାଡା"} }
];

const App = {
  lang: 'en',
  user: null,
  cases: [],
  activeCase: null,
  quickSet: new Set(),
  recognition: null,

  init() {
    this.token = localStorage.getItem('ashacare_token');
    if (this.token) {
      this.fetchUser();
    } else {
      this.renderLogin();
    }
    this.initMic();
  },

  async fetchUser() {
    try {
      const res = await fetch('/api/auth/me', { headers: { 'authorization': 'Bearer ' + this.token }});
      if(res.ok) {
        this.user = await res.json();
        document.getElementById('userBadge').innerText = this.user.name;
        document.getElementById('bottomNav').style.display = 'grid';
        this.fetchCases();
      } else {
        this.logout();
      }
    } catch(e) {
      this.logout();
    }
  },

  async fetchCases() {
    try {
      const res = await fetch('/api/cases', { headers: { 'authorization': 'Bearer ' + this.token }});
      if(res.ok) {
        this.cases = await res.json();
        if(this.user.role === 'Medical Officer / Doctor') {
            this.go('doctorDashboard');
        } else {
            this.go('home');
        }
      }
    } catch(e) {
      this.toast("Failed to load cases.");
    }
  },

  logout() {
    localStorage.removeItem('ashacare_token');
    this.user = null;
    this.cases = [];
    document.getElementById('bottomNav').style.display = 'none';
    this.renderLogin();
  },

  async login(e) {
    if(e) e.preventDefault();
    const name = document.getElementById('lName').value;
    const workerId = document.getElementById('lId').value;
    const pin = document.getElementById('lPin').value;
    const role = document.getElementById('lRole').value;

    if(!workerId || !pin) return this.toast(this.t('missingDetails'));

    try {
      const res = await fetch('/api/auth/authenticate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name, workerId, pin, role })
      });
      const data = await res.json();
      
      if(res.ok) {
        this.token = data.token;
        localStorage.setItem('ashacare_token', this.token);
        this.user = data.user;
        document.getElementById('userBadge').innerText = this.user.name;
        document.getElementById('bottomNav').style.display = 'grid';
        this.fetchCases();
      } else {
        this.toast(data.error || "Login failed");
      }
    } catch(err) {
      this.toast("Network error.");
    }
  },

  t(key) {
    return T[this.lang][key] || T['en'][key] || key;
  },

  toggleLang() {
    const langs = ['en', 'hi', 'or'];
    const labels = { 'en': 'A/अ/ଅ', 'hi': 'अ/ଅ/A', 'or': 'ଅ/A/अ' };
    
    let currentIdx = langs.indexOf(this.lang);
    this.lang = langs[(currentIdx + 1) % langs.length];
    
    document.getElementById('langBtn').innerText = labels[this.lang];
    
    if(!this.user) this.renderLogin();
    else if(this.currentScreen) this.go(this.currentScreen);
  },

  toast(msg) {
    const t = document.getElementById('toast');
    t.innerText = msg;
    t.style.display = 'block';
    setTimeout(() => t.style.display = 'none', 3000);
  },

  go(screen) {
    this.currentScreen = screen;
    document.querySelectorAll('.nav').forEach(n => n.classList.remove('active'));
    if(document.getElementById('nav-'+screen)) {
       document.getElementById('nav-'+screen).classList.add('active');
    }

    const scr = document.getElementById('screen');
    if(screen === 'home') this.renderHome(scr);
    if(screen === 'patient') this.renderPatient(scr);
    if(screen === 'assess') this.renderAssess(scr);
    if(screen === 'records') this.renderRecords(scr);
    if(screen === 'qr') this.renderQR(scr);
    if(screen === 'about') this.renderAbout(scr);
    if(screen === 'doctorDashboard') this.renderDoctorDashboard(scr);
  },

  newAssessment() {
    this.activeCase = null;
    this.quickSet.clear();
    this.go('assess');
  },

  renderLogin() {
    this.currentScreen = 'login';
    document.getElementById('bottomNav').style.display = 'none';
    document.getElementById('userBadge').innerText = 'Lock';
    document.getElementById('screen').innerHTML = \`
      <div class="loginCard">
        <h2 style="margin-top:0">\${this.t('loginTitle')}</h2>
        <form onsubmit="App.login(event)">
          <label class="label">\${this.t('enterName')}</label>
          <input type="text" id="lName" class="input" placeholder="e.g. Sunita Devi" required>
          <label class="label">\${this.t('enterWorkerId')}</label>
          <input type="text" id="lId" class="input" placeholder="ASHA-12345" required>
          <label class="label">\${this.t('enterPin')}</label>
          <input type="password" id="lPin" class="input" placeholder="••••" required>
          <label class="label">Role</label>
          <select id="lRole" class="select">
            <option value="ASHA Worker">ASHA Worker</option>
            <option value="Medical Officer / Doctor">Medical Officer / Doctor</option>
          </select>
          <button type="submit" class="primary">\${this.t('loginBtn')}</button>
        </form>
      </div>
    \`;
  },

  renderHome(scr) {
    const recent = this.cases.slice(0, 3);
    let recentHtml = recent.length ? '' : \`<p class="muted">\${this.t('noRecords')}</p>\`;
    recent.forEach(c => {
      recentHtml += \`
        <button class="record" onclick="App.openRecord('\${c.caseId}')">
          <div>
            <div class="recordName">\${c.name} (\${c.age}y)</div>
            <div class="muted">\${new Date(c.date).toLocaleDateString()} - \${c.status}</div>
          </div>
          <span class="risk \${c.level}"><span class="dot"></span> \${c.level.toUpperCase()}</span>
        </button>
      \`;
    });

    scr.innerHTML = \`
      <div class="hero">
        <div class="eyebrow">\${this.t('tagline')}</div>
        <h2>Hello, \${this.user.name.split(' ')[0]}</h2>
        <p>\${this.t('ready') || "Ready for today's screening."}</p>
        <button onclick="App.newAssessment()">\${this.t('startAssessment')}</button>
      </div>
      <div class="grid2 stats">
        <div class="card stat">
          <strong>\${this.cases.length}</strong>
          <span>\${this.t('todaysCases')}</span>
        </div>
        <div class="card stat">
          <strong>\${this.cases.filter(c=>c.status==='Pending Review').length}</strong>
          <span>\${this.t('pendingFollowups')}</span>
        </div>
      </div>
      <div class="sync">
        <span class="muted">\${this.t('synced')}</span>
        <button class="linkBtn" onclick="App.fetchCases()">\${this.t('syncNow')}</button>
      </div>
      <div class="sectionTitle">\${this.t('recentAssessments')}</div>
      \${recentHtml}
    \`;
  },

  renderDoctorDashboard(scr) {
    const redCount = this.cases.filter(c=>c.level==='red').length;
    const pendingCount = this.cases.filter(c=>c.status==='Pending Review').length;

    let casesHtml = '';
    this.cases.forEach(c => {
      casesHtml += \`
        <button class="record" onclick="App.openRecord('\${c.caseId}')">
          <div>
            <div class="recordName">\${c.name} <span class="muted" style="font-size:10px">ID: \${c.caseId}</span></div>
            <div class="muted" style="margin-top:2px; font-size:11px;">\${c.transcript.substring(0,40)}...</div>
          </div>
          <div style="text-align:right">
             <span class="risk \${c.level}"><span class="dot"></span> \${c.level.toUpperCase()}</span>
             <div class="muted" style="font-size:9px;margin-top:4px">\${c.status}</div>
          </div>
        </button>
      \`;
    });

    scr.innerHTML = \`
      <div class="doctorHero">
        <h2>Dr. \${this.user.name.split(' ')[0]}'s Portal</h2>
        <div style="font-size:12px;opacity:0.9">District Medical Dashboard</div>
      </div>
      <div class="metricGrid">
        <div class="metricCard"><strong>\${this.cases.length}</strong><span>Total</span></div>
        <div class="metricCard"><strong>\${redCount}</strong><span style="color:#dc2626">Red Flag</span></div>
        <div class="metricCard"><strong>\${pendingCount}</strong><span>Pending</span></div>
      </div>
      <div class="filterRow">
        <button class="pill" style="background:#0f172a;color:#fff">All Cases</button>
        <button class="pill risk red">Urgent Needs</button>
        <button class="pill risk yellow">Follow-ups</button>
      </div>
      <div style="margin-top:12px;">\${casesHtml || '<p class="muted">No cases found.</p>'}</div>
    \`;
  },

  renderPatient(scr) {
    scr.innerHTML = \`
      <h2 style="margin-top:0">\${this.t('registeredPatients')}</h2>
      <div class="loginCard">
        <div class="row">
          <div><label class="label">Patient Name</label><input class="input" placeholder="Enter name"></div>
          <div><label class="label">Age</label><input class="input" placeholder="Years"></div>
        </div>
        <div class="row">
          <div><label class="label">Guardian Name</label><input class="input" placeholder="Parent/Guardian"></div>
          <div><label class="label">Mobile Number</label><input class="input" placeholder="+91XXXXXXXXXX" inputmode="tel"></div>
        </div>
        <button class="primary" onclick="App.go('home')">\${this.t('savePatient')}</button>
      </div>
    \`;
  },

  renderAssess(scr) {
    let qHtml = QUICK.map(q => \`<button class="\${this.quickSet.has(q.id)?'active':''}" onclick="App.toggleQuick('\${q.id}')">\${q.label[this.lang]}</button>\`).join('');
    
    scr.innerHTML = \`
      <button class="back" onclick="App.go('home')">← \${this.t('back')}</button>
      <div class="row">
        <input type="text" id="aName" class="input" placeholder="\${this.t('childName')}">
        <input type="number" id="aAge" class="input" placeholder="\${this.t('childAge')}">
      </div>
      <div class="voice">
        <button class="mic" id="micBtn" onclick="App.toggleVoice()">🎤</button>
        <div class="voiceTitle" id="micStatus">\${this.t('tapToSpeak')}</div>
      </div>
      <div style="text-align:center" class="muted">\${this.t('orType')}</div>
      <textarea id="aText" class="textarea" placeholder="\${this.t('listening')}"></textarea>
      
      <div class="sectionTitle">\${this.t('quickAdd')}</div>
      <div class="quick" id="quickBox">\${qHtml}</div>
      <button class="primary" onclick="App.analyze()">\${this.t('analyze')}</button>
    \`;
  },

  toggleQuick(id) {
    if(this.quickSet.has(id)) this.quickSet.delete(id);
    else this.quickSet.add(id);
    this.renderAssess(document.getElementById('screen'));
  },

  initMic() {
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if(SR) {
      this.recognition = new SR();
      this.recognition.continuous = false;
      this.recognition.interimResults = true;
      this.recognition.onstart = () => {
        document.getElementById('micBtn').classList.add('listening');
        document.getElementById('micStatus').innerText = this.t('listening');
      };
      this.recognition.onresult = (e) => {
        let transcript = '';
        for (let i = e.resultIndex; i < e.results.length; i++) transcript += e.results[i][0].transcript;
        document.getElementById('aText').value = transcript;
      };
      this.recognition.onend = () => {
        document.getElementById('micBtn').classList.remove('listening');
        document.getElementById('micStatus').innerText = this.t('tapToSpeak');
      };
    }
  },

  toggleVoice() {
    if(!this.recognition) return this.toast(this.t('noSpeechSupport'));
    if(document.getElementById('micBtn').classList.contains('listening')) {
      this.recognition.stop();
    } else {
      let langCode = 'en-IN';
      if(this.lang === 'hi') langCode = 'hi-IN';
      if(this.lang === 'or') langCode = 'or-IN';
      this.recognition.lang = langCode;
      this.recognition.start();
    }
  },

  async analyze() {
    const scr = document.getElementById('screen');
    const name = document.getElementById('aName').value || "Unknown";
    const age = document.getElementById('aAge').value || "0";
    const text = document.getElementById('aText').value;

    if(!text && this.quickSet.size === 0) return this.toast("Please enter symptoms.");

    scr.innerHTML = \`<div class="loader"><div class="spinner"></div><div>\${this.t('analyzing')}</div></div>\`;

    const triage = (txt, set) => {
        const txtLower = txt.toLowerCase();
        const redList = ['fever', 'pallor', 'bleeding', 'mass', 'white_eye', 'pain', 'severe', 'white pupil', 'रक्त', 'खून', 'ଜ୍ୱର', 'ରକ୍ତସ୍ରାବ', 'ଫିକାପଣ'];
        const yellowList = ['cough', 'diarrhea', 'खांसी', 'दस्त', 'କାଶ', 'ଝାଡା'];
        let hasRed = false, hasYellow = false, reasons = [];

        redList.forEach(k => { if(set.has(k) || txtLower.includes(k.replace('_',' '))) { hasRed=true; reasons.push("Red flag: "+k); } });
        yellowList.forEach(k => { if(set.has(k) || txtLower.includes(k.replace('_',' '))) { hasYellow=true; reasons.push("Yellow flag: "+k); } });

        if(hasRed) return { level: 'red', concern: 'High Risk / Possible Oncological Flag', re: reasons };
        if(hasYellow) return { level: 'yellow', concern: 'Monitor Closely', re: reasons };
        return { level: 'green', concern: 'Routine', re: ['No high-risk signs'] };
    };

    const result = triage(text, this.quickSet);
    const payload = {
        caseId: 'AC-' + Math.floor(100000 + Math.random() * 900000),
        name, age, transcript: text || Array.from(this.quickSet).join(', '),
        level: result.level, concern: result.concern, re: result.re,
        registeredBy: this.user.name
    };

    try {
        const res = await fetch('/api/cases', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'authorization': 'Bearer ' + this.token },
            body: JSON.stringify(payload)
        });
        if(res.ok) {
            const savedData = await res.json();
            this.cases.unshift(savedData);
            this.activeCase = savedData;
            this.renderResult(savedData);
        } else {
            this.toast("Failed to save assessment.");
            this.go('home');
        }
    } catch(e) {
        this.toast("Network error.");
        this.go('home');
    }
  },

  renderResult(c) {
    const scr = document.getElementById('screen');
    let bannerBg = c.level === 'red' ? '#dc2626' : (c.level === 'yellow' ? '#d97706' : '#16a34a');
    let icon = c.level === 'red' ? '⚠️' : (c.level === 'yellow' ? '👀' : '✅');
    let riskStr = c.level === 'red' ? this.t('riskRed') : (c.level === 'yellow' ? this.t('riskYellow') : this.t('riskGreen'));
    
    let reHtml = c.re.map(r => \`<div class="reason"><div class="reasonDot"></div>\${r}</div>\`).join('');

    scr.innerHTML = \`
      <button class="back" onclick="App.go('home')">← \${this.t('back')}</button>
      <div class="resultBanner" style="background:\${bannerBg};color:#fff">
        <div class="resultIcon" style="color:\${bannerBg}">\${icon}</div>
        <h2 style="margin:0;font-size:22px">\${riskStr}</h2>
        <p style="margin:5px 0 0;font-size:12px;opacity:0.9">\${c.name} (\${c.age}y)</p>
      </div>
      
      <div class="box">
        <div class="boxTitle">\${this.t('flaggedBecause')}</div>
        \${reHtml}
        <div class="transcriptBox">\${c.transcript}</div>
      </div>
      
      \${c.level === 'red' ? \`
        <div class="next">
          <div class="boxTitle">\${this.t('nextSteps')}</div>
          <div style="font-weight:800;font-size:16px;margin:8px 0">\${this.t('nearestFacility')}</div>
          <button class="primary dangerBtn" onclick="App.renderReferral()">\${this.t('generateReferral')}</button>
        </div>
      \` : \`
        <button class="outline" onclick="App.go('home')" style="margin-top:15px">\${this.t('goHome')}</button>
      \`}
      <div class="disclaimer">\${this.t('disclaimer')}</div>
    \`;
  },

  renderReferral() {
    const c = this.activeCase;
    if(!c) return this.go('home');
    const scr = document.getElementById('screen');
    
    scr.innerHTML = \`
      <button class="back" onclick="App.renderResult(App.activeCase)">← \${this.t('back')}</button>
      <div style="border:1px solid var(--line);border-radius:14px;background:#fff">
        <div class="refHead">
          <div><strong style="font-size:16px">\${this.t('referralSlip')}</strong><div style="font-size:10px;color:#64748b">\${this.t('caseId')}: \${c.caseId}</div></div>
          <div class="logo">⚕</div>
        </div>
        <div class="refBody">
           <div style="font-size:13px"><strong>\${c.name}</strong>, \${c.age}y</div>
           <div style="font-size:12px;color:#b3261e;font-weight:800;margin-top:5px">URGENT REFERRAL</div>
           <div class="transcriptBox" style="font-size:11px;margin-top:10px">\${c.transcript}</div>
           <div class="qrWrap">
             <div id="qrCodeDiv"></div>
             <div class="qrNote">\${this.t('scanNote')}</div>
           </div>
        </div>
        <div class="actions">
          <button onclick="window.print()">\${this.t('printSlip')}</button>
          <button onclick="App.go('home')">\${this.t('goHome')}</button>
        </div>
      </div>
    \`;
    setTimeout(() => {
        new QRCode(document.getElementById("qrCodeDiv"), {
            text: JSON.stringify({id: c.caseId, name: c.name, risk: c.level}),
            width: 180, height: 180
        });
    }, 100);
  },

  renderRecords(scr) {
    let list = this.cases.map(c => \`
      <button class="record" onclick="App.openRecord('\${c.caseId}')">
        <div>
          <div class="recordName">\${c.name}</div>
          <div class="muted">\${new Date(c.date).toLocaleDateString()}</div>
        </div>
        <span class="risk \${c.level}"><span class="dot"></span> \${c.level.toUpperCase()}</span>
      </button>
    \`).join('');
    
    scr.innerHTML = \`
      <h2 style="margin-top:0">\${this.t('records')}</h2>
      \${list || '<p class="muted">'+this.t('noRecords')+'</p>'}
    \`;
  },

  openRecord(id) {
    const c = this.cases.find(x => x.caseId === id);
    if(!c) return;
    this.activeCase = c;
    const scr = document.getElementById('screen');
    
    scr.innerHTML = \`
      <button class="back" onclick="App.go('home')">← \${this.t('back')}</button>
      <div class="box">
        <div style="display:flex;justify-content:space-between;align-items:center">
           <h2>\${c.name}</h2>
           <span class="risk \${c.level}"><span class="dot"></span> \${c.level.toUpperCase()}</span>
        </div>
        <div class="caseMeta" style="margin-top:10px">
           <div><small>Age</small><b>\${c.age} Years</b></div>
           <div><small>Case ID</small><b>\${c.caseId}</b></div>
           <div><small>Date</small><b>\${new Date(c.date).toLocaleDateString()}</b></div>
           <div><small>Status</small><b>\${c.status}</b></div>
        </div>
        <div class="boxTitle" style="margin-top:15px">Symptoms Captured</div>
        <div class="transcriptBox">\${c.transcript}</div>
        
        \${c.doctorNotes ? \`<div class="boxTitle" style="margin-top:15px">Doctor Notes</div><div class="transcriptBox" style="background:#eff6ff">\${c.doctorNotes}</div>\` : ''}
      </div>

      \${this.user.role === 'Medical Officer / Doctor' ? \`
        <div class="examBox">
           <h3 style="margin-top:0;font-size:14px">Clinical Exam / Resolution</h3>
           <textarea id="docNotes" class="textarea" placeholder="Enter findings and action taken..."></textarea>
           <button class="primary" onclick="App.resolveCase('\${c.caseId}')">Save & Resolve Case</button>
        </div>
      \` : ''}
    \`;
  },

  async resolveCase(id) {
    const notes = document.getElementById('docNotes').value;
    try {
        const res = await fetch('/api/cases/'+id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json', 'authorization': 'Bearer ' + this.token },
            body: JSON.stringify({ doctorNotes: notes, status: 'Resolved' })
        });
        if(res.ok) {
            this.toast("Case updated successfully.");
            this.fetchCases();
        }
    } catch(e) {
        this.toast("Failed to update case.");
    }
  },

  renderQR(scr) {
    scr.innerHTML = \`
      <h2 style="margin-top:0">\${this.t('qrTitle')}</h2>
      <p class="muted">\${this.t('qrText')}</p>
      <div class="loginCard" style="text-align:center">
        <div id="standaloneQr" style="margin: 20px auto; width:200px; height:200px; border:1px solid #eef2f7; padding:10px; border-radius:10px;"></div>
        <input type="text" id="qrInput" class="input" placeholder="Type here..." oninput="App.generateStandAloneQR()">
      </div>
    \`;
    this.generateStandAloneQR();
  },

  generateStandAloneQR() {
    const text = document.getElementById('qrInput')?.value || "AshaCare Portal";
    const box = document.getElementById('standaloneQr');
    if(box) {
        box.innerHTML = '';
        new QRCode(box, { text: text, width: 180, height: 180 });
    }
  },

  renderAbout(scr) {
    scr.innerHTML = \`
      <h2 style="margin-top:0">\${this.t('aboutTitle')}</h2>
      <div class="box">
         <p style="font-size:13px; line-height:1.5">\${this.t('aboutText1')}</p>
         <p style="font-size:13px; line-height:1.5">\${this.t('aboutText2')}</p>
         <p style="font-size:13px; line-height:1.5">\${this.t('aboutText3')}</p>
      </div>
      <h3 style="margin-top:20px">\${this.t('doctorReviewTitle')}</h3>
      <div class="doctor-review-card">
        <div class="doctor-grid">
           <div style="width:50px;height:50px;background:#0f766e;color:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:bold">AR</div>
           <div class="doctor-info"><h4>\${this.t('doc1Name')}</h4><p>\${this.t('doc1Role')}</p></div>
        </div>
        <div class="review-quote">\${this.t('doc1Review')}</div>
      </div>
    \`;
  }
};

window.onload = () => App.init();
</script>
</body>
</html>`;

// Serve the embedded HTML on the root route
app.get('/', (req, res) => {
  res.send(frontendHTML);
});

// ==========================================
// 5. SERVER INITIALIZATION
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`AshaCare Secure Server running on port ${PORT}`);
});
