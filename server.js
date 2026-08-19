
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
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['asha', 'doctor'], required: true },
  createdAt: { type: Date, default: Date.now }
});

const caseSchema = new mongoose.Schema({
  caseId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  age: { type: String, required: true },
  guardian: { type: String, required: true },
  symptoms: { type: String, required: true },
  riskLevel: { type: String, enum: ['RED', 'YELLOW', 'GREEN'], default: 'GREEN' },
  date: { type: Date, default: Date.now },
  status: { type: String, default: 'Pending Review' },
  doctorNotes: { type: String, default: '' },
  followUp: { type: Boolean, default: false },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
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
  if (!token) return res.status(401).json({ error: 'Access denied. Please log in.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired or invalid. Log in again.' });
    req.user = user;
    next();
  });
};

// ==========================================
// 3. API ENDPOINTS
// ==========================================

// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || !role) {
      return res.status(400).json({ error: 'All fields are required.' });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email is already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, email, password: hashedPassword, role });
    await user.save();

    const token = jwt.sign({ userId: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.status(201).json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Registration failed server-side.' });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Invalid email or password.' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ userId: user._id, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: 'Login failed server-side.' });
  }
});

// Get Current User Session
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch user session.' });
  }
});

// Fetch all cases across devices
app.get('/api/cases', authenticateToken, async (req, res) => {
  try {
    const cases = await Case.find().populate('createdBy', 'name email').sort({ date: -1 });
    res.json(cases);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch cases.' });
  }
});

// Create a new case
app.post('/api/cases', authenticateToken, async (req, res) => {
  try {
    const newCase = new Case({
      ...req.body,
      createdBy: req.user.userId
    });
    const savedCase = await newCase.save();
    res.status(201).json(savedCase);
  } catch (err) {
    res.status(500).json({ error: 'Failed to save case.' });
  }
});

// Update a case (Doctor Notes & Status)
app.put('/api/cases/:caseId', authenticateToken, async (req, res) => {
  try {
    const updatedCase = await Case.findOneAndUpdate(
      { caseId: req.params.caseId },
      req.body,
      { new: true }
    );
    res.json(updatedCase);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update case.' });
  }
});

// ==========================================
// 4. EMBEDDED FRONTEND UI
// ==========================================
const frontendHTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AshaCare - Pediatric Triage & Clinical Decision Support</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
  <script src="https://unpkg.com/lucide@latest"></script>
</head>
<body class="bg-slate-50 text-slate-800 font-sans min-h-screen flex flex-col">

  <header class="bg-teal-700 text-white shadow-md sticky top-0 z-40">
    <div class="max-w-7xl mx-auto px-4 py-3 flex flex-wrap items-center justify-between gap-4">
      <div class="flex items-center space-x-2">
        <i data-lucide="activity" class="w-8 h-8 text-amber-300"></i>
        <div>
          <h1 class="text-xl font-bold tracking-wide">AshaCare</h1>
          <p class="text-xs text-teal-100" id="headerSubtitle">Digital Frontline Clinical Companion</p>
        </div>
      </div>
      <div class="flex items-center space-x-3 text-sm">
        <div class="flex items-center space-x-1 bg-teal-800 rounded-lg px-2 py-1">
          <i data-lucide="globe" class="w-4 h-4 text-teal-200"></i>
          <select id="langSelect" onchange="changeLanguage()" class="bg-transparent text-white font-medium focus:outline-none cursor-pointer">
            <option value="en" class="text-slate-800">English</option>
            <option value="hi" class="text-slate-800">हिंदी (Hindi)</option>
            <option value="or" class="text-slate-800">ଓଡ଼ିଆ (Odia)</option>
          </select>
        </div>
        <div class="bg-teal-900/60 p-1 rounded-lg flex items-center">
          <button id="btnAshaRole" onclick="switchRole('asha')" class="px-3 py-1 rounded-md text-xs font-semibold transition-colors bg-amber-400 text-teal-950 shadow">
            ASHA Worker
          </button>
          <button id="btnDoctorRole" onclick="switchRole('doctor')" class="px-3 py-1 rounded-md text-xs font-semibold transition-colors text-teal-100 hover:text-white">
            Doctor / MO
          </button>
        </div>
        <div id="userProfile" class="hidden items-center gap-2 pl-2 border-l border-teal-600">
          <span id="userNameDisplay" class="text-xs font-semibold text-amber-200"></span>
          <button onclick="logout()" title="Logout" class="p-1 hover:bg-teal-800 rounded text-teal-200 hover:text-white">
            <i data-lucide="log-out" class="w-4 h-4"></i>
          </button>
        </div>
      </div>
    </div>
  </header>

  <main class="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 grid grid-cols-1 gap-6">
    <!-- ASHA WORKER VIEW -->
    <div id="ashaView" class="space-y-6">
      <div class="bg-white rounded-xl shadow-sm border border-slate-200 p-5 md:p-6">
        <h2 class="text-lg font-bold text-slate-800 mb-4 flex items-center gap-2" id="formTitle">
          <i data-lucide="user-plus" class="text-teal-600"></i> Patient Screening & Triage
        </h2>
        <form id="triageForm" onsubmit="handleTriageSubmit(event)" class="space-y-4">
          <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Child Name *</label>
              <input type="text" id="childName" required class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="e.g. Aarav Sharma">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Age (Years/Months) *</label>
              <input type="text" id="childAge" required class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="e.g. 3 years">
            </div>
            <div>
              <label class="block text-xs font-semibold text-slate-600 mb-1">Guardian Name & Phone *</label>
              <input type="text" id="guardianDetails" required class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="e.g. Sunita (9876543210)">
            </div>
          </div>

          <div class="border-t border-slate-100 pt-4">
            <label class="block text-xs font-semibold text-slate-700 mb-2">Check High-Risk Pediatric Warning Signs:</label>
            <div class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2 text-xs">
              <label class="flex items-center gap-2 bg-slate-50 p-2 rounded border hover:bg-slate-100 cursor-pointer"><input type="checkbox" value="Prolonged Fever" class="flag-checkbox rounded text-teal-600"><span>Prolonged Fever</span></label>
              <label class="flex items-center gap-2 bg-slate-50 p-2 rounded border hover:bg-slate-100 cursor-pointer"><input type="checkbox" value="White Pupil Reflex" class="flag-checkbox rounded text-teal-600"><span>White Pupil Reflex</span></label>
              <label class="flex items-center gap-2 bg-slate-50 p-2 rounded border hover:bg-slate-100 cursor-pointer"><input type="checkbox" value="Severe Pallor" class="flag-checkbox rounded text-teal-600"><span>Severe Pallor</span></label>
              <label class="flex items-center gap-2 bg-slate-50 p-2 rounded border hover:bg-slate-100 cursor-pointer"><input type="checkbox" value="Abnormal Swelling" class="flag-checkbox rounded text-teal-600"><span>Abnormal Swelling</span></label>
              <label class="flex items-center gap-2 bg-slate-50 p-2 rounded border hover:bg-slate-100 cursor-pointer"><input type="checkbox" value="Unusual Bleeding" class="flag-checkbox rounded text-teal-600"><span>Unusual Bleeding</span></label>
              <label class="flex items-center gap-2 bg-slate-50 p-2 rounded border hover:bg-slate-100 cursor-pointer"><input type="checkbox" value="Rapid Weight Loss" class="flag-checkbox rounded text-teal-600"><span>Rapid Weight Loss</span></label>
            </div>
          </div>

          <div class="border-t border-slate-100 pt-4">
            <div class="flex items-center justify-between mb-1">
              <label class="block text-xs font-semibold text-slate-700">Detailed Clinical Observations / Symptoms:</label>
              <button type="button" id="micBtn" onclick="toggleVoiceInput()" class="flex items-center gap-1 text-xs px-3 py-1 bg-teal-600 text-white rounded-full hover:bg-teal-700 transition-all shadow-sm">
                <i data-lucide="mic" class="w-3.5 h-3.5"></i> <span id="micBtnText">Voice Input</span>
              </button>
            </div>
            <div id="micStatus" class="text-xs font-semibold text-red-600 hidden mb-1 flex items-center gap-1">
              <span class="w-2 h-2 rounded-full bg-red-600 animate-ping"></span> Listening...
            </div>
            <textarea id="symptomsInput" rows="3" required class="w-full border border-slate-300 rounded-lg p-2.5 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="Type or click 'Voice Input'..."></textarea>
          </div>
          <button type="submit" id="submitBtn" class="w-full bg-teal-700 hover:bg-teal-800 text-white font-semibold py-2.5 rounded-lg transition-colors flex items-center justify-center gap-2 text-sm shadow">
            <i data-lucide="shield-alert" class="w-4 h-4"></i> Run Triage Assessment & Generate Referral
          </button>
        </form>
      </div>

      <div id="resultCard" class="hidden bg-white rounded-xl shadow-md border p-6 space-y-4">
        <div class="flex items-center justify-between border-b pb-3">
          <div class="flex items-center gap-3">
            <span id="badgeRisk" class="px-3 py-1 rounded-full text-xs font-bold uppercase tracking-wider"></span>
            <h3 class="text-lg font-bold text-slate-800" id="resultCaseId"></h3>
          </div>
          <button onclick="window.print()" class="text-xs flex items-center gap-1 text-slate-600 hover:text-slate-900 border px-2.5 py-1 rounded">
            <i data-lucide="printer" class="w-3.5 h-3.5"></i> Print Slip
          </button>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div class="md:col-span-2 space-y-2 text-sm">
            <p><strong>Patient:</strong> <span id="resName"></span> (<span id="resAge"></span>)</p>
            <p><strong>Guardian:</strong> <span id="resGuardian"></span></p>
            <p><strong>Symptoms:</strong> <span id="resSymptoms" class="text-slate-700 italic"></span></p>
            <div id="resActionBox" class="p-3 rounded-lg text-sm mt-3 font-medium"></div>
          </div>
          <div class="flex flex-col items-center justify-center border-l pl-4">
            <div id="qrcode" class="p-2 bg-white border rounded shadow-sm"></div>
            <p class="text-[10px] text-slate-500 mt-2 text-center">Scan at District Hospital</p>
          </div>
        </div>
      </div>
    </div>

    <!-- DOCTOR DASHBOARD VIEW -->
    <div id="doctorView" class="hidden space-y-6">
      <div class="bg-white rounded-xl shadow-sm border border-slate-200 p-5 md:p-6">
        <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-6">
          <div>
            <h2 class="text-lg font-bold text-slate-800 flex items-center gap-2">
              <i data-lucide="stethoscope" class="text-teal-600"></i> Medical Officer Clinical Portal
            </h2>
          </div>
          <div class="flex gap-2">
            <button onclick="renderDoctorTable('ALL')" class="px-3 py-1 rounded text-xs font-semibold bg-slate-100 hover:bg-slate-200 text-slate-700">All</button>
            <button onclick="renderDoctorTable('RED')" class="px-3 py-1 rounded text-xs font-semibold bg-red-100 text-red-700 hover:bg-red-200">Red Flags</button>
            <button onclick="renderDoctorTable('YELLOW')" class="px-3 py-1 rounded text-xs font-semibold bg-amber-100 text-amber-800 hover:bg-amber-200">Yellow</button>
            <button onclick="renderDoctorTable('GREEN')" class="px-3 py-1 rounded text-xs font-semibold bg-emerald-100 text-emerald-800 hover:bg-emerald-200">Green</button>
          </div>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm border-collapse">
            <thead>
              <tr class="bg-slate-50 text-slate-600 border-b text-xs uppercase tracking-wider">
                <th class="p-3">Case ID</th>
                <th class="p-3">Patient</th>
                <th class="p-3">Risk Tier</th>
                <th class="p-3">Symptoms</th>
                <th class="p-3">Logged By</th>
                <th class="p-3">Status</th>
                <th class="p-3">Action</th>
              </tr>
            </thead>
            <tbody id="doctorCasesTable" class="divide-y divide-slate-100"></tbody>
          </table>
        </div>
      </div>
    </div>
  </main>

  <!-- AUTH MODAL -->
  <div id="authModal" class="fixed inset-0 bg-slate-900/60 backdrop-blur-sm z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-2xl max-w-md w-full p-6 space-y-4">
      <div class="text-center border-b pb-3">
        <div class="flex justify-center mb-1">
          <i data-lucide="activity" class="w-10 h-10 text-teal-600"></i>
        </div>
        <h3 class="text-xl font-bold text-slate-800" id="authTitle">Welcome to AshaCare</h3>
        <p class="text-xs text-slate-500">Log in or create an account to sync clinical records</p>
      </div>

      <div id="authError" class="hidden text-xs bg-red-50 text-red-700 p-2.5 rounded border border-red-200 font-medium"></div>

      <form id="authForm" onsubmit="handleAuthSubmit(event)" class="space-y-3">
        <div id="nameField" class="hidden">
          <label class="block text-xs font-semibold text-slate-600 mb-1">Full Name</label>
          <input type="text" id="authName" class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="e.g. Dr. Ananya Das">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-600 mb-1">Email Address</label>
          <input type="email" id="authEmail" required class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="name@health.gov.in">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-600 mb-1">Password</label>
          <input type="password" id="authPassword" required class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none" placeholder="••••••••">
        </div>
        <div>
          <label class="block text-xs font-semibold text-slate-600 mb-1">Role</label>
          <select id="authRole" class="w-full border border-slate-300 rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none">
            <option value="asha">ASHA Worker / Field Screener</option>
            <option value="doctor">Medical Officer / Doctor</option>
          </select>
        </div>
        <button type="submit" id="authSubmitBtn" class="w-full bg-teal-700 hover:bg-teal-800 text-white font-semibold py-2.5 rounded-lg text-sm transition-colors shadow">
          Log In
        </button>
      </form>

      <div class="text-center border-t pt-3">
        <button id="toggleAuthModeBtn" onclick="toggleAuthMode()" class="text-xs text-teal-700 hover:text-teal-900 font-semibold underline">
          Need an account? Register here
        </button>
      </div>
    </div>
  </div>

  <!-- DOCTOR EXAM MODAL -->
  <div id="examModal" class="hidden fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-50 flex items-center justify-center p-4">
    <div class="bg-white rounded-xl shadow-xl max-w-lg w-full p-6 space-y-4">
      <div class="flex justify-between items-center border-b pb-2">
        <h3 class="font-bold text-slate-800" id="modalCaseTitle">Clinical Exam Notes</h3>
        <button onclick="closeModal()" class="text-slate-400 hover:text-slate-600"><i data-lucide="x" class="w-5 h-5"></i></button>
      </div>
      <div class="space-y-3 text-sm">
        <div>
          <label class="block text-xs font-semibold text-slate-600 mb-1">Doctor's Diagnosis & Notes</label>
          <textarea id="doctorNotes" rows="3" class="w-full border rounded-lg p-2 text-sm focus:ring-2 focus:ring-teal-500 focus:outline-none"></textarea>
        </div>
        <div class="flex items-center gap-2">
          <input type="checkbox" id="setReminder" class="rounded text-teal-600">
          <label for="setReminder" class="text-xs font-semibold text-slate-700">Set 3-Day Follow-Up Reminder for ASHA Worker</label>
        </div>
      </div>
      <div class="flex justify-end gap-2 pt-2 border-t">
        <button onclick="closeModal()" class="px-4 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-100 rounded-lg">Cancel</button>
        <button id="saveExamBtn" onclick="saveDoctorNotes()" class="px-4 py-2 text-xs font-semibold bg-teal-700 hover:bg-teal-800 text-white rounded-lg shadow">Save & Resolve Case</button>
      </div>
    </div>
  </div>

  <script>
    // Global State
    let activeRole = 'asha';
    let currentLanguage = 'en';
    let recognition = null;
    let isListening = false;
    let activeExamCaseId = null;
    let cachedCases = [];
    let isRegisterMode = false;
    let currentUser = null;

    const RED_FLAG_KEYWORDS = ['fever', 'white pupil', 'leukocoria', 'pallor', 'mass', 'swelling', 'bleeding', 'petechiae', 'weight loss', 'pain', 'vomiting', 'lump', 'बुखार', 'सफेद', 'खून', 'दर्द', 'ଓଜନ', 'ରକ୍ତ', 'ଜ୍ଵର'];
    const YELLOW_FLAG_KEYWORDS = ['cough', 'cold', 'diarrhea', 'rash', 'fatigue', 'खांसी', 'दस्त', 'काଶ', 'ଝାଡା'];

    document.addEventListener('DOMContentLoaded', () => {
      lucide.createIcons();
      initSpeechRecognition();
      checkSession();
    });

    // Session Management
    function getAuthToken() { return localStorage.getItem('ashacare_token'); }

    async function checkSession() {
      const token = getAuthToken();
      if (!token) return showAuthModal();

      try {
        const res = await fetch('/api/auth/me', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        if (res.ok) {
          currentUser = await res.json();
          hideAuthModal();
          updateUserUI();
        } else {
          logout();
        }
      } catch (err) {
        showAuthModal();
      }
    }

    function showAuthModal() {
      document.getElementById('authModal').classList.remove('hidden');
    }

    function hideAuthModal() {
      document.getElementById('authModal').classList.add('hidden');
    }

    function updateUserUI() {
      if (!currentUser) return;
      document.getElementById('userProfile').classList.remove('hidden');
      document.getElementById('userProfile').classList.add('flex');
      document.getElementById('userNameDisplay').innerText = currentUser.name + " (" + currentUser.role.toUpperCase() + ")";
      switchRole(currentUser.role);
    }

    function logout() {
      localStorage.removeItem('ashacare_token');
      currentUser = null;
      document.getElementById('userProfile').classList.add('hidden');
      document.getElementById('userProfile').classList.remove('flex');
      showAuthModal();
    }

    function toggleAuthMode() {
      isRegisterMode = !isRegisterMode;
      const title = document.getElementById('authTitle');
      const submitBtn = document.getElementById('authSubmitBtn');
      const toggleBtn = document.getElementById('toggleAuthModeBtn');
      const nameField = document.getElementById('nameField');

      if (isRegisterMode) {
        title.innerText = "Create AshaCare Account";
        submitBtn.innerText = "Register";
        toggleBtn.innerText = "Already have an account? Log in";
        nameField.classList.remove('hidden');
      } else {
        title.innerText = "Welcome to AshaCare";
        submitBtn.innerText = "Log In";
        toggleBtn.innerText = "Need an account? Register here";
        nameField.classList.add('hidden');
      }
    }

    async function handleAuthSubmit(e) {
      e.preventDefault();
      const errDiv = document.getElementById('authError');
      errDiv.classList.add('hidden');

      const email = document.getElementById('authEmail').value;
      const password = document.getElementById('authPassword').value;
      const role = document.getElementById('authRole').value;
      const name = document.getElementById('authName').value;

      const endpoint = isRegisterMode ? '/api/auth/register' : '/api/auth/login';
      const payload = isRegisterMode ? { name, email, password, role } : { email, password };

      try {
        const res = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });
        const data = await res.json();

        if (!res.ok) {
          errDiv.innerText = data.error || 'Authentication failed.';
          errDiv.classList.remove('hidden');
          return;
        }

        localStorage.setItem('ashacare_token', data.token);
        currentUser = data.user;
        hideAuthModal();
        updateUserUI();
      } catch (err) {
        errDiv.innerText = 'Unable to connect to the server.';
        errDiv.classList.remove('hidden');
      }
    }

    function changeLanguage() {
      currentLanguage = document.getElementById('langSelect').value;
      const sub = document.getElementById('headerSubtitle');
      const title = document.getElementById('formTitle');
      if (currentLanguage === 'hi') {
        sub.innerText = 'डिजिटल आशा स्वास्थ्य सहायक';
        title.innerHTML = '<i data-lucide="user-plus" class="text-teal-600"></i> बाल स्वास्थ्य जांच एवं ट्राइएज';
      } else if (currentLanguage === 'or') {
        sub.innerText = 'ଡିଜିଟାଲ୍ ଆଶା ସ୍ୱାସ୍ଥ୍ୟ ସହାୟକ';
        title.innerHTML = '<i data-lucide="user-plus" class="text-teal-600"></i> ଶିଶୁ ସ୍ୱାସ୍ଥ୍ୟ ପରୀକ୍ଷା';
      } else {
        sub.innerText = 'Digital Frontline Clinical Companion';
        title.innerHTML = '<i data-lucide="user-plus" class="text-teal-600"></i> Patient Screening & Triage';
      }
      lucide.createIcons();
    }

    function switchRole(role) {
      activeRole = role;
      document.getElementById('ashaView').classList.toggle('hidden', role !== 'asha');
      document.getElementById('doctorView').classList.toggle('hidden', role !== 'doctor');
      document.getElementById('btnAshaRole').className = role === 'asha' ? "px-3 py-1 rounded-md text-xs font-semibold bg-amber-400 text-teal-950 shadow" : "px-3 py-1 rounded-md text-xs font-semibold text-teal-100 hover:text-white";
      document.getElementById('btnDoctorRole').className = role === 'doctor' ? "px-3 py-1 rounded-md text-xs font-semibold bg-amber-400 text-teal-950 shadow" : "px-3 py-1 rounded-md text-xs font-semibold text-teal-100 hover:text-white";
      if (role === 'doctor') renderDoctorTable('ALL');
    }

    // Web Speech API
    function initSpeechRecognition() {
      const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
      if (!SpeechRecognition) return;
      recognition = new SpeechRecognition();
      recognition.continuous = false;
      recognition.interimResults = true;
      recognition.onstart = () => { isListening = true; updateMicUI(true); };
      recognition.onresult = (e) => {
        let transcript = '';
        for (let i = e.resultIndex; i < e.results.length; i++) transcript += e.results[i][0].transcript;
        document.getElementById('symptomsInput').value = transcript;
      };
      recognition.onerror = () => stopVoiceInput();
      recognition.onend = () => stopVoiceInput();
    }

    function toggleVoiceInput() {
      if (!recognition) return alert("Speech Recognition not supported.");
      if (isListening) recognition.stop();
      else {
        const langMap = { 'en': 'en-IN', 'hi': 'hi-IN', 'or': 'or-IN' };
        recognition.lang = langMap[currentLanguage] || 'en-IN';
        recognition.start();
      }
    }

    function stopVoiceInput() { isListening = false; updateMicUI(false); }
    function updateMicUI(listening) {
      const btn = document.getElementById('micBtn');
      const status = document.getElementById('micStatus');
      if (listening) {
        btn.className = "flex items-center gap-1 text-xs px-3 py-1 bg-red-600 text-white rounded-full animate-pulse shadow-sm";
        document.getElementById('micBtnText').innerText = "Stop";
        status.classList.remove('hidden');
      } else {
        btn.className = "flex items-center gap-1 text-xs px-3 py-1 bg-teal-600 text-white rounded-full hover:bg-teal-700 shadow-sm";
        document.getElementById('micBtnText').innerText = "Voice Input";
        status.classList.add('hidden');
      }
    }

    // API Integration - Submit Triage
    async function handleTriageSubmit(e) {
      e.preventDefault();
      const btn = document.getElementById('submitBtn');
      btn.innerText = "Saving to Database...";
      btn.disabled = true;

      const name = document.getElementById('childName').value;
      const age = document.getElementById('childAge').value;
      const guardian = document.getElementById('guardianDetails').value;
      let symptoms = document.getElementById('symptomsInput').value;

      const checkedBoxes = Array.from(document.querySelectorAll('.flag-checkbox:checked')).map(cb => cb.value);
      if (checkedBoxes.length > 0) symptoms += " [Flags: " + checkedBoxes.join(', ') + "]";

      const lowerSymptoms = symptoms.toLowerCase();
      let riskLevel = 'GREEN';
      if (checkedBoxes.length > 0 || RED_FLAG_KEYWORDS.some(k => lowerSymptoms.includes(k))) riskLevel = 'RED';
      else if (YELLOW_FLAG_KEYWORDS.some(k => lowerSymptoms.includes(k))) riskLevel = 'YELLOW';

      const caseId = 'AC-' + Math.floor(100000 + Math.random() * 900000);
      const caseRecord = { caseId, name, age, guardian, symptoms, riskLevel };

      try {
        const res = await fetch('/api/cases', {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + getAuthToken()
          },
          body: JSON.stringify(caseRecord)
        });
        const savedData = await res.json();
        displayResult(savedData);
        e.target.reset();
      } catch (err) {
        alert("Failed to connect to the server.");
      } finally {
        btn.innerHTML = '<i data-lucide="shield-alert" class="w-4 h-4"></i> Run Triage Assessment & Generate Referral';
        btn.disabled = false;
        lucide.createIcons();
      }
    }

    function displayResult(record) {
      document.getElementById('resultCaseId').innerText = "Case Ref: " + record.caseId;
      document.getElementById('resName').innerText = record.name;
      document.getElementById('resAge').innerText = record.age;
      document.getElementById('resGuardian').innerText = record.guardian;
      document.getElementById('resSymptoms').innerText = record.symptoms;

      const badge = document.getElementById('badgeRisk');
      const actionBox = document.getElementById('resActionBox');

      if (record.riskLevel === 'RED') {
        badge.className = "px-3 py-1 rounded-full text-xs font-bold bg-red-100 text-red-800 border border-red-200";
        badge.innerText = "RED TIER";
        actionBox.className = "p-3 rounded-lg text-sm bg-red-50 text-red-900 border border-red-200";
        actionBox.innerText = "CRITICAL: Urgent referral to District Hospital required.";
      } else if (record.riskLevel === 'YELLOW') {
        badge.className = "px-3 py-1 rounded-full text-xs font-bold bg-amber-100 text-amber-800 border border-amber-200";
        badge.innerText = "YELLOW TIER";
        actionBox.className = "p-3 rounded-lg text-sm bg-amber-50 text-amber-900 border border-amber-200";
        actionBox.innerText = "WARNING: Schedule follow-up in 48-72 hours.";
      } else {
        badge.className = "px-3 py-1 rounded-full text-xs font-bold bg-emerald-100 text-emerald-800 border border-emerald-200";
        badge.innerText = "GREEN TIER";
        actionBox.className = "p-3 rounded-lg text-sm bg-emerald-50 text-emerald-900 border border-emerald-200";
        actionBox.innerText = "ROUTINE: Provide standard care.";
      }

      const qrContainer = document.getElementById('qrcode');
      qrContainer.innerHTML = '';
      new QRCode(qrContainer, {
        text: JSON.stringify({ id: record.caseId, name: record.name, risk: record.riskLevel }),
        width: 100, height: 100
      });

      const card = document.getElementById('resultCard');
      card.classList.remove('hidden');
      card.scrollIntoView({ behavior: 'smooth' });
    }

    // API Integration - Doctor Dashboard
    async function renderDoctorTable(filter = 'ALL') {
      const tbody = document.getElementById('doctorCasesTable');
      tbody.innerHTML = "<tr><td colspan='7' class='p-4 text-center text-slate-500'>Loading data from server...</td></tr>";

      try {
        const res = await fetch('/api/cases', {
          headers: { 'Authorization': 'Bearer ' + getAuthToken() }
        });

        if (res.status === 401 || res.status === 403) return logout();

        cachedCases = await res.json();
        
        const filteredCases = cachedCases.filter(c => filter === 'ALL' || c.riskLevel === filter);
        tbody.innerHTML = '';

        if (filteredCases.length === 0) {
          tbody.innerHTML = "<tr><td colspan='7' class='p-4 text-center text-slate-400 italic'>No patient records found</td></tr>";
          return;
        }

        filteredCases.forEach(c => {
          const tr = document.createElement('tr');
          tr.className = "hover:bg-slate-50 border-b";
          
          let riskBadge = "<span class='px-2 py-0.5 text-[10px] font-bold rounded bg-emerald-100 text-emerald-800'>GREEN</span>";
          if (c.riskLevel === 'RED') riskBadge = "<span class='px-2 py-0.5 text-[10px] font-bold rounded bg-red-100 text-red-800'>RED</span>";
          if (c.riskLevel === 'YELLOW') riskBadge = "<span class='px-2 py-0.5 text-[10px] font-bold rounded bg-amber-100 text-amber-800'>YELLOW</span>";

          let statusBadge = c.status === 'Resolved' 
            ? "<span class='px-2 py-0.5 rounded-full bg-slate-200 text-slate-700'>" + c.status + "</span>" 
            : "<span class='px-2 py-0.5 rounded-full bg-blue-100 text-blue-800'>" + c.status + "</span>";

          const creatorName = c.createdBy ? c.createdBy.name : 'Unknown';

          tr.innerHTML = 
            "<td class='p-3 font-mono text-xs font-semibold text-slate-700'>" + c.caseId + "</td>" +
            "<td class='p-3 font-medium'>" + c.name + "</td>" +
            "<td class='p-3'>" + riskBadge + "</td>" +
            "<td class='p-3 text-xs text-slate-600 truncate max-w-xs'>" + c.symptoms + "</td>" +
            "<td class='p-3 text-xs text-slate-500'>" + creatorName + "</td>" +
            "<td class='p-3 text-xs'>" + statusBadge + "</td>" +
            "<td class='p-3'><button onclick=\\"openExamModal('" + c.caseId + "')\\" class='text-xs text-teal-700 hover:text-teal-900 font-semibold underline'>Examine</button></td>";
          tbody.appendChild(tr);
        });
      } catch (err) {
        tbody.innerHTML = "<tr><td colspan='7' class='p-4 text-center text-red-500'>Error connecting to database</td></tr>";
      }
    }

    function openExamModal(caseId) {
      activeExamCaseId = caseId;
      const target = cachedCases.find(c => c.caseId === caseId);
      if (target) {
        document.getElementById('modalCaseTitle').innerText = "Examine: " + target.caseId;
        document.getElementById('doctorNotes').value = target.doctorNotes || '';
        document.getElementById('setReminder').checked = target.followUp || false;
        document.getElementById('examModal').classList.remove('hidden');
      }
    }

    function closeModal() {
      document.getElementById('examModal').classList.add('hidden');
      activeExamCaseId = null;
    }

    async function saveDoctorNotes() {
      if (!activeExamCaseId) return;
      const btn = document.getElementById('saveExamBtn');
      btn.innerText = "Saving...";
      
      const notes = document.getElementById('doctorNotes').value;
      const followUp = document.getElementById('setReminder').checked;

      try {
        await fetch('/api/cases/' + activeExamCaseId, {
          method: 'PUT',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': 'Bearer ' + getAuthToken()
          },
          body: JSON.stringify({ doctorNotes: notes, followUp: followUp, status: 'Resolved' })
        });
        closeModal();
        renderDoctorTable('ALL');
      } catch (err) {
        alert('Failed to save exam notes');
      } finally {
        btn.innerText = "Save & Resolve Case";
      }
    }
  </script>
</body>
</html>
`;

// Serve the embedded HTML on the root route
app.get('/', (req, res) => {
  res.send(frontendHTML);
});

// ==========================================
// 5. SERVER INITIALIZATION
// ==========================================
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`AshaCare Auth-Enabled Server running on port ${PORT}`);
});

