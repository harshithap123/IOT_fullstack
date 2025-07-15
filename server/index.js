const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
require('dotenv').config();
const pool = require('./db');
const multer = require('multer');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// App setup
const app = express();
//const upload = multer();

const upload = multer({
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB file limit
});

const PORT = process.env.PORT || 4000;

// SSL Setup
//const sslOptions = {
  //key: fs.readFileSync('/home/mca/IOTproject/ssl/key.pem'),
  //cert: fs.readFileSync('/home/mca/IOTproject/ssl/cert.pem')
//};

const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'ssl/key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'ssl/cert.pem'))
};


// Middleware
app.use(cors());
app.use(express.json());

// Allowed file types
const allowedTypes = [
  'application/pdf', 'image/jpeg', 'image/png', 'image/gif',
  'text/csv', 'application/json', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
];

// JWT Admin Auth Middleware
const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Missing token' });
  try {
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.admin = decoded;
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid token' });
  }
};

// --------------------- API ROUTES ---------------------

// Admin Login
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password, user.password_hash)))
    return res.status(401).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET);
  res.json({ token });
});

// Admin User Statistics
app.get('/api/admin/user-stats', authenticateAdmin, async (req, res) => {
  const result = await pool.query(`
    SELECT uploaded_by, COUNT(*) AS total_uploads, ARRAY_AGG(DISTINCT mimetype) AS file_types
    FROM files
    GROUP BY uploaded_by
    ORDER BY total_uploads DESC`);
  res.json(result.rows);
});

// File Upload
app.post('/api/upload', upload.single('file'), async (req, res) => {
    const file = req.file;
    const uploadedBy = req.body.user || 'anonymous';

    if (!file) return res.status(400).send('No file uploaded');

    if (!allowedTypes.includes(file.mimetype)) {
        return res.status(400).json({ error: 'File type not allowed' });
    }

    // Check count limit (max 4 files per user)
    const countResult = await pool.query(
        'SELECT COUNT(*) FROM files WHERE uploaded_by = $1',
        [uploadedBy]
    );

    if (parseInt(countResult.rows[0].count) >= 4) {
        return res.status(403).json({ error: 'Upload limit reached (Max 4 files per user).' });
    }

    await pool.query(
        'INSERT INTO files (name, mimetype, data, uploaded_by) VALUES ($1, $2, $3, $4)',
        [file.originalname, file.mimetype, file.buffer, uploadedBy]
    );
    res.json({ message: 'File uploaded successfully' });
});

// List all files
app.get('/api/files', async (req, res) => {
  const result = await pool.query('SELECT id, name, mimetype, uploaded_by, uploaded_at FROM files ORDER BY uploaded_at DESC');
  res.json(result.rows);
});

// Download a file
app.get('/api/file/:id', async (req, res) => {
  const result = await pool.query('SELECT * FROM files WHERE id = $1', [req.params.id]);
  const file = result.rows[0];
  if (!file) return res.status(404).send('File not found');
  res.setHeader('Content-Disposition', `inline; filename="${file.name}"`);
  res.setHeader('Content-Type', file.mimetype);
  res.send(file.data);
});

// Health Check
app.get('/api/health', (req, res) => {
  res.json({ status: 'API is working fine' });
});

// --------------------- REACT FRONTEND ---------------------

app.use(express.static(path.join(__dirname, '../client/build')));

// Fallback: Serve React app for non-API routes
app.get(/^\/(?!api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, '../client/build/index.html'));
});


// --------------------- HTTPS SERVER ---------------------

https.createServer(sslOptions, app).listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Secure API running at https://0.0.0.0:${PORT}`);
});
