require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { z } = require('zod');
const dbConnect = require('./db-connect');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
dbConnect();

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error(JSON.stringify({ level: 'fatal', message: 'JWT_SECRET is required' }));
  process.exit(1);
}

// Shared-volume file logging (one file per pod)
const LOG_DIR = process.env.LOG_DIR || './logs';
const INSTANCE_ID = process.env.INSTANCE_ID || 'local';
let LOG_FILE = null;
try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  LOG_FILE = path.join(LOG_DIR, `login-${INSTANCE_ID}.log`);
} catch (e) {
  console.error(JSON.stringify({ level: 'warn', service: 'login', message: 'File logging disabled', error: e.message }));
}

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'login',
      instance: INSTANCE_ID,
      requestId: req.headers['x-request-id'] || 'none',
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start
    });
    console.log(line);
    if (LOG_FILE) fs.appendFile(LOG_FILE, line + '\n', () => {});
  });
  next();
});

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, index: true },
  password: { type: String, required: true },
  role: { type: String, required: true }
});
const User = mongoose.model('User', userSchema);

const loginSchema = z.object({
  email: z.string().trim().email('Valid email is required'),
  password: z.string().min(1, 'Password is required')
});

app.get('/health', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    status: dbReady ? 'ok' : 'degraded',
    service: 'login',
    dbConnected: dbReady
  });
});

app.post('/api/v1/auth/login', async (req, res, next) => {
  try {
    const parsed = loginSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: parsed.error.issues[0].message,
        requestId: req.headers['x-request-id']
      });
    }

    const { email, password } = parsed.data;
    const user = await User.findOne({ email: email.toLowerCase() }).lean();
    if (!user) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
        requestId: req.headers['x-request-id']
      });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
        requestId: req.headers['x-request-id']
      });
    }

    const token = jwt.sign(
      { userId: String(user._id), id: String(user._id), role: user.role },
      JWT_SECRET,
      { expiresIn: '2h' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      expiresIn: '2h',
      role: user.role,
      userId: user._id
    });
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', service: 'login', requestId: req.headers['x-request-id'], error: err.message }));
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId: req.headers['x-request-id'] });
});

const PORT = process.env.PORT || 8002;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'login', message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
});