require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const dbConnect = require('./db-connect');
const User = require('./User');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '10kb' }));
dbConnect();

// Shared-volume file logging (one file per pod)
const LOG_DIR = process.env.LOG_DIR || './logs';
const INSTANCE_ID = process.env.INSTANCE_ID || 'local';
let LOG_FILE = null;
try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  LOG_FILE = path.join(LOG_DIR, `registration-${INSTANCE_ID}.log`);
} catch (e) {
  console.error(JSON.stringify({ level: 'warn', service: 'registration', message: 'File logging disabled', error: e.message }));
}

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'registration',
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

const registerSchema = z.object({
  name: z.string().trim().min(2, 'Name must be at least 2 characters').max(100),
  email: z.string().trim().email('Invalid email address'),
  password: z.string().min(8, 'Password must be at least 8 characters').max(128),
  phone: z.string().trim().min(6, 'Valid phone number required').max(25),
  role: z.enum(['owner', 'vet']).optional().default('owner'),
  inviteCode: z.string().optional()
});

app.get('/health', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    status: dbReady ? 'ok' : 'degraded',
    service: 'registration',
    dbConnected: dbReady
  });
});

app.post('/api/v1/auth/register', async (req, res, next) => {
  try {
    const parsed = registerSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: parsed.error.issues[0].message,
        requestId: req.headers['x-request-id']
      });
    }

    const { name, email, password, role, phone, inviteCode } = parsed.data;
    const normalizedEmail = email.toLowerCase();

    let assignedRole = 'owner';
    if (role === 'vet') {
      if (!process.env.VET_INVITE_CODE || inviteCode !== process.env.VET_INVITE_CODE) {
        return res.status(403).json({
          success: false,
          code: 'INVALID_INVITE_CODE',
          message: 'Valid invite code required to register as vet',
          requestId: req.headers['x-request-id']
        });
      }
      assignedRole = 'vet';
    }

    const existingUser = await User.findOne({ email: normalizedEmail }).lean();
    if (existingUser) {
      return res.status(409).json({
        success: false,
        code: 'EMAIL_EXISTS',
        message: 'Email already exists',
        requestId: req.headers['x-request-id']
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const newUser = await User.create({
      name,
      email: normalizedEmail,
      password: hashedPassword,
      role: assignedRole,
      phone
    });

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: { id: newUser._id, name: newUser.name, email: newUser.email, role: newUser.role, phone: newUser.phone }
    });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ success: false, code: 'EMAIL_EXISTS', message: 'Email already exists' });
    }
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', service: 'registration', requestId: req.headers['x-request-id'], error: err.message }));
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId: req.headers['x-request-id'] });
});

const PORT = process.env.PORT || 8001;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'registration', message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
});