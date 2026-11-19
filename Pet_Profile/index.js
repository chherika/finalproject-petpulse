require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const fs = require('fs');
const path = require('path');
const { z } = require('zod');
const dbConnect = require('./db-connect');

const app = express();
const PORT = process.env.PORT || 8003;
const INSTANCE_ID = process.env.INSTANCE_ID || `Pet-Service-Port-${PORT}`;

// Shared Volume Log Setup (for Kubernetes emptyDir + log-sidecar)
const LOG_DIR = process.env.LOG_DIR || './logs';
fs.mkdirSync(LOG_DIR, { recursive: true });
const LOG_FILE = path.join(LOG_DIR, 'pet.log');

app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
dbConnect();

// Structured JSON Access Logging (writes to both stdout and shared volume file)
app.use((req, res, next) => {
  const start = Date.now();
  res.setHeader('X-Served-By', INSTANCE_ID);
  res.on('finish', () => {
    const logLine = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'pet-service',
      instance: INSTANCE_ID,
      requestId: req.headers['x-request-id'] || 'none',
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start
    });
    console.log(logLine);
    fs.appendFile(LOG_FILE, logLine + '\n', () => {});
  });
  next();
});

const petSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  species: { type: String, required: true, trim: true },
  breed: { type: String, trim: true },
  age: { type: Number, min: 0 },
  ownerId: { type: String, required: true, index: true },
  medicalHistory: [{ type: String, trim: true }]
}, { timestamps: true });
const Pet = mongoose.model('Pet', petSchema);

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const createPetSchema = z.object({
  name: z.string().trim().min(1, 'Pet name is required').max(60),
  species: z.string().trim().min(1, 'Species is required').max(40),
  breed: z.string().trim().max(60).optional(),
  age: z.number().min(0).max(100).optional(),
  medicalHistory: z.array(z.string().trim()).optional().default([])
});

const medicalRecordSchema = z.object({
  record: z.string().trim().min(3, 'Medical record note must be at least 3 characters').max(500)
});

// Kubernetes Readiness & Liveness Probe
app.get('/health', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    status: dbReady ? 'ok' : 'degraded',
    service: 'pet-service',
    instance: INSTANCE_ID,
    dbConnected: dbReady
  });
});

// Load Balancer Visual Proof Page
app.get('/demo', (req, res) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>PetPulse Load Balancer</title></head>
      <body style="font-family: sans-serif; margin: 40px;">
        <h1>Load Balanced Distributed System</h1>
        <p><strong>Served by Pod / Instance:</strong> ${INSTANCE_ID}</p>
        <p><strong>Timestamp:</strong> ${new Date().toISOString()}</p>
      </body>
    </html>
  `);
});

// Create Pet
app.post('/api/v1/pets', async (req, res, next) => {
  try {
    const requesterId = req.headers['x-user-id'];
    if (!requesterId) {
      return res.status(401).json({ success: false, code: 'UNAUTHORIZED', message: 'Missing user context' });
    }

    const parsed = createPetSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({
        success: false,
        code: 'VALIDATION_ERROR',
        message: parsed.error.issues[0].message,
        requestId: req.headers['x-request-id']
      });
    }

    const pet = await Pet.create({ ...parsed.data, ownerId: requesterId });
    res.status(201).json({ success: true, instance: INSTANCE_ID, pet });
  } catch (err) {
    next(err);
  }
});

// Get Pets by Owner
app.get('/api/v1/pets/owner/:ownerId', async (req, res, next) => {
  try {
    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];

    if (requesterRole === 'owner' && requesterId !== req.params.ownerId) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Cannot access other users pets' });
    }

    const pets = await Pet.find({ ownerId: req.params.ownerId }).lean();
    res.json({ success: true, instance: INSTANCE_ID, pets });
  } catch (err) {
    next(err);
  }
});

// Update Medical Records (Vet & Admin only)
app.put('/api/v1/pets/:id/medical-records', async (req, res, next) => {
  try {
    const requesterRole = req.headers['x-user-role'];
    if (!['vet', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Only Vets and Admins can edit medical records' });
    }
    if (!objectIdRegex.test(req.params.id)) {
      return res.status(400).json({ success: false, code: 'INVALID_ID', message: 'Invalid Pet ID format' });
    }

    const parsed = medicalRecordSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: parsed.error.issues[0].message });
    }

    const pet = await Pet.findByIdAndUpdate(
      req.params.id,
      { $push: { medicalHistory: parsed.data.record } },
      { new: true }
    );
    if (!pet) return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Pet record not found' });

    res.json({ success: true, instance: INSTANCE_ID, pet });
  } catch (err) {
    next(err);
  }
});

// Centralized Error Handler
app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', service: 'pet-service', instance: INSTANCE_ID, requestId: req.headers['x-request-id'], error: err.message }));
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId: req.headers['x-request-id'] });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'pet-service', instance: INSTANCE_ID, message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
});