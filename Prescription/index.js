require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const { z } = require('zod');
const dbConnect = require('./db-connect');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
dbConnect();

// Shared-volume file logging (one file per pod)
const LOG_DIR = process.env.LOG_DIR || './logs';
const INSTANCE_ID = process.env.INSTANCE_ID || 'local';
let LOG_FILE = null;
try {
  fs.mkdirSync(LOG_DIR, { recursive: true });
  LOG_FILE = path.join(LOG_DIR, `prescription-${INSTANCE_ID}.log`);
} catch (e) {
  console.error(JSON.stringify({ level: 'warn', service: 'prescription', message: 'File logging disabled', error: e.message }));
}

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'prescription',
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

const prescriptionSchema = new mongoose.Schema({
  petId: { type: String, required: true, index: true },
  ownerId: { type: String, required: true, index: true },
  vetId: { type: String, required: true, index: true },
  diagnosis: { type: String, required: true, trim: true },
  medicines: [{
    name: { type: String, required: true, trim: true },
    dosage: { type: String, required: true, trim: true },
    duration: { type: String, required: true, trim: true }
  }],
  status: { type: String, enum: ['Issued', 'Dispensed'], default: 'Issued' }
}, { timestamps: true });
const Prescription = mongoose.model('Prescription', prescriptionSchema);

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const createPrescriptionSchema = z.object({
  petId: z.string().regex(objectIdRegex, 'Invalid petId format'),
  ownerId: z.string().regex(objectIdRegex, 'Invalid ownerId format'),
  diagnosis: z.string().trim().min(2, 'Diagnosis is required').max(300),
  medicines: z.array(z.object({
    name: z.string().trim().min(1),
    dosage: z.string().trim().min(1),
    duration: z.string().trim().min(1)
  })).min(1, 'At least one medicine is required')
});

app.get('/health', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    status: dbReady ? 'ok' : 'degraded',
    service: 'prescription',
    dbConnected: dbReady
  });
});

app.post('/api/v1/prescriptions', async (req, res, next) => {
  try {
    const requesterRole = req.headers['x-user-role'];
    if (!['vet', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Only Vets and Admins can issue prescriptions' });
    }

    const parsed = createPrescriptionSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: parsed.error.issues[0].message });
    }

    const vetId = req.headers['x-user-id'];
    const prescription = await Prescription.create({ ...parsed.data, vetId });
    res.status(201).json({ success: true, prescription });
  } catch (err) {
    next(err);
  }
});

app.get('/api/v1/prescriptions/pet/:petId', async (req, res, next) => {
  try {
    if (!objectIdRegex.test(req.params.petId)) {
      return res.status(400).json({ success: false, code: 'INVALID_ID', message: 'Invalid Pet ID format' });
    }

    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];
    const filter = { petId: req.params.petId };
    if (requesterRole === 'owner') filter.ownerId = requesterId;

    const list = await Prescription.find(filter).sort({ createdAt: -1 }).lean();
    res.json({ success: true, list });
  } catch (err) {
    next(err);
  }
});

app.patch('/api/v1/prescriptions/:id/dispense', async (req, res, next) => {
  try {
    const requesterRole = req.headers['x-user-role'];
    if (!['vet', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Access denied' });
    }
    if (!objectIdRegex.test(req.params.id)) {
      return res.status(400).json({ success: false, code: 'INVALID_ID', message: 'Invalid Prescription ID format' });
    }

    const item = await Prescription.findByIdAndUpdate(req.params.id, { status: 'Dispensed' }, { new: true });
    if (!item) return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Prescription not found' });

    res.json({ success: true, item });
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', service: 'prescription', requestId: req.headers['x-request-id'], error: err.message }));
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId: req.headers['x-request-id'] });
});

const PORT = process.env.PORT || 8005;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'prescription', message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
});