require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const mongoose = require('mongoose');
const { z } = require('zod');
const dbConnect = require('./db-connect');

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
  LOG_FILE = path.join(LOG_DIR, `appointment-${INSTANCE_ID}.log`);
} catch (e) {
  console.error(JSON.stringify({ level: 'warn', service: 'appointment', message: 'File logging disabled', error: e.message }));
}

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'appointment',
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

const appointmentSchema = new mongoose.Schema({
  petId: { type: String, required: true, index: true },
  ownerId: { type: String, required: true, index: true },
  vetId: { type: String, required: true, index: true },
  appointmentDate: { type: Date, required: true },
  status: { type: String, enum: ['Scheduled', 'Completed', 'Cancelled'], default: 'Scheduled' }
}, { timestamps: true });
const Appointment = mongoose.model('Appointment', appointmentSchema);

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const createApptSchema = z.object({
  petId: z.string().regex(objectIdRegex, 'Invalid petId format'),
  vetId: z.string().regex(objectIdRegex, 'Invalid vetId format'),
  appointmentDate: z.string().refine((val) => !isNaN(Date.parse(val)), 'Invalid appointmentDate format')
});

const statusUpdateSchema = z.object({
  status: z.enum(['Scheduled', 'Completed', 'Cancelled'])
});

app.get('/health', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    status: dbReady ? 'ok' : 'degraded',
    service: 'appointment',
    dbConnected: dbReady
  });
});

app.post('/api/v1/appointments', async (req, res, next) => {
  try {
    const requesterRole = req.headers['x-user-role'];
    if (!['owner', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Only owners can book appointments' });
    }

    const parsed = createApptSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: parsed.error.issues[0].message });
    }

    const ownerId = req.headers['x-user-id'];
    const appointment = await Appointment.create({
      petId: parsed.data.petId,
      ownerId,
      vetId: parsed.data.vetId,
      appointmentDate: new Date(parsed.data.appointmentDate)
    });

    res.status(201).json({ success: true, appointment });
  } catch (err) {
    next(err);
  }
});

app.get('/api/v1/appointments/vet/:vetId', async (req, res, next) => {
  try {
    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];
    const allowed = requesterRole === 'admin' || (requesterRole === 'vet' && requesterId === req.params.vetId);
    if (!allowed) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Cannot view this schedule' });
    }

    const list = await Appointment.find({ vetId: req.params.vetId }).sort({ appointmentDate: 1 }).lean();
    res.json({ success: true, list });
  } catch (err) {
    next(err);
  }
});

app.get('/api/v1/appointments/owner/:ownerId', async (req, res, next) => {
  try {
    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];
    const allowed = requesterRole === 'admin' || (requesterRole === 'owner' && requesterId === req.params.ownerId);
    if (!allowed) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Cannot view these appointments' });
    }

    const list = await Appointment.find({ ownerId: req.params.ownerId }).sort({ appointmentDate: -1 }).lean();
    res.json({ success: true, list });
  } catch (err) {
    next(err);
  }
});

app.patch('/api/v1/appointments/:id/status', async (req, res, next) => {
  try {
    const requesterRole = req.headers['x-user-role'];
    if (!['vet', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Only Vets and Admins can update status' });
    }
    if (!objectIdRegex.test(req.params.id)) {
      return res.status(400).json({ success: false, code: 'INVALID_ID', message: 'Invalid Appointment ID format' });
    }

    const parsed = statusUpdateSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: parsed.error.issues[0].message });
    }

    const updated = await Appointment.findByIdAndUpdate(
      req.params.id,
      { status: parsed.data.status },
      { new: true, runValidators: true }
    );
    if (!updated) return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Appointment not found' });

    res.json({ success: true, updated });
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', service: 'appointment', requestId: req.headers['x-request-id'], error: err.message }));
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId: req.headers['x-request-id'] });
});

const PORT = process.env.PORT || 8004;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'appointment', message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
});