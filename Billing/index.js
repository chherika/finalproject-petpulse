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
  LOG_FILE = path.join(LOG_DIR, `billing-${INSTANCE_ID}.log`);
} catch (e) {
  console.error(JSON.stringify({ level: 'warn', service: 'billing', message: 'File logging disabled', error: e.message }));
}

app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const line = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'billing',
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

const invoiceSchema = new mongoose.Schema({
  appointmentId: { type: String, required: true, index: true },
  ownerId: { type: String, required: true, index: true },
  amount: { type: Number, required: true, min: 0.01 },
  status: { type: String, enum: ['UNPAID', 'PAID'], default: 'UNPAID' }
}, { timestamps: true });

const Invoice = mongoose.model('Invoice', invoiceSchema);

const objectIdRegex = /^[0-9a-fA-F]{24}$/;
const createInvoiceSchema = z.object({
  appointmentId: z.string().regex(objectIdRegex, 'Invalid appointmentId format'),
  ownerId: z.string().regex(objectIdRegex, 'Invalid ownerId format'),
  amount: z.number().positive('Amount must be greater than 0')
});

const payInvoiceSchema = z.object({
  invoiceId: z.string().regex(objectIdRegex, 'Invalid invoiceId format')
});

app.get('/health', (req, res) => {
  const dbReady = mongoose.connection.readyState === 1;
  res.status(dbReady ? 200 : 503).json({
    status: dbReady ? 'ok' : 'degraded',
    service: 'billing',
    dbConnected: dbReady
  });
});

app.post('/api/v1/billing/invoices', async (req, res, next) => {
  try {
    const requesterRole = req.headers['x-user-role'];
    if (!['vet', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Only Vets and Admins can create invoices' });
    }

    const parsed = createInvoiceSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: parsed.error.issues[0].message });
    }

    const invoice = await Invoice.create(parsed.data);
    res.status(201).json({ success: true, invoice });
  } catch (err) {
    next(err);
  }
});

app.post('/api/v1/billing/pay', async (req, res, next) => {
  try {
    const parsed = payInvoiceSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ success: false, code: 'VALIDATION_ERROR', message: parsed.error.issues[0].message });
    }

    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];

    const invoice = await Invoice.findById(parsed.data.invoiceId);
    if (!invoice) return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Invoice not found' });

    const allowed = requesterRole === 'admin' || (requesterRole === 'owner' && invoice.ownerId === requesterId);
    if (!allowed) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'You can only pay your own invoices' });
    }
    if (invoice.status === 'PAID') {
      return res.status(409).json({ success: false, code: 'ALREADY_PAID', message: 'Invoice already paid' });
    }

    invoice.status = 'PAID';
    await invoice.save();

    res.json({ success: true, message: 'Payment processed successfully', invoice });
  } catch (err) {
    next(err);
  }
});

app.get('/api/v1/billing/invoices', async (req, res, next) => {
  try {
    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];

    if (!['owner', 'vet', 'admin'].includes(requesterRole)) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'Unauthorized role' });
    }

    const filter = requesterRole === 'owner' ? { ownerId: requesterId } : {};
    const invoices = await Invoice.find(filter).sort({ createdAt: -1 }).lean();
    res.json({ success: true, count: invoices.length, invoices });
  } catch (err) {
    next(err);
  }
});

app.get('/api/v1/billing/invoices/:id', async (req, res, next) => {
  try {
    if (!objectIdRegex.test(req.params.id)) {
      return res.status(400).json({ success: false, code: 'INVALID_ID', message: 'Invalid Invoice ID format' });
    }

    const requesterId = req.headers['x-user-id'];
    const requesterRole = req.headers['x-user-role'];

    const invoice = await Invoice.findById(req.params.id).lean();
    if (!invoice) return res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Invoice not found' });

    if (requesterRole === 'owner' && invoice.ownerId !== requesterId) {
      return res.status(403).json({ success: false, code: 'FORBIDDEN', message: 'You can only view your own invoices' });
    }

    res.json({ success: true, invoice });
  } catch (err) {
    next(err);
  }
});

app.use((err, req, res, next) => {
  console.error(JSON.stringify({ level: 'error', service: 'billing', requestId: req.headers['x-request-id'], error: err.message }));
  res.status(500).json({ success: false, code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', requestId: req.headers['x-request-id'] });
});

const PORT = process.env.PORT || 8006;
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'billing', message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(async () => {
    await mongoose.connection.close();
    process.exit(0);
  });
});