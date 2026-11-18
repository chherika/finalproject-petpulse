require('dotenv').config();
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const proxy = require('express-http-proxy');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error(JSON.stringify({ level: 'fatal', message: 'JWT_SECRET is required' }));
  process.exit(1);
}

const REGISTRATION_URL = process.env.REGISTRATION_URL || 'http://localhost:8001';
const LOGIN_URL        = process.env.LOGIN_URL        || 'http://localhost:8002';
const APPOINTMENT_URL  = process.env.APPOINTMENT_URL  || 'http://localhost:8004';
const PRESCRIPTION_URL = process.env.PRESCRIPTION_URL || 'http://localhost:8005';
const BILLING_URL      = process.env.BILLING_URL      || 'http://localhost:8006';
const PET_URL          = process.env.PET_URL          || 'http://pet-lb:80';

// 1. Security Headers & Strict CORS
app.disable('x-powered-by');
app.use(helmet());
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost,http://petpulse.com').split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || allowedOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('CORS policy blocked this origin'));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID']
}));

// 2. Distributed Request Correlation ID + Structured Access Logging
app.use((req, res, next) => {
  const start = Date.now();
  const requestId = req.headers['x-request-id'] || crypto.randomUUID();
  req.requestId = requestId;
  res.setHeader('X-Request-ID', requestId);

  // Strip spoofable internal headers
  delete req.headers['x-user-id'];
  delete req.headers['x-user-role'];

  res.on('finish', () => {
    console.log(JSON.stringify({
      timestamp: new Date().toISOString(),
      level: res.statusCode >= 500 ? 'error' : 'info',
      service: 'api-gateway',
      requestId,
      method: req.method,
      path: req.originalUrl,
      status: res.statusCode,
      durationMs: Date.now() - start
    }));
  });
  next();
});

// 3. Rate Limiting (Anti-Brute Force & DDoS Protection)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Max 15 auth attempts per IP per 15 mins
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, code: 'RATE_LIMIT_EXCEEDED', message: 'Too many authentication attempts. Try again in 15 minutes.' }
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 120, // Max 120 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, code: 'RATE_LIMIT_EXCEEDED', message: 'Too many requests. Please slow down.' }
});

// 4. JWT & Role Verification Middleware
const verifyRole = (allowedRoles = []) => (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ success: false, code: 'UNAUTHORIZED', message: 'Access Denied: No token provided', requestId: req.requestId });
  }
  try {
    const decoded = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
    req.user = decoded;
    if (allowedRoles.length > 0 && !allowedRoles.includes(decoded.role)) {
      return res.status(403).json({
        success: false,
        code: 'FORBIDDEN',
        message: `Forbidden: ${String(decoded.role).toUpperCase()} role cannot access this endpoint`,
        requestId: req.requestId
      });
    }
    next();
  } catch (err) {
    return res.status(401).json({ success: false, code: 'INVALID_TOKEN', message: 'Invalid or expired token', requestId: req.requestId });
  }
};

// 5. Proxy Configuration (Forwards Identity + Request ID)
const proxyOptions = {
  parseReqBody: false,
  timeout: 10000,
  proxyReqPathResolver: (req) => req.originalUrl,
  proxyReqOptDecorator: (proxyReqOpts, srcReq) => {
    proxyReqOpts.agent = false; // Force fresh connection for visible round-robin load balancing
    proxyReqOpts.headers['x-request-id'] = srcReq.requestId;
    if (srcReq.user) {
      proxyReqOpts.headers['x-user-id'] = String(srcReq.user.userId || srcReq.user.id);
      proxyReqOpts.headers['x-user-role'] = String(srcReq.user.role);
    }
    return proxyReqOpts;
  },
  proxyErrorHandler: (err, res, next) => {
    console.error(JSON.stringify({ level: 'error', service: 'api-gateway', message: 'Upstream proxy error', error: err.message }));
    res.status(502).json({ success: false, code: 'BAD_GATEWAY', message: 'Upstream microservice unavailable' });
  }
};

const ALL = ['owner', 'vet', 'admin'];

// Health Probe
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'api-gateway', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Public Routes
app.use('/api/v1/auth/register', authLimiter, proxy(REGISTRATION_URL, proxyOptions));
app.use('/api/v1/auth/login',    authLimiter, proxy(LOGIN_URL, proxyOptions));
app.use('/demo',                 apiLimiter,  proxy(PET_URL, proxyOptions));

// Protected Microservice Routes
app.use('/api/v1/pets',          apiLimiter, verifyRole(ALL), proxy(PET_URL, proxyOptions));
app.use('/api/v1/appointments',  apiLimiter, verifyRole(ALL), proxy(APPOINTMENT_URL, proxyOptions));
app.use('/api/v1/billing',       apiLimiter, verifyRole(ALL), proxy(BILLING_URL, proxyOptions));
app.use('/api/v1/prescriptions', apiLimiter, verifyRole(ALL), proxy(PRESCRIPTION_URL, proxyOptions));

// 404 Fallback
app.use((req, res) => {
  res.status(404).json({ success: false, code: 'NOT_FOUND', message: 'Route not found', requestId: req.requestId });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(JSON.stringify({ level: 'info', service: 'api-gateway', message: `Listening on port ${PORT}` }));
});

process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});