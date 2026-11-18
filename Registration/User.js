const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true, index: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['owner', 'vet', 'admin'], default: 'owner' },
  phone: { type: String, required: true, trim: true }
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);