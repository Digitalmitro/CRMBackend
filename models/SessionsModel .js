const mongoose = require("mongoose");
// const jwt = require('jsonwebtoken')

const sessionSchema = new mongoose.Schema({
    userId: mongoose.Schema.Types.ObjectId,
    token: String,
    createdAt: { type: Date, default: Date.now, expires: '2d' } // Token expiry
  });
  
  const SessionModel = mongoose.model('Session', sessionSchema);