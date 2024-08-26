const mongoose = require("mongoose");

const registeruserSchema = mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  phone: {
    type: Number,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  aliceName: {
    type: String,
  },
  type: {
    type: String,
    required: true,
  },
  callback: [
    { type: mongoose.Schema.Types.ObjectId, ref: "callback" },
  ],
  transfer: [
    { type: mongoose.Schema.Types.ObjectId, ref: "transfer" },
  ],
  sale: [
    { type: mongoose.Schema.Types.ObjectId, ref: "sale" },
  ],
  attendance: [
    { type: mongoose.Schema.Types.ObjectId, ref: "attendance" },
  ],
  message: [{ type: mongoose.Schema.Types.ObjectId, ref: "message" }],
  concern: [{ type: mongoose.Schema.Types.ObjectId, ref: "concern" }],

  image: { type: mongoose.Schema.Types.ObjectId, ref: "image" },
  notes: { type: mongoose.Schema.Types.ObjectId, ref: "notes" },

  
});

const RegisteruserModal = mongoose.model(
  "register user",
  registeruserSchema
);

module.exports = { RegisteruserModal };
