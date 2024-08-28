const mongoose = require("mongoose");
const jwt = require('jsonwebtoken')

const registeradminSchema = mongoose.Schema({
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
  mailData: [{ type: mongoose.Schema.Types.ObjectId, ref: "mail" }],
});


registeradminSchema.methods.generateAuthToken = async function () {
  try {
    // const expirationTime = Math.floor(Date.now() / 1000) + (60 * 60);
    const expirationTime = process.env.expiry
    let token = jwt.sign({ _id: this._id, expiresIn: expirationTime }, process.env.secret_key);
    return token;
  } catch (e) {
    console.log(`Failed to generate token --> ${e}`);
  }
};

const RegisteradminModal = mongoose.model(
  "register admin",
  registeradminSchema
);

module.exports = { RegisteradminModal };
