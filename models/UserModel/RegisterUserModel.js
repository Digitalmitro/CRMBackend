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

registeruserSchema.methods.generateAuthToken = async function () {
  try {
    // const expirationTime = Math.floor(Date.now() / 1000) + (60 * 60);
    const expirationTime = process.env.expiry
    let token = jwt.sign({ _id: this._id, exp: expirationTime }, process.env.secret_key);
    return token;
  } catch (e) {
    console.log(`Failed to generate token --> ${e}`);
  }
};

const RegisteruserModal = mongoose.model(
  "register user",
  registeruserSchema
);

module.exports = { RegisteruserModal };
