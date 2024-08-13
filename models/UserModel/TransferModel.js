const mongoose = require("mongoose");

const transferSchema = new mongoose.Schema({
  employeeName: { type: String },
  employeeEmail: { type: String },
  name: { type: String },
  email: { type: String},
  phone: { type: String, required: true },
  transferTo: { type: String },
  address: { type: String },
  domainName: { type: String },
  country: { type: String },
  zipcode: { type: String },
  comments: { type: String },
  buget: { type: String },
  calldate: { type: String },
  createdDate: {type: String},
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "register user",
    required: true,
  },
});

const TransferModel = mongoose.model("transfer", transferSchema);

module.exports = { TransferModel };
