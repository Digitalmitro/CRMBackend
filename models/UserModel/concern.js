// name, email, concern, date, status, user_id 

const mongoose = require("mongoose");

const concernSchema = new mongoose.Schema({
 
    name: { type: String },
    email: { type: String },
    ConcernDate: { type: String },
    ActualPunchIn: { type: String },
    ActualPunchOut: { type: String },
    message: { type: String },
    currenDate: { type: String },
    status: { type: String },
    punchType: { type: String },
    
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "register user",
    required: true,
  },
}, {timestamps: true});

const ConcernModel = mongoose.model("concern",concernSchema);

module.exports = { ConcernModel };
