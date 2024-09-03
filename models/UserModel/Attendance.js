const mongoose = require("mongoose");

const attendanceSchema = new mongoose.Schema(
  {
    userName: { type: String },
    userEmail: { type: String },
    currentDate: { type: Date },
    punchIn: { type: Date },
    punchOut: { type: Date },
    workingTime: { type: Number, default: 0 },
    ip: { type: String },
    status: {
      type: String,
      enum: ["On Time", "Late"],
    },
    user_id: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "register user",
      required: true,
    },
  },
  { timestamps: true }
);

const AttendanceModel = mongoose.model("attendance", attendanceSchema);

module.exports = { AttendanceModel };
