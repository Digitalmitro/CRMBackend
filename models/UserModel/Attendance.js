const mongoose = require("mongoose");

const attendanceSchema = new mongoose.Schema(
  {
    userName: { type: String },
    userEmail: { type: String },
    currentDate: { type: Date },
    punches: [
      {
        punchIn: { type: Date },
        punchOut: { type: Date },
        workingTime: { type: Number, default: 0 },
      },
    ],
    shiftType:{
      type:String,
      enum:['Day', 'Night']
    },
    totalWorkingTime: { type: Number, default: 0 },
    ip: { type: String },
    status: {
      type: String,
      enum: ["On Time", "Late"],
    },
    workStatus :{
      type: String,
      enum: ["Half Day", "Full Day", "Over Time", "Absent"],  
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
