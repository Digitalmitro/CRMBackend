const mongoose = require("mongoose");

const holidaySchema = new mongoose.Schema(
  {
    holiday: Date,
    status: {
      type: Boolean,
      default: true,
    },
    label: {
      type: String,
      default: "",
    },
  },
  { timestamps: true }
);

const HolidayModel = mongoose.model("holidays", holidaySchema);

module.exports = { HolidayModel };
