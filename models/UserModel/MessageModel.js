const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  messages: [
    {
      senderId: { type: String },
      receiverId: { type: String },
      name: { type: String },
      email: { type: String },
      image: { type: String },
      message: { type: String },
      time: { type: Date },
      role: {
        type: String,
        enum: ["admin", "user"]
      },
      status: { type: String },
    },
  ],
  date: { type: String },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "register user",
    required: true,
  },
}, {timestamps: true});

const MessageModel = mongoose.model("message", messageSchema);

module.exports = { MessageModel };
