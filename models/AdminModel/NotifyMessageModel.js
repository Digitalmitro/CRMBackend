const mongoose = require("mongoose");

const msgnotificationSchema = new mongoose.Schema({
   senderName:  {type: String},
   Date :  {type: String},
   status :  {type: Boolean},
   message: [String],
   senderId : {type:String},
   receiverId : {type:String}
},{timestamps:true});

const NotifyMessageModel = mongoose.model("notifymessage", msgnotificationSchema);

module.exports = { NotifyMessageModel };
