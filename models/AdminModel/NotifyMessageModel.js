const mongoose = require("mongoose");

const msgnotificationSchema = new mongoose.Schema({
   senderName:  {type: String},
   Date :  {type: String},
   status :  {type: Boolean},
   message: [{type: String}],
   senderId : {type:String},
   receiverId : {type:String}
});

const NotifyMessageModel = mongoose.model("notifymessage", msgnotificationSchema);

module.exports = { NotifyMessageModel };
