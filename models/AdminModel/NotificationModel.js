const mongoose = require("mongoose");

const notificationSchema = new mongoose.Schema({
   name:  {type: String},
   Date :  {type: String},
   Status :  {type: Boolean},
   message: {type: String}
});

const NotificationModel = mongoose.model("notification", notificationSchema);

module.exports = { NotificationModel };
