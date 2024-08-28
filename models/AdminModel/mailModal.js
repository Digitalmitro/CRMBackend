const mongoose = require("mongoose");

const mailSchema = new mongoose.Schema({
    BasicWebMailIntro:{type: String},
    BasicWebMailMainBody:{type: String},
    BasicWebMailList:{type: String},
    BasicWebMailConclude:{type: String},
    BasicWebMailLink:{type: [String]},

    DmMailIntro:{type: String},
    DmMailMainBody:{type: String},
    DmMailList:{type: String},
    DmMailConclude:{type: String},
    DmMailLink:{type: [String]},

    EcomMailIntro:{type: String},
    EcomMailMainBody:{type: String},
    EcmoMailList:{type: String},
    EcomMailConclude:{type: String},
    EcomMailLink:{type: [String]},

    SeoMailIntro:{type: String},
    SeoMailMainBody:{type: String},
    SeoMailList:{type: String},
    SeoMailConclude:{type: String},
    SeoMailLink:{type: [String]},

    SmoMailIntro:{type: String},
    SmoMailMainBody:{type: String},
    SmoMailList:{type: String},
    SmoMailConclude:{type: String},
    SmoMailLink:{type: [String]},

    user_id: {type: mongoose.Schema.Types.ObjectId, ref: 'register admin', required: true}
});

const MailModel = mongoose.model("mail", mailSchema);

module.exports = { MailModel };


