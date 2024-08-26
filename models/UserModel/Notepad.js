const mongoose = require("mongoose");

const notesSchema = new mongoose.Schema({
   
    notes: [{ type: String }],
    user_id: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "register user",
        required: true,
    },
});

const NotesModel = mongoose.model("notes", notesSchema);

module.exports = { NotesModel };
