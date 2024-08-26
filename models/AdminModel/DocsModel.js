const mongoose = require("mongoose");

const docsSchema = new mongoose.Schema({
  docsName: { type: String },
  assigneeName: { type: String },
  projectName: { type: String },
  docs: { type: String },
});

const DocsModel = mongoose.model("documents", docsSchema);

module.exports = { DocsModel };