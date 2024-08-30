const mongoose = require("mongoose");

const projectsSchema = new mongoose.Schema({
   projectName: {type: String},
   TaskId: {}
});

const ProjectsModel = mongoose.model("projects", projectsSchema);

module.exports = { ProjectsModel };
