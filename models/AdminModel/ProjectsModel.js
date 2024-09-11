const mongoose = require("mongoose");

const taskSchema = new mongoose.Schema({
  taskname: { type: String },
  assigneeName: { type: String },
  assigneeId: { type: String },
  comments : {type : String},
  deadline: { type: Date },
  status: { 
    type: String, default:"pending"
   },
  priority: { type: String },
});

const projectSchema = new mongoose.Schema({
  projectName: { type: String },
  tasks: [taskSchema],
  createdAt: { type: Date },
},{timestamps:true});
const ProjectsModel = mongoose.model("projects", projectSchema);

module.exports = { ProjectsModel };
