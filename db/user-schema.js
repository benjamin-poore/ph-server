const mongoose = require("mongoose");
const { v4: uuidv4 } = require('uuid')

const Schema = mongoose.Schema

const user = new Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  },
  role: {
    type: [String],
    default: ["user"]
  },

  refreshToken: [String]
});

user.index({ email: 1, domain: 1 }, { unique: true });
const model = mongoose.model("User", user);

module.exports = model;

