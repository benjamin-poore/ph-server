const mongoose = require("mongoose");
const { v4: uuidv4 } = require('uuid')

const Schema = mongoose.Schema

const domain = new Schema({
  url: { type: String, required: true, unique: true },
  secret: {
    type:String,
    default: uuidv4()
  },
  refreshSecret: {
    type:String,
    default: uuidv4()
  },
  ttlAccess: {
    // jwtExpiration: 3600,         // 1 hour
    type: Number,
    default: 60 
  },
  ttlRefresh: {
    // jwtRefreshExpiration: 86400, // 24 hours
    type: Number,
    default: 120 
  }
});

const model = mongoose.model("Domain", domain);

module.exports = model;