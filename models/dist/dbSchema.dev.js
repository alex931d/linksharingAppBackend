"use strict";

var mongoose = require("mongoose");

var UserSchema = new mongoose.Schema({
  user_email: {
    type: String,
    required: true
  },
  user_password: {
    type: String,
    required: true
  },
  user_role: {
    type: String,
    required: true
  },
  devLinks: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'DevLinks'
  }]
});
var DevLinksSchema = new mongoose.Schema({
  platform: {
    type: String,
    required: true
  },
  url: {
    type: String,
    require: true
  },
  createdAt: {
    type: Date,
    "default": Date.now,
    required: true
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  }
});
var DevLinks = mongoose.model("MainBoard", DevLinksSchema);
var User = mongoose.model("User", UserSchema);
module.exports = {
  User: User,
  DevLinks: DevLinks
};