"use strict";

var dotenv = require("dotenv");

var express = require("express");

var path = require('path');

var bcrypt = require('bcrypt');

var multer = require('multer');

var app = express();

var cors = require('cors');

var mongoose = require('mongoose');

var bodyParser = require('body-parser');

var jwt = require('jsonwebtoken');

var helmet = require('helmet');

var _require = require("./models/dbSchema.cjs"),
    User = _require.User;

var _require2 = require("./models/dbSchema.cjs"),
    DevLinks = _require2.DevLinks;

var config = require("./config/config");

var api = require("./routes/api.cjs");

dotenv.config();

var cookieParser = require('cookie-parser');

app.use(cookieParser());
app.use(express.json({
  limit: '10mb'
}));

var verifyToken = require("./routes/middleware/auth.cjs");

var port = config.port,
    allowedDomains = config.allowedDomains,
    mongodb_connect = config.mongodb_connect;
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));
app.use(helmet());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use(express.urlencoded({
  limit: '10mb',
  extended: true
}));
app.use(cookieParser());
app.use(express["static"](path.join(__dirname)));
app.use(express["static"](path.join(__dirname, '..', "linksharing", 'build')));
mongoose.connect(process.env.MONGODB_CONNECT, {
  useNewUrlParser: true
});
app.get('*', function (req, res) {
  res.sendFile(path.join(__dirname, '..', 'linksharing', 'build', 'index.html'));
});
app.post('/api/protected', verifyToken, function (req, res) {
  res.json({
    success: true,
    message: 'You have access to protected data'
  });
});
var db = mongoose.connection;
db.on("error", function (error) {
  console.log("error");
});
db.once("open", function () {
  console.log("db conntected");
});
app.use(function (req, res, next) {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use("/api", api);
app.listen(process.env.PORT, function () {
  console.log("server started");
});