"use strict";

var express = require("express");

var path = require('path');

var bcrypt = require('bcrypt');

var multer = require('multer');

var app = express();

var cors = require('cors');

var jwt = require('jsonwebtoken');

var _require = require("./models/dbSchema.cjs"),
    User = _require.User;

var _require2 = require("./models/dbSchema.cjs"),
    DevLinks = _require2.DevLinks;

var api = require("./routes/api.cjs");

app.use(express.json());
app.use(express["static"]('client'));
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
  extended: true
}));
app.use('/', express["static"](path.join(__dirname, 'client', 'public')));
mongoose.connect("mongodb://127.0.0.1:27017/linksharing-db", {
  useNewUrlParser: true
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
app.listen(5000, function () {
  console.log("server started");
});