"use strict";

var express = require("express");

var router = express.Router();

var path = require("path");

var multer = require('multer');

var crypto = require('crypto');

var verifyToken = require('../routes/middleware/auth');

var mongoose = require('mongoose');

var _require = require("../models/dbSchema.cjs"),
    User = _require.User;

var _require2 = require("../models/dbSchema.cjs"),
    DevLinks = _require2.DevLinks;

router.post("/createLink", function _callee(req, res) {
  var link;
  return regeneratorRuntime.async(function _callee$(_context) {
    while (1) {
      switch (_context.prev = _context.next) {
        case 0:
          _context.prev = 0;
          link = new DevLinks({
            platform: req.body.platform,
            url: req.body.url,
            owner: req.user.userId
          });
          _context.next = 4;
          return regeneratorRuntime.awrap(link.save());

        case 4:
          res.status(200).json({
            message: 'link successfully created'
          });
          _context.next = 10;
          break;

        case 7:
          _context.prev = 7;
          _context.t0 = _context["catch"](0);
          console.log("error trying to create link ", _context.t0);

        case 10:
        case "end":
          return _context.stop();
      }
    }
  }, null, null, [[0, 7]]);
});
router.get("/getProfile", function _callee2(req, res) {
  var userId, userIdObjectId, userLinks;
  return regeneratorRuntime.async(function _callee2$(_context2) {
    while (1) {
      switch (_context2.prev = _context2.next) {
        case 0:
          _context2.prev = 0;
          userId = req.user.userId;
          userIdObjectId = new mongoose.Types.ObjectId(userId);
          _context2.next = 5;
          return regeneratorRuntime.awrap(DevLinks.find({
            'Owner': userIdObjectId
          }));

        case 5:
          userLinks = _context2.sent;

          if (userLinks > 0) {
            res.json(userLinks);
          }

          _context2.next = 12;
          break;

        case 9:
          _context2.prev = 9;
          _context2.t0 = _context2["catch"](0);
          res.status(500).json({
            error: "An error occurred"
          });

        case 12:
        case "end":
          return _context2.stop();
      }
    }
  }, null, null, [[0, 9]]);
});
module.exports = router;