const express = require("express");

const secretKey = '1a3f7d9e2c5h8k0o3w6s9v2b4x7z1q3u5t8m0l2n'; 
const jwt = require('jsonwebtoken');


function verifyToken(req, res, next) {
    const token = req.cookies.jwt;

  if (!token) {
    return res.status(401).json({ success: false, message: "Unauthorized" });  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.clearCookie('jwt').status(401).json({ success: false, message: "Unauthorized" });    }
    req.user = decoded;
    next();
  });
}
module.exports = verifyToken;