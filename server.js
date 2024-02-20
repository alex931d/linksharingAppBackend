const dotenv = require("dotenv");
const express = require("express")
var path = require('path');
const bcrypt = require('bcrypt');
const multer = require('multer');
const app = express();
const cors = require('cors'); 
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const { User } = require("./models/dbSchema.cjs");
const { DevLinks } = require("./models/dbSchema.cjs");
const config = require("./config/config")
const api = require("./routes/api.cjs");
dotenv.config();
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.use(express.json({ limit: '10mb' }));
const verifyToken = require("./routes/middleware/auth.cjs");
const {port,allowedDomains,mongodb_connect} =  config;



app.use(cors({
  origin: "https://linksharingappfrontend.onrender.com",
  credentials: true,
}));

app.use(helmet({
  referrerPolicy: {
    policy: 'strict-origin-when-cross-origin'
  }
}));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname)));

mongoose.connect(process.env.MONGODB_CONNECT, {
  useNewUrlParser: true
});



app.post('/api/protected', verifyToken, (req, res) => {
  res.json({ success: true, message: 'You have access to protected data' });
});


const db = mongoose.connection
db.on("error",(error)=>{
    console.log("error");
})
db.once("open",()=>{
    console.log("db conntected")
})
app.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  
  app.use("/api",api);

  app.listen(process.env.PORT,()=>{
    console.log("server started");
  })