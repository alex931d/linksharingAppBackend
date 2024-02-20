
const express = require("express");
const router = express.Router();
const path = require("path");
const multer = require('multer');
const mime = require('mime-types');
const cookieParser = require('cookie-parser');
const sizeOf = require('image-size');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const fs = require("fs")
const nodemailer = require('nodemailer');
const cors = require('cors');
const bodyParser = require('body-parser');
const verifyToken = require('./middleware/auth.cjs');
const { generateMatchExp } = require("../config/validatePlatforms");
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const { AuditLog } = require("../models/dbSchema.cjs");
const { User } = require("../models/dbSchema.cjs");
const { DevLinks } = require("../models/dbSchema.cjs");
const { OAuth2Client } = require('google-auth-library');
const apiKey = process.env.VIRUS_TOTAL_API_KEY;
const secretKey = process.env.SECRET_KEY; 
const GOOGLE_CLIENT_ID = process.env.GOOGLEOAUTH_API_KEY;

const googleClient = new OAuth2Client(GOOGLE_CLIENT_ID);

const storage = multer.memoryStorage({
  destination: function (req, file, cb) {
    cb(null, `${__dirname}/../../linksharing/public/nonAuthImgs`); 
  },
  filename: function (req, file, cb) {

    cb(null, file.originalname);
  },
});

const upload = multer({ storage: storage });
router.post('/logout',verifyToken,async (req,res)=>{
  try {
    res
    .clearCookie('jwt')
    .status(200).json({ message: 'user successfully logged out' })
  } catch (error) {
    res.status(500).json({ error: "error trying to logout" });
  }
})
router.post('/getuserinfo',verifyToken, async (req, res) => {
  try {
    let user;
    const token = req.cookies.jwt;

    if (!token) {
      return res.status(401).json({ message: 'Unauthorized' });
    }
  
    jwt.verify(token, process.env.SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: 'Invalid token' });
      }
  
      user = decoded;
    });
    const userAuditLogs = await AuditLog.find({ userId: user.userId });
    res.status(200).json({ message: 'user successfully sendt', userInfo: user,userAuditLog: userAuditLogs  });
  } catch (error) {
    res.status(500).json({ error: "failled to send profile" });
  }
   
});
router.post('/closeTour',verifyToken, async (req,res)=>{
  const id = req.body.id;
  try {
    const existingUser = await User.findById(id);

    if (existingUser.firstLogin) {
      existingUser.firstLogin = false;
      await existingUser.save();
    }
    return res.status(200).json({ message: 'tour removed!' });
  } catch (error) {
    return res.status(500).json({ error: "tour error" });
  }
})
router.post("/removeLink", verifyToken, async (req, res) => {
  const { id } = req.body;

  try {
    const DevLink = await DevLinks.findById(req.body.id);

    if (!DevLink) {
      return res.status(500).json({ error: "No devLink exists!" });
    }

    const linkIndex = DevLink.links.findIndex(link => link.id === id);

    if (linkIndex !== -1) {
      DevLink.links.splice(linkIndex, 1);
      await DevLink.save();

      return res.status(200).json({ message: 'Link successfully removed' });
    } else {
      return res.status(500).json({ error: "Link not found" });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "An error occurred" });
  }
});

const logUserEvent = async (userId, eventType, eventDetails) => {
  const user = await User.findById(userId);

  try {
    if (user) {
      const newAuditLog = new AuditLog({
        userId: userId,
        eventType:eventType,
        eventDetails:eventDetails,
      });
      await newAuditLog.save();
    }
  } catch (error) {
    return res.status(500).json({ error: "error logging events in audit log!" });
  }
};

router.put("/updateLinks", verifyToken,upload.array('files'),async (req,res)=>{
   let items = JSON.parse(req.body.items);
   let settings = JSON.parse(req.body.settings);
   let files = req.files;
   let itemIds = JSON.parse(req.body.itemIds)
   const allowedFileTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'application/vnd.google-apps.document'];
    const DevLink = await DevLinks.findById(req.body.id)
    if (!DevLink) {
      return res.status(500).json({error:"no devLink exists!"})
    }    
      try {
        // if there is less then or equals 5 items and settings is not null
        if (items.length <= 5 && Object.keys(settings).length !== 0) {
          
          const promises = itemIds.map(async (itemId) => {
   
            let item = items.find(item => item.id === itemId);
          if (item.url !== '') {
            if (item && item.file && item.itemType === 'files') {
              if (item.name.length !== 0) {
                
        
              const file = files.find(f => f.originalname.includes(`${itemId}_`));
              if (!allowedFileTypes.includes(file.mimetype)) {
                return res.status(400).send('Invalid file type. Allowed types: PDF, DOCX, Google Docs');
              }
              
              const generatedId = crypto.randomBytes(20).toString('hex');
              const devLinkItem = DevLink.items.find(item => item.id === itemId);
              if (item.file && devLinkItem) {
                // If the file already exists, and is uploaded then remove the existing file
                fs.unlink(`${__dirname}/../../linksharing/public/nonAuthFiles/${devLinkItem.url}`, (unlinkError) => {
                  if (unlinkError) {
                    console.error('Error removing existing file:', unlinkError);
                    return Promise.reject({ error: 'Internal server error' });
                  } else {
                    console.log('Existing file removed successfully');
                  }
                });
              }
    
              // Write the new file
              await new Promise((resolve, reject) => {
                fs.writeFile(`${__dirname}/../../linksharing/public/nonAuthFiles/${generatedId}.${mime.extension(file.mimetype)}`, file.buffer, (err) => {
                  if (err) {
                    console.log(err);
                    reject(err);
                  } else {
                    item.url = `${generatedId}.${mime.extension(file.mimetype)}`;
                    item.name = item.name;
                    resolve(item);
                  }
                });
              });
            }
            else{
              res.status(500).json({ error: 'no file name provied in one of your file links!' });
             }
           }
           else if (item && item.itemType === "links" && item.url) {
            const regex = generateMatchExp(item.platform)
            if (!regex.test(item.url)) {
              res.status(500).json({ error: 'url validation failure not correct url for platform' });
          } 
           }
          }
          else{
            res.status(500).json({ error: 'no url provied!' });
          }
            return items;
           });
          // compare the arrays 
          const itemsToRemove = DevLink.items.filter(devLinkItem => {
            return devLinkItem.itemType === 'files' && items.every(item => item._id) && !items.some(item => item._id.toString() === devLinkItem._id.toString());          });
          // Unlink files for items that need to be removed
    
          itemsToRemove.forEach(itemToRemove => {
            fs.unlink(`${__dirname}/../../linksharing/public/nonAuthFiles/${itemToRemove.url}`, (unlinkError) => {
              if (unlinkError) {
                console.error('Error removing existing file:', unlinkError);
              } else {
                console.log('Existing file removed successfully');
              }
            });
          });
        
          const updatedItems = (await Promise.all(promises)).flat();         

        
              DevLinks.findOneAndUpdate(
                { _id: req.body.id },
                {
                   items: updatedItems.length > 0 ? updatedItems : items,
                   $set: settings,
                },
                { new: true }
            )
            .then((devlink) => {
                if (!devlink) {
                    return res.status(404).json({ message: 'devlink not found or updated!' });
                }
                res.status(200).json({ message: 'links successfully updated' });
            })
            .catch((error) => {
                console.log("Error trying to update profile in the database:", error);
                res.status(500).json({ error: 'Internal server error',error });
            });


      }
        else{
          res.status(500).json({ error: "maximum links reached!" });
        }

      } catch (error) {
        res.status(500).json({ error: "An error occurred",error});
      }
  })
  router.post('/upload', upload.single('file'), (req, res) => {
    console.log('File uploaded:', req.file);

    res.json({ success: true, message: 'File uploaded successfully' });
  });
  router.post("/getPreviewData",async(req,res)=>{
    const id = req.body.id;
    try {
      const existingDevlink = await DevLinks.findById(id);
      if (!existingDevlink) {
        return res.status(400).json({ message: 'DevLink dont exists!' });
      }
      res.status(200).json({ message: 'devLink successfully fetched', devLinks: existingDevlink });
    } catch (error) {
      return res.status(401).json({ message: 'error fetching devLink try again!' });
    }
  })

  router.post('/refresh', verifyToken, (req, res) => {
    const { refreshToken } = req.body;

    jwt.verify(refreshToken, process.env.SECRET_KEY, (err, user) => {
      if (err) {
        return res.status(403).json({ error: 'Invalid refresh token' });
      }

      const newAccessToken = jwt.sign({ user: user }, process.env.SECRET_KEY, { expiresIn: '15m' });
  
      res.json({
        token: newAccessToken,
      });
    });
  });
  router.put("/updateUser",async(req,res)=>{
    const id = req.body.id;
    const props = req.body.props;
    try {
      const user = await User.findById(id);
      if (!user) {
        return res.status(400).json({message: 'user not found!'});
      }
      if (Object.keys(props).length !== 0) {
        User.findOneAndUpdate(
          { _id: id },
          {
             $set: props,
          },
          { new: true }
      )
      .then((user) => {
          if (!user) {
              return res.status(404).json({ message: 'user not found or updated!' });
          }
          return res.status(200).json({ message: 'User updated successfully', user: user });
      })
      .catch((error) => {
          console.log("Error trying to update user in the database:", error);
          res.status(500).json({ error: 'Internal server error',error });
      });
      }
      else{
        return res.status(400).json({message: 'no props was passed in!'});
      }
    } catch (error) {
      return res.status(400).json({message: 'error',error});
    }
  })
  router.post("/signup", async (req, res) => {
    const { email, password } = req.body;
  
    try {
      const existingUser = await User.findOne({ email });
      if (existingUser) {
        return res.status(400).json({ message: 'Email already exists' });
      }
     
      const hashedPassword = await bcrypt.hash(password, 10);
   
      const newUser = new User({
        user_email: email,
        user_password: hashedPassword,
        user_role: "user",
        isPaidTier: false,
       avatar: "deafult",
        devLinks: [], 
        firstLogin: true,
      });

  const devLink = new DevLinks({
    items: [
      {
        id: 1,
        itemType: 'links',
        platform: 'GitHub',
        url: 'https://github.com/',
      }
    ],
    name: 'John', 
    last_name: 'Doe',
    email: 'john.doe@example.com',
    profile_picture: null, 
    enable_color_customization: false,
    owner: newUser._id
  });
  await devLink.save();

  newUser.devLinks.push(devLink._id);
  await newUser.save();

  await logUserEvent(newUser._id, 'SignUp', 'Account Creation');
  const token = jwt.sign({ userId: newUser._id, avatar: newUser.avatar, firstLogin: newUser.firstLogin, isPaidTier: newUser.isPaidTier, email: newUser.user_email }, process.env.SECRET_KEY, {
    expiresIn: "2h",
  });
    
res
.clearCookie('jwt')
.cookie('jwt', token, { expiresIn: '2h' })
.status(200).json({ message: 'user successfully signed up',user:newUser,devlink:newUser.devLinks,token: token,expiresIn: "24h" })

    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "An error occurred",error });
    }
  });
  router.post('/loginWithGoogle', async (req, res) => {
    try {
      const ticket = await googleClient.verifyIdToken({
        idToken: req.body.AuthToken,
        audience: GOOGLE_CLIENT_ID,
      });
  
      const { email } = ticket.getPayload();
      const user = await User.findOne({ user_email: email });
  
      if (!user) {
        const generatedId = crypto.randomBytes(20).toString('hex');
        const hashedPassword = await bcrypt.hash(generatedId, 10);
  
        const newUser = new User({
          user_email: email,
          user_password: hashedPassword,
          user_role: "user",
          isPaidTier: false,
          avatar: "default",
          loggedInWithGoogle: true,
          devLinks: [],
          firstLogin: true,
        });
  
        await logUserEvent(newUser._id, 'SignUp', 'Account Creation');
  
        const devLink = new DevLinks({
          items: [
            {
              id: 1,
              itemType: 'links',
              platform: 'GitHub',
              url: 'https://github.com/',
            }
          ],
          name: '',
          last_name: '',
          email: '',
          profile_picture: null,
          enable_color_customization: false,
          owner: newUser._id
        });
        
        await devLink.save();
         newUser.devLinks.unshift(devLink._id);
        await newUser.save();
  
        const token = jwt.sign({ userId: newUser._id, avatar: newUser.avatar, firstLogin: newUser.firstLogin, isPaidTier: newUser.isPaidTier, email: newUser.user_email }, process.env.SECRET_KEY, {
          expiresIn: "24h",
        });
  
        res.clearCookie('jwt').cookie('jwt', token, { expiresIn: '24h' }).status(200).json({ message: 'User successfully signed up', user: newUser, devlink: newUser.devLinks, token: token, expiresIn: "24h" });
      } else {
        const allDevLinks = await DevLinks.find({ owner: user._id });
  
        if (!allDevLinks || allDevLinks.length === 0) {
          return res.status(500).json({ error: "No dev links found" });
        }
  
        await logUserEvent(user._id, 'Login', 'User logged in');
        const token = jwt.sign({ userId: user._id, avatar: user.avatar, firstLogin: user.firstLogin, isPaidTier: user.isPaidTier, email: user.user_email }, process.env.SECRET_KEY, {
          expiresIn: "24h",
        });
       
        res.clearCookie('jwt').cookie('jwt', token, { expiresIn: '24h' }).status(200).json({ message: 'User successfully logged in', user: user, devlink: allDevLinks, token: token, expiresIn: "24h" });
      }
    } catch (error) {
      console.error('Error in loginWithGoogle:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
  router.post('/login', async (req, res) => {
    const { email, password } = req.body;
     
    try {
      const user = await User.findOne({ user_email:email });
  
      if (!user) {
        return res.status(401).json({ message: 'cannot find user' });
        
      }
      const allDevLinks = await DevLinks.find({ owner: user._id })

      if (!allDevLinks) {
        return res.status(500).json({error:"no dev links found"})
      }
      const passwordMatch = await bcrypt.compare(password, user.user_password);
      if (!passwordMatch) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }
      await logUserEvent(user._id, 'login', 'User logged in');
      const token = jwt.sign({ userId: user._id, avatar: user.avatar, firstLogin: user.firstLogin, isPaidTier: user.isPaidTier, email: user.user_email }, secretKey, {
        expiresIn: "2h",
      });
  
  
  res
  .clearCookie('jwt')
  .cookie('jwt', token, { expiresIn: '2h' })
  .status(200).json({ message: 'user successfully logged in', user:user,devlink:allDevLinks,token: token,expiresIn: "24h" });

    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });


  router.post("/updateProfile", upload.single('profileBlob'), verifyToken, async (req, res) => {
   const {first_name, last_name,email,profile_picture} = JSON.parse(req.body.profile);
    if (req.file) {
    const { buffer, mimetype } = req.file;
    const generatedId = crypto.randomBytes(20).toString('hex');

    if (!buffer) {
        return res.status(400).json({ error: 'Invalid request, no profile picture buffer found.' });
    }

    const fileData = new FormData();
    const blob = new Blob([buffer], { type: 'application/octet-stream' });
    fileData.append('file', blob, 'sample_file');

    try {
        const response = await fetch('https://www.virustotal.com/api/v3/files', {
            method: 'POST',
            headers: {
                'x-apikey': apiKey,
            },
            body: fileData,
        });

        if (!response.ok) {
            throw new Error(`Error scanning file: ${response.statusText}`);
        }

        const scanResults = await response.json();
        const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${scanResults.data.id}`, {
            method: 'GET',
            headers: {
                'x-apikey': apiKey,
            },
        });

        const analysesReport = await analysisResponse.json();
        const lastAnalysisResults = analysesReport.data.attributes.stats;
        const isSafe = lastAnalysisResults.malicious === 0;
        const dimensions = sizeOf(buffer);
        const isSizeValid = dimensions.width <= 1024 && dimensions.height <= 1024;

        if (isSizeValid) {
        if (isSafe) {
          const existingDevlink = await DevLinks.findById(req.body.id);
             if (!existingDevlink) {
              return res.status(404).json({ message: 'Devlinks not found!' });
          }
             if (existingDevlink.profile_picture) {
              try {
                fs.unlink(`${__dirname}/../../linksharing/public/nonAuthImgs/${existingDevlink.profile_picture}`, (unlinkError) => {
                    if (unlinkError) {
                        console.error('Error removing existing profile picture:', unlinkError);
                        return res.status(500).json({ error: 'Internal server error' });
                    } else {
                        console.log('Existing profile picture removed successfully');
                    }
                });
            } catch (unlinkError) {
                console.error('Error removing existing profile picture:', unlinkError);
                return res.status(500).json({ error: 'Internal server error' });
            }
          }
            fs.writeFile(`${__dirname}/../../linksharing/public/nonAuthImgs/${generatedId}.${mime.extension(mimetype)}`, buffer, (err) => {
                if (err) {
                    console.log(err);
                    return res.status(500).json({ error: 'Internal server error' });
                }
    
                DevLinks.findOneAndUpdate(
                    { _id: req.body.id },
                    {
                        name: first_name,
                        last_name: last_name,
                        email: email,
                        profile_picture: `${generatedId}.${mime.extension(mimetype)}`,
                    },
                    { new: true }
                )
                .then((devlink) => {
                    if (!devlink) {
                        return res.status(404).json({ message: 'devlink not found or updated!' });
                    }
                    res.status(200).json({ message: 'profile successfully updated' });
                })
            });
        } else {
            res.status(400).json({ error: 'The file is flagged as potentially unsafe.' });
        }
      }
      else{
        return res.status(400).json({ error: 'Image dimensions must be equal or under 1024x1024 pixels.' });
      }

    } catch (error) {
        console.log("Error trying to scan file or update profile:", error);
        res.status(500).json({ error: 'Internal server error' });
    }
  }
  else{
    DevLinks.findOneAndUpdate(
      { _id: req.body.id },
      {
          name: first_name,
          last_name: last_name,
          email: email,
      },
      { new: true }
  )
  .then((devlink) => {
      if (!devlink) {
          return res.status(404).json({ message: 'devlink not found or updated!' });
      }
      res.status(200).json({ message: 'profile successfully updated' });
  })
  .catch((error) => {
      console.log("Error trying to update profile in the database:", error);
      res.status(500).json({ error: 'Internal server error' });
  });
  }
});
  router.post('/reset-password-request', async (req, res) => {
    const email = req.body.email; 
    const resetToken = crypto.randomBytes(20).toString('hex'); 
    
      const user = await User.findOne({user_email: email})
      if (!user) {
        res.status(500).json({ message: 'user not found!' });
      }
      user.user_password_reset.push(
        {
          token: resetToken,
          date: Date.now(),
        }
      );
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'mbe52are@gmail.com', 
        pass: 'alex931d', 
      },
    });

    const mailOptions = {
      from: 'mbe52are@gmail.com', 
      to: email, 
      subject: 'Password Reset Request',
      text: `Click the following link to reset your password: https://localhost:3000/reset-password/${resetToken}`,
    };
  
    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {

        res.status(500).send('Internal Server Error');
      } else {

        res.status(200).send('Password reset email sent successfully');
      }
    });
  });
  router.get('/reset-password/:token',async (req, res) => {
    const resetToken = req.params.token;
    try {
      const user = await User.findOne({
        'user_password_reset.token': resetToken,
        'user_password_reset.date': { $gte: new Date() }, 
      });
  
      if (user) {

        res.status(200).send('Valid reset token');
      } else {
        res.status(404).send('Invalid or expired reset token');
      }
    } catch (error) {
      console.error(error);
      res.status(500).send('Internal Server Error');
    }
   
  });
    router.post('/reset-password/:token', async (req, res) => {
        const { email, newPassword } = req.body;
        const resetToken = req.params.token;
      
        try {
          if (!email || !newPassword) {
            return res.status(400).send('Email and new password are required');
          }
      
          const user = await User.findOne({
            email,
            'user_password_reset.token': resetToken,
            'user_password_reset.date': { $gte: new Date() },
          });
         
      
          if (user) {
            user.password = await bcrypt.hash(newPassword, 10);
            user.user_password_reset = user.user_password_reset.filter(ps => ps.token !== resetToken);
      
            await user.save();
      
            res.status(200).send('Password reset successful');
          } else {
            res.status(404).send('User not found');
          }
        } catch (error) {
          console.error(error);
          res.status(500).send('Internal Server Error');
        }
      });
  router.post("/createDevLink",verifyToken,async (req,res)=>{
    const { userId } = req.body;
    try {
      const devLink = new DevLinks({
        links: [
          {
            id:1,
            platform: 'GitHub',
            url: 'https://github.com/',
          }
        ],
        name: 'john',
        last_name: 'doe',
        email: 'johndoe@hotmail.com',
        owner: userId,
      })
      await devLink.save();
    } catch (error) {
      res.status(500).json({ error: "An error occurred" });
    }
  })
  router.post("/getdevlinks",verifyToken, async (req, res) => {
    console.log("getdevlinks")
    try {
      const userId = req.user.userId;
        const userIdObjectId = new mongoose.Types.ObjectId(userId);
        const allDevLinks = await DevLinks.find({ owner: userId })
        if (!allDevLinks) {
          return res.status(500).json({error:"no dev links found"})
        }
        res.status(200).json({ message: 'user successfully logged in', allDevLinks: allDevLinks });
    } catch (error) {
      res.status(500).json({ error: "An error occurred" });
    }
  });

module.exports = router;