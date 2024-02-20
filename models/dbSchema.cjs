const mongoose = require("mongoose");
const UserAuditLog = new mongoose.Schema({
  userId:{
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
  eventType:{
    type:String,
    required:true,
  },
  eventDetails:{
    type:String,
    required: false,
  },
  timeStamp:{
    type:Date,
    default: Date.now(),
    required:false
  },
})
const UserSchema = new mongoose.Schema({
user_email:{
  type: String,
  required: true
},
user_password:{
  type:String,
  required: true
},
user_role:{
  type:String,
  required:true
},  
isPaidTier:{
  type: Boolean,
  required:true,
},
avatar: {
  type: String,
  required: true,
  default: '',
},
loggedInWithGoogle: {
  type: Boolean,
  required: true,
  default: false,
},
user_password_reset:[{
  token:{
    type:String,
    required:false
  },
  date:{
    type:Date,
    required:false,
    default: Date.now(),
  },
}],

devLinks: [{
  type: mongoose.Schema.Types.ObjectId,
  ref: 'DevLinks',
}],
firstLogin: {
  type: Boolean,
  required: true,
  default: true, 
},
});
const DevLinksSchema = new mongoose.Schema({

  items: [
    {
      id: {
        type: Number,
        required: true,
      },
      itemType: {
        type: String,
        enum: ['links', 'medias', 'notes','files'],
        required: true,
      },
      platform: {
        type: String,
      },
      url: {
        type: String,
      },
      name: {
        type:String,
      },
      font_family:{
        type:String,
        default: null,
      },
      font_size:{
        type:Number,
        default: null,
      },
      foreground:{
        type:String,
        default: null,
      },
      link_color:{
        type:String,
        default: null,
      },
      fileType: {
        type:String
      },
      type: {
        type: String,
        enum: ['image', 'video', 'audio', 'file', 'other'],
      },
      content: {
        type: String,
      },
  
    },
  ],
  name: {
    type:String,
    required: false
  },
  last_name:{
    type: String,
    required: false
  },
  email: {
    type: String,
    required: false
  },
  profile_picture:{
    type: String,
    required: false,
  },
  enable_color_customization:{
    type: Boolean,
    required: false,
  },
  owner: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
  },
});



const DevLinks = mongoose.model("DevLinks", DevLinksSchema);
const User = mongoose.model("User",UserSchema);
const AuditLog = mongoose.model("AuditLog",UserAuditLog);
module.exports = {User,DevLinks,AuditLog};