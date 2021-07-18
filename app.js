//jshint esversion:6
require('dotenv').config();
const express=require("express");
const ejs=require("ejs");
const bodyParser=require("body-parser");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy=require("passport-google-oauth20").Strategy;
//strategy is a authentication mechanism.
//Applications can choose which strategy to employ
//Strategy gets created and them added to the passport object
const findOrCreate=require("mongoose-findorcreate");
////////////using mongoose-encryption///////////
// const encrypt=require("mongoose-encryption");
////////////using mongoose-encryption///////////
///////////using hashing///////////////////////
// const md5=require("md5");
///////////using hashing///////////////////////
//////////using bcrypt////////////////////////
// const bcrypt=require("bcrypt");
// const saltrounds=10;
//////////using bcrypt////////////////////////
const app=express();


app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.use(express.static("public"));
app.use(session({
  secret:"Our little secret",
  resave:false,
  saveUninitialized:false
}));//session is like visiting a site.this we have to authenticate using passport
app.use(passport.initialize());
app.use(passport.session());
mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser:true})
mongoose.set("useCreateIndex",true);// without this warning was coming
const userSchema =new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String
});

userSchema.plugin(passportLocalMongoose);//maybe this allows to use username instead of email in login(scroll down)
userSchema.plugin(findOrCreate);
////////////using mongoose-encryption///////////
//defined before model
// const secret=process.env.SECRET;
// userSchema.plugin(encrypt,{secret:secret,encryptedFields:["password"]});
////////////using mongoose-encryption///////////

const User=new mongoose.model("User",userSchema);
passport.use(User.createStrategy());
//works for only local authentication//
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
//works for all authentication//
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
passport.use(new GoogleStrategy({
    clientID:process.env.CLIENT_ID,
    clientSecret:process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));
app.get("/",function(req,res){
  res.render("home");
});
app.get("/auth/google",
passport.authenticate("google",{scope:["profile"]})
);
app.get("/auth/google/secrets",//this is the path that will be shown after google authenticates the user
passport.authenticate("google",{failureRedirect:"/login"}),
function(req,res){
  //successful authentication redirects to secrets page
  res.redirect("/secrets");
}
);
app.get("/submit",function(req,res){
  if(req.isAuthenticated()) res.render("submit");
  else{
    res.redirect("/login");
  }
});
app.get("/login",function(req,res){
  res.render("login");
});
app.get("/register",function(req,res){
  res.render("register");
});
app.get("/secrets",function(req,res){
  // if(req.isAuthenticated()) res.render("secrets");
  // else{
  //   res.redirect("/login");
  // }
  User.find({"secret":{$ne:null}},function(err,foundUser){
    if(err) console.log(err);
    else {
      if(foundUser){
        res.render("secrets",{usersWithSecrets:foundUser});
      }
    }
  });
});
app.get("/logout",function(req,res){
  req.logout();
  res.redirect("/");
});
app.post("/register",function(req,res){
//////////using bcrypt////////////////////////
// bcrypt.hash(req.body.password,saltrounds,function(err,hash){
//   const newuser=new User({
//     email:req.body.username,
//     // password:md5(req.body.password) while using md5
//     password:hash
//   });
//   newuser.save(function(err){
//     if(err) console.log(err);
//     else res.render("secrets");
//   });
//})
/////////////using passport/////////////
User.register({username:req.body.username},req.body.password,function(err,user){
  if(err){
    console.log(err);
    res.redirect("/register");
  }
  else{
    passport.authenticate("local")(req,res,function(){//maybe here the data is saved in the database
      res.redirect("/secrets");
    })
  }
})

});
 app.post("/login",function(req,res){
  // const username=req.body.username;
  // const pass=req.body.password;
  // //uisng hashinhg
  // // const pass=md5(req.body.password); using hashing
  //
  // User.findOne({email:username},function(err,result){
  //   if(err) console.log(err);
  //   else {
  //     if(result){
  //      bcrypt.compare(pass,result.password,function(err,result){
  //       if(result===true)  res.render("secrets");
  //      })
  //
  //     }
  //
  // }
  // })
///////////////////////using passport///////////
const user=new User({
  username:req.body.username,
  password:req.body.password
})
req.login(user,function(err){
  if(err) console.log(err);
  else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    })
  }
})


});
app.post("/submit",function(req,res){
  const requestedSecret=req.body.secret;
  User.findById(req.user.id,function(err,foundUser){
    if(err) console.log(err);
    else{
      if(foundUser){
        foundUser.secret=requestedSecret;
        foundUser.save(function(err){
          if(err) console.log(err);
          else res.redirect("/secrets");
        });
      }
    }
  })

})








app.listen(3000,function(){
  console.log("Successfully running");
})
