
const express = require ("express");
const ejs = require ("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook");
const findOrCreate = require("mongoose-findorcreate");



const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));

app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
})) 

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/ModuleDB", { useNewUrlParser: true} );
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    username: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret:  String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());
 
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });


////////////////////////////Google oAuth////////////////////////////////////
passport.use(new GoogleStrategy({
    clientID: "262127650463-l9glc97asi4lr3itjs9hdejn5b223clp.apps.googleusercontent.com",
    clientSecret: "tGDdM5W6PySeN0rhft0vkBdg",
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


/////////////////////////////Facebook oAuth/////////////////////////////////////////
passport.use(new FacebookStrategy({
    clientID: "372569863411421",
    clientSecret: "9466d3a9376012275b84968af24df7d7",
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile);
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));




app.get("/", function(req, res){
    res.render("home");
});


//////////////////////////google oAuth middleware////////////////////////////////////
app.get("/auth/google",
passport.authenticate("google", {scope:["profile"]})
); 

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });



///////////////////////////Facebook oAuth middleware/////////////////////////////////////
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

 

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/secrets", function(req, res){
  User.find({"secret": {$ne: null}}, function(err, foundUsers){
    if (err){
      console.log(err);
    } else{
      if(foundUsers){
        res.render("secrets", {usersWithSecrets: foundUsers})
      }
    }
  })
});

app.get("/submit", function(req, res){
  if (req.isAuthenticated()){
    res.render("submit");
} else{
    res.redirect("/login");
}
});

app.get("/logout", function(req, res){
  if (req.isAuthenticated()){
    req.logout();
    res.redirect("/");
} else{
    res.redirect("/login");
}
    
})

app.post("/register", function(req, res){
   
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect("/register");
        } else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })
        }
    })
  
});

app.post("/login", function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })
    req.login(user, function(err){
        if(err){
            console.log(err);
        } else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");   
         })
        }
})
});

app.post("/submit", function(req, res){
  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else{
      foundUser.secret = req.body.secret;
      foundUser.save(function(){
        res.redirect("/secrets");
      });
    }
  });
});

app.listen("3000", function(){
    console.log("server started at port 3000");
});