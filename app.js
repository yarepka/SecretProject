require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}));

// set up session
app.use(session({
    secret: "Out little secret.",
    resave: false,
    saveUninitialized: false
}));

// initialized session
app.use(passport.initialize());
// use passport to manage the session
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

// use passportLocalMongoose as a plugin
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
 
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// set passport to serialize and deserialize user
passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
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

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets",
    passport.authenticate("google", {failureRedirect: "/login"}),
    (req, res) => {
        res.redirect("/secrets")
    }
);

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    // find all users who's secret is not equals to null
    User.find({"secret": {$ne:null}}, (err, foundUsers) => {
        if(!err) {
            if(foundUsers) {
                res.render("secrets", {usersWithSecrets:foundUsers});
            }
        } else {
            console.log(err);
        }
    });
});

app.get("/submit", (req, res) => {
    if(req.isAuthenticated()) {
        res.render("submit");
    } else {
        // redirect to login page if user not loged in yet
        res.redirect("/login");
    }
});

app.post("/submit", (req, res) => {
    const submittedSecret = req.body.secret;
    console.log(req.user.id);
    User.findById(req.user.id, (err, foundUser) => {
        if(!err)
        {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save();
                res.redirect("/secrets");
            }
        } else {
            console.log(err);
        }
    });
});

app.get("/logout", (req, res) => {
   req.logout();
   res.redirect("/");
});

app.post("/register", (req, res) => { 
    // insert user with username and password to the users collection
    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            // creates cookie
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            });
        }
    });
});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err) => {
        // err might appear when there is no
        // user with that username and password
        if(err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, () => {
                res.redirect("/secrets");
            })
        }
    });

});

app.listen(3000, () => {
    console.log("Server started on post 3000.");
});