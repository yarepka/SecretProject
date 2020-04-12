const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

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
    password: String
});

// use passportLocalMongoose as a plugin
userSchema.plugin(passportLocalMongoose);
 
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// set passport to serialize and deserialize user
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", (req, res) => {
    res.render("home");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.get("/register", (req, res) => {
    res.render("register");
});

app.get("/secrets", (req, res) => {
    if(req.isAuthenticated()) {
        res.render("secrets");
    } else {
        // redirect to login page if user not loged in yet
        res.redirect("/login");
    }
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