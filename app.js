//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

//const bcrypt = require('bcrypt'); level 4 encryption
//const saltRounds = 10;        level 4 encryption

//const md5 = require('md5'); for level 3 encryption
//const encrypt = require('mongoose-encryption') for level 1 encryption

const app = express();

//console.log(process.env.SECRET);
//console.log(md5("123")); for level 3 encryption

app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(express.urlencoded({ extended: true })); //body-parser deprecated undefined extended https://stackoverflow.com/questions/25471856/express-throws-error-as-body-parser-deprecated-undefined-extended
//app.use(bodyParser.urlencoded({}));

app.use(
  session({
    secret: "thisisourlittelsecret",
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

//  mongoose.connect("mongodb://localhost:27017/userDB");
mongoose.connect(
  `mongodb+srv://${process.env.MONGO_UID}:${process.env.MONGO_PASS}@cluster0.ibkwu.mongodb.net/userDB?retryWrites=true&w=majority`
);

const userSchema = new mongoose.Schema({
  // i use new mongoose.Schema for encryption of passwords
  email: String,
  password: String,
  googleId: String,
  // secret: String,
  facebookId: String,
});

//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] }); // for level 2 encryption
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function (user, done) {
  done(null, user.id);
  //console.log(user);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
    //console.log(user);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    function (accessToken, refreshToken, profile, cb) {
      // console.log(profile);
      User.findOrCreate(
        { username: profile.displayName, googleId: profile.id },
        function (err, user) {
          return cb(err, user);
        }
      );
    }
  )
);
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.CLIENT_ID_FB,
      clientSecret: process.env.CLIENT_SECRET_FB,
      callbackURL: "http://localhost:3000/auth/facebook/secrets",
    },
    function (accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ facebookId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);
app.get("/", function (req, res) {
  res.render("home");
});
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect to Secrets Page.
    res.redirect("/secrets");
  }
);

app.get("/auth/facebook", passport.authenticate("facebook"));

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", { failureRedirect: "/login" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  }
);

app.get("/login", function (req, res) {
  res.render("login");
});
app.get("/register", function (req, res) {
  res.render("register");
});
app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  //console.log(req.user.id);

  User.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/register", function (req, res) {
  User.register(
    { username: req.body.username },
    req.body.password,
    function (err, user) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );

  //////////////level 4 encryption////////////////////
  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {

  //     const newUser = new User({
  //         email: req.body.username,
  //         password: hash // password: md5(req.body.password) for level 3 encryption
  //     });
  //     newUser.save(function(err) {
  //         if (err) {
  //             console.log(err);
  //         } else {
  //             res.render("secrets");
  //         }
  //     });
  // });
  //////////////level 4 encryption////////////////////
});

app.post("/login", function (req, res) {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });

  req.login(user, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });

  //////////////level 4 encryption////////////////////
  // const username = req.body.username;
  // const password = req.body.password; // const password = md5(req.body.password); for level 3 encryption

  // User.findOne({ email: username }, function(err, foundUser) {
  //     if (err) {
  //         console.log(err);
  //     } else {
  //         if (foundUser) {
  //             bcrypt.compare(password, foundUser.password, function(err, result) {
  //                 if (result === true) {
  //                     res.render("secrets");
  //                 }
  //             });
  //         }
  //     }
  // });
  //////////////level 4 encryption////////////////////
});

app.listen(3000 || process.env.PORT, function () {
  console.log("server is running on port 3000");
});
