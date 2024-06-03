const express = require("express");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");
var crypto = require("crypto");

// Package documentation - https://www.npmjs.com/package/connect-mongo
const MongoStore = require("connect-mongo");

/**
 * -------------- GENERAL SETUP ----------------
 */

// Gives us access to variables set in the .env file via `process.env.VARIABLE_NAME` syntax
require("dotenv").config();

// Create the Express application
var app = express();

// Middleware that allows Express to parse through both JSON and x-www-form-urlencoded request bodies
// These are the same as `bodyParser` - you probably would see bodyParser put here in most apps
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/**
 * -------------- DATABASE ----------------
 */

/**
 * Connect to MongoDB Server using the connection string in the `.env` file.  To implement this, place the following
 * string into the `.env` file
 *
 * DB_STRING=mongodb://<user>:<password>@localhost:27017/database_name
 */

mongoose.connect(process.env.MONGODB_URI);

// Creates simple schema for a User.  The hash and salt are derived from the user's given password when they register
const UserSchema = new mongoose.Schema({
  username: String,
  hash: String,
  salt: String,
});

// Defines the model that we will use in the app
const User = mongoose.model("User", UserSchema);

/**
 * -------------- SESSION SETUP ----------------
 */

/**
 * The MongoStore is used to store session data.  We will learn more about this in the post.
 *
 * Note that the `connection` used for the MongoStore is the same connection that we are using above
 */
const sessionStore = MongoStore.create({
  mongoUrl: process.env.MONGODB_URI,
  collection: "sessions",
});

/**
 * See the documentation for all possible options - https://www.npmjs.com/package/express-session
 *
 * As a brief overview (we will add more later):
 *
 * secret: This is a random string that will be used to "authenticate" the session.  In a production environment,
 * you would want to set this to a long, randomly generated string
 *
 * resave: when set to true, this will force the session to save even if nothing changed.  If you don't set this,
 * the app will still run but you will get a warning in the terminal
 *
 * saveUninitialized: Similar to resave, when set true, this forces the session to be saved even if it is unitialized
 */
app.use(
  session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: true,
    store: sessionStore,
    cookie: {
      maxAge: 1000 * 30,
    },
  })
);

/**
 * -------------- Passport -----------
 */

// Helpers //
// validate incoming password
function validPassword(password, hash, salt) {
  var hashVerify = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");
  return hash === hashVerify;
}

// generate hashed password
function genPassword(password) {
  var salt = crypto.randomBytes(32).toString("hex");
  var genHash = crypto
    .pbkdf2Sync(password, salt, 10000, 64, "sha512")
    .toString("hex");

  return {
    salt: salt,
    hash: genHash,
  };
}

// local Strat
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false);
      }

      const isValid = validPassword(password, user.hash, user.salt);

      if (!isValid) {
        return done(null, false);
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

// store the user id in the session
passport.serializeUser(function (user, cb) {
  cb(null, user.id);
});

// use the user id in session to look them up in the database when needed
passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(passport.initialize());
app.use(passport.session());

/**
 * -------------- ROUTES ----------------
 */

app.get("/", (req, res, next) => {
  res.send("<h1>Home</h1>");
});

// When you visit http://localhost:3000/login, you will see "Login Page"
app.get("/login", (req, res, next) => {
  const form =
    '<h1>Login Page</h1><form method="POST" action="/login">\
    Enter Username:<br><input type="text" name="username">\
    <br>Enter Password:<br><input type="password" name="password">\
    <br><br><input type="submit" value="Submit"></form>';

  res.send(form);
});

// Since we are using the passport.authenticate() method, we should be redirected no matter what
app.post(
  "/login",
  passport.authenticate("local", {
    failureRedirect: "/login-failure",
    successRedirect: "login-success",
  }),
  (err, req, res, next) => {
    if (err) next(err);
  }
);

// When you visit http://localhost:3000/register, you will see "Register Page"
app.get("/register", (req, res, next) => {
  const form =
    '<h1>Register Page</h1><form method="post" action="register">\
                    Enter Username:<br><input type="text" name="username">\
                    <br>Enter Password:<br><input type="password" name="password">\
                    <br><br><input type="submit" value="Submit"></form>';

  res.send(form);
});

app.post("/register", (req, res, next) => {
  const saltHash = genPassword(req.body.password);

  const salt = saltHash.salt;
  const hash = saltHash.hash;

  const newUser = new User({
    username: req.body.username,
    hash: hash,
    salt: salt,
  });

  newUser.save().then((user) => {
    console.log(user);
  });

  res.redirect("/login");
});

// check authentication for a protected route
app.get("/protected-route", (req, res, next) => {
  console.log(req.session);
  if (req.isAuthenticated()) {
    res.send("<h1>You are authenticated</h1>");
  } else {
    res.send("<h1>You are not authenticated</h1>");
  }
});

// Visiting this route logs the user out
app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
  });
  res.redirect("/login");
});

app.get("/login-success", (req, res, next) => {
  console.log(req.session);
  res.send("You successfully logged in.");
});

app.get("/login-failure", (req, res, next) => {
  res.send("You entered the wrong password.");
});

/**
 * -------------- SERVER ----------------
 */

// Server listens on http://localhost:3000
app.listen(3000);
