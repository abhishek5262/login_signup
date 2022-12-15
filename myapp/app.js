var session = require("express-session");
var mongoose = require("mongoose");
var nodemailer = require("nodemailer");
require("dotenv").config();
var passport = require("passport");
var LocalStrategy = require("passport-local").Strategy;
var bcrypt = require("bcrypt-nodejs");
var async = require("async");
var crypto = require("crypto");
var flash = require('express-flash');

var express = require("express");
var favicon = require("serve-favicon");
var path = require("path");
var logger = require("morgan");
var cookieParser = require("cookie-parser");
var bodyParser = require("body-parser");
var xoauth2 = require("xoauth2");

mongoose.connect("mongodb://localhost:27017/forgotpass");
var db = mongoose.connection;
db.on("error", console.error.bind(console, "connection error:"));

db.once("open", function () {
  console.log("connection successful");
});

// mongoose.set('useNewUrlParser', true);
// mongoose.set('useFindAndModify', false);
// mongoose.set('useCreateIndex', true);
// mongoose.set('useUnifiedTopology', true);

passport.use(new LocalStrategy(function(username, password, done) {
  User.findOne({ username: username }, function(err, user) {
    if (err) return done(err);
    if (!user) return done(null, false, { message: 'Incorrect username.' });
    user.comparePassword(password, function(err, isMatch) {
      if (isMatch) {
        return done(null, user);
      } else {
        return done(null, false, { message: 'Incorrect password.' });
      }
    });
  });
}));

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});


var userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  resetPasswordToken: String,
  resetPasswordExpires: Date,
});

userSchema.pre("save", function (next) {
  var user = this;
  var SALT_FACTOR = 5;

  if (!user.isModified("password")) return next();

  bcrypt.genSalt(SALT_FACTOR, function (err, salt) {
    if (err) return next(err);

    bcrypt.hash(user.password, salt, null, function (err, hash) {
      if (err) return next(err);
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function (candidatePassword, cb) {
  bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

var User = mongoose.model("User", userSchema);

var app = express();
// Middleware
app.set("port", process.env.PORT || 8040);
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "jade");
// app.use(favicon());
app.use(logger("dev"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(favicon(path.join(__dirname, "public", "favicon.ico")));
app.use(
  session(
    { secret: "keyboard cat",
      resave: true, 
      saveUninitialized: true
    }
  )
);

app.use(passport.initialize());
app.use(passport.session());
// app.use(express.static(path.join(__dirname, 'public')));
app.use(flash());

// Routes
app.get("/", function (req, res) {
  res.render("index", {
    title: "Express",
    user: req.user,
  });
});

app.get("/login", function (req, res) {
  res.render("login", {
    user: req.user,
  });
});

app.get("/signup", function (req, res) {
  res.render("signup", {
    user: req.user,
  });
});

app.post("/signup", function (req, res) {
  var user = new User({
    username: req.body.username,
    email: req.body.email,
    password: req.body.password,
  });

  user.save(function (err) {
    req.logIn(user, function (err) {
      res.redirect("/");
    });
  });
});

app.post("/login", function (req, res, next) {
  passport.authenticate("local", function (err, user, info) {
    if (err) return next(err);
    if (!user) {
      return res.redirect("/login");
    }
    req.logIn(user, function (err) {
      if (err) return next(err);
      return res.redirect("/");
    });
  })(req, res, next);
});

app.get("/logout", function (req, res) {
  req.logout();
  res.redirect("/");
});

app.get("/forgot", function (req, res) {
  res.render("forgot", {
    user: req.user,
  });
});

app.post("/forgot", function (req, res, next) {
  async.waterfall(
    [
      function (done) {
        crypto.randomBytes(20, function (err, buf) {
          var token = buf.toString("hex");
          done(err, token);
        });
      },
      function (token, done) {
        User.findOne({ email: req.body.email }, function (err, user) {
          if (!user) {
            return res.redirect("back");
          }
          // app.get('/reset');
          user.resetPasswordToken = token;
          user.resetPasswordExpires = Date.now() + 3600000; // 1 hour

          user.save(function (err) {
            done(err, token, user);
          });
        });
      },
      function (token, user, done) {
        var smtpTransport = nodemailer.createTransport({
          // host: "smtp.gmail.com",
          service: "Gmail",
          auth: {
            // xoauth2: xoauth2.createXOAuth2Generator({
            //   type: "OAuth2",
              user: 'mrinal.annand@gmail.com',
              pass: 'qdimydzmsclbjcic'
              // clientId: process.env.Client_Id,
              // refreshToken: process.env.refresh_token,
              // expires: process.env.expires,
            // }),
          }
        });
        var mailOptions = {
          from: "mrinal.annand@gmail.com",
          to: user.email,
          subject: "Node.js Password Reset",
          text:
            "You are receiving this because you (or someone else) have requested the reset of the password for your account.\n\n" +
            "Please click on the following link, or paste this into your browser to complete the process:\n\n" +
            "http://" +
            req.headers.host +
            "/reset/" +
            token +
            "\n\n" +
            "If you did not request this, please ignore this email and your password will remain unchanged.\n",
        };
        smtpTransport.sendMail(mailOptions, function (err) {
          res.status(200).json({ message: 'Check '+ user.email +' for a Password reset link.' });
          done(err, "done");
        }); 
      },
    ],
    function (err) {
      if (err) return next(err);
      res.redirect("/forgot");
    }
  );
});

app.get("/reset/:token", function (req, res) {
  User.findOne(
    {
      resetPasswordToken: req.params.token,
      resetPasswordExpires: { $gt: Date.now() }
    },
    function (err, user) {
      if (!user) {
        req.flash("error", "Password reset token is invalid or has expired.");
        return res.redirect("/forgot");
      }
      res.render("reset", {
        user: req.user,
      });
    });
});

app.post('/reset/:token', function(req, res) {
  async.waterfall([
    function(done) {
      User.findOne({ resetPasswordToken: req.params.token, resetPasswordExpires: { $gt: Date.now() } }, function(err, user) {
        if (!user) {
          req.flash('error', 'Password reset token is invalid or has expired.');
          return res.redirect('back');
        }

        user.password = req.body.password;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.save(function(err) {
          req.logIn(user, function(err) {
            done(err, user);
          });
          
        });
      });
      // res.redirect('/login');
    },
    function(user, done) {
      var smtpTransport = nodemailer.createTransport( {
        // host:'smtp.gmail.com',
        service: 'Gmail',
        auth: {
          user: 'mrinal.annand@gmail.com',
          pass: 'qdimydzmsclbjcic'
        }
      });
      var mailOptions = {
        to: user.email,
        from: 'mrinal.annand@gmail.com',
        subject: 'Your password has been changed',
        text: 'Hello,\n\n' +
          'This is a confirmation that the password for your account ' + user.email + ' has just been changed.\n'
      };
      smtpTransport.sendMail(mailOptions, function(err) {
        res.status(200).json({message:'Your password has been successfully updated. If you are not directed to the home page please do it manually'});
        done(err);
      }); 
    }
  ], function(err) { 
    return res.redirect('/');
  });
});

app.listen(app.get("port"), function () {
  console.log("Express server listening on port " + app.get("port"));
});

