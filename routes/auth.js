var express = require('express');
var express = require('express');
var passport = require('passport');
var LocalStrategy = require('passport-local');
var crypto = require('crypto');
var GoogleStrategy = require('passport-google-oidc');


var con = require('../mysql');
var db = require('../db');
const { resolve } = require('path');


function checkAccount(username) {
  return new Promise((resolve, reject) => {
    con.query('Select * from users where username= ?', [username], (err, results) => {
      if (err) {
        reject(err);
      } else {
        if (results.length > 0) {
          resolve(true);
        } else {
          resolve(false);
        }
      }
    });
  });
}




passport.use(new LocalStrategy(function verify(username, password, cb) {

  // Pass the username as an argument when calling the function
  
  con.query('SELECT * FROM users WHERE username = ?', [username], function (err, rows) {
    if (err) { return cb(err); }
    if (!rows || rows.length === 0) { return cb(null, false, { message: 'Incorrect username or password.' }); }
    const row = rows[0]; // Extract the first row
    console.log(password)
    crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function (err, hashedPassword) {
      if (err) { return cb(err); }

      // Compare hashed passwords as buffers
      if (!crypto.timingSafeEqual(Buffer.from(row.hashed_password), hashedPassword)) {
        return cb(null, false, { message: 'Incorrect username or password.' });
      }

      return cb(null, row);
    });
  });
}));

passport.use(new GoogleStrategy({
  clientID: process.env['GOOGLE_CLIENT_ID'],
  clientSecret: process.env['GOOGLE_CLIENT_SECRET'],
  callbackURL: '/oauth2/redirect/google',
  scope: ['profile']
}, function verify(issuer, profile, cb) {
  con.query('SELECT * FROM federated_credentials WHERE provider = ? AND subject = ?', [
    issuer,
    profile.id
  ], function (err, rows) {
    if (err) { return cb(err); }

    if (!rows || rows.length === 0) {
      // If no rows found, insert a new user and federated credentials
      con.query('INSERT INTO users (name,username) VALUES (?,?)', [
        profile.displayName,
        profile.name.givenName
      ], function (err, result) {
        if (err) { return cb(err); }

        const id = result.insertId;

        con.query('INSERT INTO federated_credentials (user_id, provider, subject) VALUES (?, ?, ?)', [
          id,
          issuer,
          profile.id
        ], function (err) {
          if (err) { return cb(err); }

          var user = {
            id: id,
            name: profile.displayName
          };

          return cb(null, user);
        });
      });
    } else {
      const row = rows[0];

      con.query('SELECT * FROM users WHERE id = ?', [row.user_id], function (err, userRows) {
        if (err) { return cb(err); }

        if (!userRows || userRows.length === 0) {
          return cb(null, false);
        }

        const user = userRows[0];
        return cb(null, user);
      });
    }
  });
}));


// passport.use(new LocalStrategy(function verify(username, password, cb) {
//     db.get('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
//       if (err) { return cb(err); }
//       if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
  
//       crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
//         if (err) { return cb(err); }
//         if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
//           return cb(null, false, { message: 'Incorrect username or password.' });
//         }
//         return cb(null, row);
//       });
//     });
//   }));

  passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

var router = express.Router();

router.get('/login', function(req, res, next) {
  res.render('login');
});

router.get('/login/federated/google', passport.authenticate('google'));

router.get('/oauth2/redirect/google', passport.authenticate('google', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

router.post('/login/password', passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login'
}));

router.post('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect('/');
    });
});

router.get('/signup', function(req, res, next) {
    res.render('signup');
});

router.post('/signup', function(req, res, next) {
    let accountPresent = checkAccount(req.body.username);
    accountPresent.then( function(value) { 
      console.log('value'+value);
      if(value){
        res.locals.message = "Account exists!";
        res.render("signup", res.locals);
        // res.redirect('/');
      }
    },
    function(error) { 
      return next(err); }
    )
    var salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', function(err, hashedPassword) {
      if (err) { return next(err); }
      con.query('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
        req.body.username,
        hashedPassword,
        salt
      ], function(err) {
        if (err) { return next(err); }
        var user = {
          id: this.lastID,
          username: req.body.username
        };
        req.login(user, function(err) {
          if (err) { return next(err); }
          res.redirect('/');
        });
      });
    });
});

module.exports = router;