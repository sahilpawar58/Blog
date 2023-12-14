var mysql = require('mysql');
var crypto = require('crypto');

var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "blog"
});

con.connect(function(err) {
  if (err) throw err;
  console.log("Connected!");
  var sql = "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, \
    username TEXT UNIQUE, \
    hashed_password BLOB, \
    salt BLOB, \
    name TEXT, \
    email TEXT UNIQUE, \
    email_verified INTEGER)";
  con.query(sql, function (err, result) {
    if (err) throw err;
    console.log("Table created");
  });

  var sql = "CREATE TABLE IF NOT EXISTS federated_credentials ( \
    id INTEGER PRIMARY KEY, \
    user_id INTEGER NOT NULL, \
    provider TEXT NOT NULL, \
    subject TEXT NOT NULL, \
    UNIQUE (provider, subject) \
  )";
  con.query(sql, function (err, result) {
    if (err) throw err;
    console.log("Table created");
  });

  var salt = crypto.randomBytes(16);
  // con.query('INSERT INTO users (username, hashed_password, salt) VALUES (?, ?, ?)', [
  //   'alice',
  //   crypto.pbkdf2Sync('letmein', salt, 310000, 32, 'sha256'),
  //   salt
  // ], function (err, result) {
  //   if (err) throw err;
  //   console.log("inserted");
  // });


});


module.exports = con;