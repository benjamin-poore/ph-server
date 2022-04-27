const mongoose = require('mongoose');

function mongooseConnectDB() {
  mongoose
    .connect('mongodb://localhost/auth')
    .then((result) =>
      console.log("Mongoose connected")
    )
    .catch((err) => console.log("error connecting to the database", err))
}

module.exports = mongooseConnectDB;

