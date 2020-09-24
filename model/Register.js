const mongoose = require("mongoose");
const validator = require("validator");
const passportLocalMongoose = require("passport-local-mongoose");
var RegisterSchema = new mongoose.Schema({
  googleId: String,
  countries: String,
  fname: {
    type: String,
    required: true,
  },
  lname: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    trim: true,
    lowercase: true,
    validate(value) {
      if (!validator.isEmail(value)) {
        throw new Error("Email is not valid");
      }
    },
  },
  password: {
    type: String,
    minlength: [8, "password has at least 8 characters"],
    required: [true, "password is required"],
  },
  address: {
    type: String,
    required: true,
  },
  city: {
    type: String,
    required: true,
  },
  state: {
    type: String,
    required: true,
  },
  zip: String,
  mobile: {
    type: String,
    validate(value) {
      if (value) {
        if (!validator.isMobilePhone(value)) {
          throw new Error("Invalid phone number");
        }
      }
    },
  },
  password_token: String,
});
mongoose.set("useCreateIndex", true);
RegisterSchema.plugin(passportLocalMongoose);
module.exports = mongoose.model("Register", RegisterSchema);
