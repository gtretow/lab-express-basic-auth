// User model here
const { Schema, model } = require("mongoose");

const UserSchema = new Schema({
  email: { type: String, required: true, unique: true },
  username: { type: String, required: true },
  passwordHash: { type: String, required: true },
});

const UserModel = model("User", UserSchema);

module.exports = UserModel;
