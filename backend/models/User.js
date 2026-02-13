const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: true, trim: true, maxlength: 80 },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    passwordHash: { type: String, required: true },
    role: {
      type: String,
      enum: ["consumer", "producer", "admin"],
      default: "consumer"
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
