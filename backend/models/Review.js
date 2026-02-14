const mongoose = require("mongoose");

const reviewSchema = new mongoose.Schema(
  {
    product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

rating: {
  type: Number,
  required: true,
  min: 1,
  max: 5,
  validate: {
    validator: (v) => Number.isFinite(v) && v >= 1 && v <= 5,
    message: "La note doit être un nombre entre 1 et 5."
  }
},
comment: { type: String, default: "", maxlength: 500 }

  },
  { timestamps: true }
);

// Un user ne peut mettre qu'un avis par produit
reviewSchema.index({ product: 1, user: 1 }, { unique: true });

module.exports = mongoose.model("Review", reviewSchema);
