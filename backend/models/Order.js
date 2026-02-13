const mongoose = require("mongoose");

const orderItemSchema = new mongoose.Schema(
  {
    product: { type: mongoose.Schema.Types.ObjectId, ref: "Product", required: true },
    name: { type: String, required: true }, // snapshot (comme ton localStorage)
    price: { type: Number, required: true }, // snapshot
    qty: { type: Number, required: true, min: 1 } // snapshot
  },
  { _id: false }
);

const orderSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    items: { type: [orderItemSchema], required: true },

    subtotal: { type: Number, required: true },
    fees: { type: Number, required: true, default: 2.0 },
    total: { type: Number, required: true },

    status: {
      type: String,
      enum: ["en_preparation", "prete", "terminee"],
      default: "en_preparation"
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Order", orderSchema);