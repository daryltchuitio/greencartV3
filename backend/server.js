const cors = require("cors");
const Review = require("./models/Review");
const Order = require("./models/Order");
const Product = require("./models/Product");
const auth = require("./middleware/auth");
const jwt = require("jsonwebtoken");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const User = require("./models/User");

const app = express();

app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PATCH", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));

app.use(express.json({ limit: "5mb" }));
app.use(express.urlencoded({ extended: true, limit: "5mb" }));

// Routes de test
app.get("/", (req, res) => {
  res.send("Backend GreenCart OK (MongoDB connecté)");
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    mongoConnected: mongoose.connection.readyState === 1
  });
});

//  REGISTER sécurisé (hash password)
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    // validations simples
    if (!name || !email || !password) {
      return res.status(400).json({ message: "name, email, password sont obligatoires" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Le mot de passe doit faire au moins 6 caractères" });
    }

    // email déjà utilisé ?
    const existing = await User.findOne({ email });
    if (existing) {
      return res.status(409).json({ message: "Email déjà utilisé" });
    }

    // hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // create user
    const safeRole = role === "producer" ? "producer" : "consumer";
    const user = await User.create({ name, email, passwordHash, role: safeRole });

    return res.status(201).json({
      message: "Utilisateur créé !",
      user: { id: user._id, name: user.name, email: user.email, role: user.role}
    });
  } catch (err) {
    return res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// LOGIN avec JWT
app.post("/api/login", async (req, res) => {
  console.log("➡️ /api/login appelé");
  try {
    const { email, password } = req.body;

    // vérifier champs
    if (!email || !password) {
      return res.status(400).json({ message: "Email et password requis" });
    }

    // trouver user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: "Identifiants invalides" });
    }

    // comparer password
    const isMatch = await bcrypt.compare(password, user.passwordHash);
    if (!isMatch) {
      return res.status(401).json({ message: "Identifiants invalides" });
    }

    // générer token
    const token = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login réussi",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Route protégée : infos utilisateur connecté
app.get("/api/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-passwordHash");
    if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Route POST /api/products (protégée)
app.post("/api/products", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const product = await Product.create({
      ...req.body,
      producer: req.user.userId
    });

    res.status(201).json(product);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Mes produits (Producer)
app.get("/api/products/mine", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const products = await Product.find({ producer: req.user.userId })
      .sort({ createdAt: -1 });

    res.json(products);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Archiver un produit (Producer : seulement ses produits)
app.patch("/api/products/:id/archive", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Produit introuvable" });

    const isOwner = product.producer?.toString() === req.user.userId;
    if (!isOwner && req.user.role !== "admin") {
      return res.status(403).json({ message: "Vous ne pouvez archiver que vos produits" });
    }

    product.isActive = false;
    await product.save();

    res.json({ message: "Produit archivé", product });
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Supprimer un produit (Producer : seulement ses produits)
app.delete("/api/products/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Produit introuvable" });

    const isOwner = product.producer?.toString() === req.user.userId;
    if (!isOwner && req.user.role !== "admin") {
      return res.status(403).json({ message: "Vous ne pouvez supprimer que vos produits" });
    }

    await product.deleteOne();
    res.json({ message: "Produit supprimé" });
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Mettre à jour un produit (Producer : seulement ses produits)
app.patch("/api/products/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const product = await Product.findById(req.params.id);
    if (!product) return res.status(404).json({ message: "Produit introuvable" });

    const isOwner = product.producer?.toString() === req.user.userId;
    if (!isOwner && req.user.role !== "admin") {
      return res.status(403).json({ message: "Vous ne pouvez modifier que vos produits" });
    }

    Object.assign(product, req.body);
    await product.save();

    res.json(product);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Route GET /api/products (public)
app.get("/api/products", async (req, res) => {
  try {
    // produits + nom du producteur
    const products = await Product.find({ isActive: true }).populate("producer", "name").lean();

    const productIds = products.map((p) => p._id);

    // stats reviews groupées par produit
    const stats = await Review.aggregate([
      { $match: { product: { $in: productIds } } },
      {
        $group: {
          _id: "$product",
          avgRating: { $avg: "$rating" },
          reviewsCount: { $sum: 1 },
        },
      },
    ]);

    const statsMap = new Map(
      stats.map((s) => [
        s._id.toString(),
        {
          avgRating: Math.round(s.avgRating * 100) / 100,
          reviewsCount: s.reviewsCount,
        },
      ])
    );

    const result = products.map((p) => {
      const s = statsMap.get(p._id.toString()) || { avgRating: 0, reviewsCount: 0 };
      return { ...p, ...s };
    });
    
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});


//  Route debug pour vérifier le contenu du token
app.get("/api/debug-token", auth, (req, res) => {
  res.json(req.user);
});

// Créer une commande (Consumer uniquement)
app.post("/api/orders", auth, async (req, res) => {
  try {
    if (req.user.role !== "consumer") {
      return res.status(403).json({ message: "Seuls les consommateurs peuvent créer une commande." });
    }

    const { items } = req.body; // attendu: [{ productId, qty }]
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ message: "items est requis." });
    }

    // Charger les produits en base pour calculer prix + snapshot
    const productIds = items.map(i => i.productId);
    const products = await Product.find({ _id: { $in: productIds } });

    if (products.length !== productIds.length) {
      return res.status(400).json({ message: "Un ou plusieurs produits sont introuvables." });
    }

    // Construire items snapshot
    const orderItems = items.map(i => {
      const p = products.find(pp => pp._id.toString() === i.productId);
      const qty = Number(i.qty || 1);
      return {
        product: p._id,
        name: p.name,
        price: p.price,
        qty
      };
    });

    const subtotal = orderItems.reduce((s, it) => s + it.price * it.qty, 0);
    const fees = orderItems.length > 0 ? 2.0 : 0.0;
    const total = subtotal + fees;

    const order = await Order.create({
      user: req.user.userId,
      items: orderItems,
      subtotal,
      fees,
      total,
      status: "en_preparation"
    });

    res.status(201).json(order);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Mes commandes (Consumer) 
app.get("/api/orders/me", auth, async (req, res) => {
  try {
    const orders = await Order.find({ user: req.user.userId })
      .sort({ createdAt: -1 });

    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// Commande reçues (Producer)
app.get("/api/producer/orders", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    // On récupère les produits de ce producteur
    const myProducts = await Product.find({ producer: req.user.userId }).select("_id");
    const myProductIds = myProducts.map(p => p._id);

    // On récupère les commandes qui contiennent au moins un de ces produits
    const orders = await Order.find({ "items.product": { $in: myProductIds } })
      .sort({ createdAt: -1 })
      .populate("user", "name email");

    res.json(orders);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Mettre à jour le statut d'une commande (Producer)
app.patch("/api/orders/:id/status", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const { status } = req.body;
    if (!["en_preparation", "prete", "terminee"].includes(status)) {
      return res.status(400).json({ message: "Statut invalide" });
    }

    const order = await Order.findById(req.params.id);
    if (!order) return res.status(404).json({ message: "Commande introuvable" });

    // Vérifier que cette commande contient au moins un produit du producteur
    const myProducts = await Product.find({ producer: req.user.userId }).select("_id");
    const mySet = new Set(myProducts.map(p => p._id.toString()));

    const hasMyItem = (order.items || []).some(it => mySet.has(it.product.toString()));
    if (!hasMyItem && req.user.role !== "admin") {
      return res.status(403).json({ message: "Vous ne pouvez pas modifier cette commande." });
    }

    order.status = status;
    await order.save();

    res.json(order);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Ajouter un avis à un produit; POST /api/reviews (consumer, produit livré uniquement)
app.post("/api/reviews", auth, async (req, res) => {
  try {
    if (req.user.role !== "consumer") {
      return res.status(403).json({ message: "Accès refusé" });
    }
    
    const { productId, rating, comment } = req.body;
    
    const ratingNum = parseFloat(rating);
    if (!productId || !Number.isFinite(ratingNum)) {
      return res.status(400).json({ message: "productId et rating (nombre) sont requis" });
    }


    // règle: le user doit avoir AU MOINS une commande "terminee" contenant ce produit
    const hasDeliveredOrder = await Order.exists({
      user: req.user.userId,
      status: "terminee",
      "items.product": productId
    });

    if (!hasDeliveredOrder) {
      return res.status(403).json({
        message: "Vous pouvez laisser un avis uniquement après livraison (commande terminée)."
      });
    }

    const review = await Review.create({
      product: productId,
      user: req.user.userId,
      rating: ratingNum,
      comment: comment || ""
    });

    res.status(201).json(review);
  } catch (err) {
    // si avis déjà existant (index unique)
    if (err.code === 11000) {
      return res.status(409).json({ message: "Vous avez déjà laissé un avis pour ce produit." });
    }
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// POST /api/products/:id/reviews (consumer, commande terminée uniquement)
app.post("/api/products/:id/reviews", auth, async (req, res) => {
  try {
    if (req.user.role !== "consumer") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const productId = req.params.id;
    const { rating, comment } = req.body;

    const ratingNum = parseFloat(String(rating).replace(",", "."));
    if (!Number.isFinite(ratingNum) || ratingNum < 1 || ratingNum > 5) {
      return res.status(400).json({ message: "rating doit être un nombre entre 1 et 5" });
    }

    // règle: le user doit avoir AU MOINS une commande "terminee" contenant ce produit
    const hasDeliveredOrder = await Order.exists({
      user: req.user.userId,
      status: "terminee",
      "items.product": productId
    });

    if (!hasDeliveredOrder) {
      return res.status(403).json({
        message: "Vous pouvez laisser un avis uniquement après livraison (commande terminée)."
      });
    }

    const review = await Review.create({
      product: productId,
      user: req.user.userId,
      rating: ratingNum,
      comment: comment || ""
    });

    res.status(201).json(review);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ message: "Vous avez déjà laissé un avis pour ce produit." });
    }
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});


// GET /api/products/:id/reviews (public)
app.get("/api/products/:id/reviews", async (req, res) => {
  try {
    const reviews = await Review.find({ product: req.params.id })
      .sort({ createdAt: -1 })
      .populate("user", "name");

    res.json(reviews);
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur" });
  }
});

// DELETE /api/reviews/:id (consumer, supprimer son avis)
app.delete("/api/reviews/:id", auth, async (req, res) => {
  try {
    if (req.user.role !== "consumer") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const review = await Review.findById(req.params.id);
    if (!review) return res.status(404).json({ message: "Avis introuvable" });

    // seul l'auteur (ou admin plus tard)
    if (review.user.toString() !== req.user.userId) {
      return res.status(403).json({ message: "Vous ne pouvez supprimer que votre avis." });
    }

    await review.deleteOne();
    res.json({ message: "Avis supprimé" });
  } catch (err) {
    res.status(500).json({ message: "Erreur serveur" });
  }
});


// Config + connexion
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI;

console.log("🔎 MONGODB_URI détectée ?", Boolean(MONGODB_URI));

mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log("✅ MongoDB connecté !");
    app.listen(PORT, () => {
      console.log(`✅ Serveur lancé sur http://localhost:${PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ Erreur connexion MongoDB :", err.message);
    process.exit(1);
  });
