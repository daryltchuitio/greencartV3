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

// Saisonalité des produits
function getSeasonFactor(month, category) {
  if (month >= 6 && month <= 8) { // été
    if (category === "famille" || category === "terroir") return 1.2;
    return 1.1;
  }
  if (month === 12 || month === 1) { // fêtes + hiver
    if (category === "terroir") return 1.3;
    return 1.1;
  }
  if (month >= 3 && month <= 5) { // printemps
    if (category === "anti-gaspi") return 1.2;
    return 1.1;
  }
  if (month >= 9 && month <= 11) { // automne
    return 1.05;
  }
  return 1.0;
}

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

// Prévisions 
app.get("/api/producer/insights/forecasts", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    // 1) Produits du producteur
    const myProducts = await Product.find({ producer: req.user.userId })
      .select("_id name category")
      .lean();

    if (myProducts.length === 0) {
      return res.json({
        historyRows: [],
        forecastRows: [],
        note: "Publiez au moins un produit pour obtenir des prévisions."
      });
    }

    const myProductIds = myProducts.map(p => p._id);

    // 2) Commandes qui contiennent un de ces produits
    const orders = await Order.find({ "items.product": { $in: myProductIds } })
      .select("createdAt items")
      .lean();

    if (orders.length === 0) {
      return res.json({
        historyRows: [],
        forecastRows: [],
        note: "Aucune commande contenant vos produits pour l’instant."
      });
    }

    // 3) Agrégation : productId -> monthKey -> qty
    const statsByProductMonth = new Map(); // key: productId(str) -> Map(monthKey -> qty)
    const monthsSet = new Set();

    for (const order of orders) {
      const d = new Date(order.createdAt);
      if (isNaN(d)) continue;
      const y = d.getFullYear();
      const m = String(d.getMonth() + 1).padStart(2, "0");
      const monthKey = `${y}-${m}`;
      monthsSet.add(monthKey);

      for (const it of (order.items || [])) {
        const pid = String(it.product);
        if (!myProductIds.some(x => String(x) === pid)) continue;

        if (!statsByProductMonth.has(pid)) statsByProductMonth.set(pid, new Map());
        const perMonth = statsByProductMonth.get(pid);
        perMonth.set(monthKey, (perMonth.get(monthKey) || 0) + Number(it.qty || 1));
      }
    }

    const allMonths = Array.from(monthsSet).sort((a,b) => b.localeCompare(a)); // desc
    const lastMonths = allMonths.slice(0, 3);
    if (lastMonths.length === 0) {
      return res.json({ historyRows: [], forecastRows: [], note: "Pas assez de données." });
    }

    // 4) Next month label
    const now = new Date();
    const currentMonth = now.getMonth() + 1;
    const currentYear = now.getFullYear();
    let nextMonth = currentMonth + 1;
    let nextYear = currentYear;
    if (nextMonth === 13) { nextMonth = 1; nextYear += 1; }
    const nextMonthLabel = `${nextYear}-${String(nextMonth).padStart(2, "0")}`;

    // 5) Construction des rows
    const productById = new Map(myProducts.map(p => [String(p._id), p]));

    const historyRows = [];
    const forecastRows = [];

    for (const pid of statsByProductMonth.keys()) {
      const prod = productById.get(pid);
      if (!prod) continue;

      const perMonth = statsByProductMonth.get(pid);
      let total = 0;
      for (const mk of lastMonths) total += (perMonth.get(mk) || 0);

      if (total === 0) continue;

      const avg = total / lastMonths.length;
      historyRows.push({
        productId: pid,
        name: prod.name,
        category: prod.category,
        period: `${lastMonths.slice().reverse().join(" à ")}`,
        total,
        avg
      });

      const factor = getSeasonFactor(nextMonth, prod.category);
      const forecast = avg * factor;

      let advice = "Stock normal.";
      if (factor > 1.2) advice = "Augmenter clairement les stocks (forte saison).";
      else if (factor > 1.05) advice = "Prévoir une légère hausse de la demande.";
      else if (factor < 1.0) advice = "Risque de baisse : limiter les surplus.";

      forecastRows.push({
        productId: pid,
        name: prod.name,
        category: prod.category,
        avg,
        factor,
        forecast,
        nextMonthLabel,
        advice
      });
    }

    return res.json({
      historyRows,
      forecastRows,
      note: "Prévisions simplifiées (moyenne 3 mois + saisonnalité)."
    });

  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// Segmentation clients
app.get("/api/producer/insights/segments", auth, async (req, res) => {
  try {
    if (req.user.role !== "producer" && req.user.role !== "admin") {
      return res.status(403).json({ message: "Accès refusé" });
    }

    const myProducts = await Product.find({ producer: req.user.userId })
      .select("_id category")
      .lean();

    if (myProducts.length === 0) {
      return res.json({ segments: [], note: "Publiez au moins un produit pour analyser vos clients." });
    }

    const myProductIds = myProducts.map(p => p._id);
    const prodCategoryById = new Map(myProducts.map(p => [String(p._id), p.category || "autre"]));

    const orders = await Order.find({ "items.product": { $in: myProductIds } })
      .select("user createdAt items")
      .populate("user", "name email")
      .lean();

    if (orders.length === 0) {
      return res.json({ segments: [], note: "Aucune commande pour l’instant." });
    }

    // statsByUser: userId -> stats
    const statsByUser = new Map();

    for (const order of orders) {
      const uid = String(order.user?._id || order.user);
      if (!uid) continue;

      // totalForProducer + categoriesCount
      let totalForProducer = 0;
      const localCats = {};

      for (const it of (order.items || [])) {
        const pid = String(it.product);
        if (!myProductIds.some(x => String(x) === pid)) continue;

        const lineTotal = Number(it.price || 0) * Number(it.qty || 1);
        totalForProducer += lineTotal;

        const cat = prodCategoryById.get(pid) || "autre";
        localCats[cat] = (localCats[cat] || 0) + Number(it.qty || 1);
      }

      if (totalForProducer <= 0) continue;

      const d = new Date(order.createdAt);
      if (isNaN(d)) continue;

      if (!statsByUser.has(uid)) {
        statsByUser.set(uid, {
          user: order.user ? { id: uid, name: order.user.name, email: order.user.email } : { id: uid },
          totalOrders: 0,
          totalSpent: 0,
          firstDate: d,
          lastDate: d,
          categoriesCount: {}
        });
      }

      const st = statsByUser.get(uid);
      st.totalOrders += 1;
      st.totalSpent += totalForProducer;
      if (d < st.firstDate) st.firstDate = d;
      if (d > st.lastDate) st.lastDate = d;

      for (const [cat, qty] of Object.entries(localCats)) {
        st.categoriesCount[cat] = (st.categoriesCount[cat] || 0) + qty;
      }
    }

    if (statsByUser.size === 0) {
      return res.json({ segments: [], note: "Pas assez de données pour segmenter." });
    }

    // Helpers segment
    function favCategory(categoriesCount) {
      let fav = "autre", max = 0;
      for (const [cat, qty] of Object.entries(categoriesCount || {})) {
        if (qty > max) { max = qty; fav = cat; }
      }
      return fav;
    }

    function getSegmentLabel(stats, favCat) {
      const avgBasket = stats.totalSpent / stats.totalOrders;

      let daysSpan = (stats.lastDate - stats.firstDate) / (1000 * 60 * 60 * 24);
      if (daysSpan < 1) daysSpan = 1;
      const frequency = stats.totalOrders / daysSpan;

      if (favCat === "etudiant" && avgBasket < 15 && stats.totalOrders >= 2) return "Étudiant budget serré";
      if (favCat === "famille" && avgBasket >= 25 && stats.totalOrders >= 3) return "Famille fidèle";
      if (favCat === "anti-gaspi" && stats.totalOrders >= 2) return "Chasseur d’anti-gaspi";
      if (favCat === "terroir" && avgBasket >= 25) return "Gourmet terroir";
      if (frequency > 0.1 && stats.totalOrders >= 3) return "Client régulier";
      return "Occasionnel";
    }

    function getSegmentAdvice(label) {
      switch (label) {
        case "Étudiant budget serré": return "Proposer des formats plus petits et des prix attractifs en semaine.";
        case "Famille fidèle": return "Mettre en avant des paniers familiaux et des abonnements hebdomadaires.";
        case "Chasseur d’anti-gaspi": return "Communiquer sur les offres de dernière minute et les paniers surprise.";
        case "Gourmet terroir": return "Valoriser vos produits premium, l’origine et les partenariats locaux.";
        case "Client régulier": return "Proposer des programmes de fidélité ou des avantages récurrents.";
        default: return "Encourager la réassurance (qualité, origine, avis clients) pour le faire revenir.";
      }
    }

    // Build segmentsMap
    const segmentsMap = new Map(); // label -> agg

    for (const st of statsByUser.values()) {
      const favCat = favCategory(st.categoriesCount);
      const label = getSegmentLabel(st, favCat);
      const avgBasket = st.totalSpent / st.totalOrders;
      const name = st.user?.name || st.user?.email || "Client GreenCart";

      if (!segmentsMap.has(label)) {
        segmentsMap.set(label, {
          label,
          usersCount: 0,
          avgBasketTotal: 0,
          avgBasketCount: 0,
          favCatCount: {},
          examples: [],
          advice: getSegmentAdvice(label)
        });
      }

      const seg = segmentsMap.get(label);
      seg.usersCount += 1;
      seg.avgBasketTotal += avgBasket;
      seg.avgBasketCount += 1;
      seg.favCatCount[favCat] = (seg.favCatCount[favCat] || 0) + 1;
      if (seg.examples.length < 3) seg.examples.push(name);
    }

    const segments = Array.from(segmentsMap.values()).map(seg => {
      let domCat = "—", max = 0;
      for (const [cat, nb] of Object.entries(seg.favCatCount)) {
        if (nb > max) { max = nb; domCat = cat; }
      }
      return {
        segment: seg.label,
        usersCount: seg.usersCount,
        avgBasket: seg.avgBasketTotal / seg.avgBasketCount,
        dominantCategory: domCat,
        examples: seg.examples,
        advice: seg.advice
      };
    });

    return res.json({ segments, note: "Segmentation simplifiée basée sur vos ventes." });

  } catch (err) {
    res.status(500).json({ message: "Erreur serveur", error: err.message });
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
