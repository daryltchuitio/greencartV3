const jwt = require("jsonwebtoken");
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const User = require("./models/User");

const app = express();
app.use(express.json());

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
    const { name, email, password } = req.body;

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
    const user = await User.create({ name, email, passwordHash });

    return res.status(201).json({
      message: "Utilisateur créé !",
      user: { id: user._id, name: user.name, email: user.email }
    });
  } catch (err) {
    return res.status(500).json({ message: "Erreur serveur", error: err.message });
  }
});

// LOGIN avec JWT
console.log("➡️ /api/login appelé");
app.post("/api/login", async (req, res) => {
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
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login réussi",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
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
