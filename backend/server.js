const express = require("express");

const app = express();

app.get("/", (req, res) => {
    res.send("Backend GreenCart fonctionne !");
});

app.listen(4000, () => {
    console.log("Serveur lancé sur http://localhost:4000");
});
