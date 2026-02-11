// auth-ui.js - adapte le bouton de nav + gère l'inactivité
document.addEventListener("DOMContentLoaded", () => {
  const CURRENT_USER_KEY = "greencart_current_user";
  const navAuth = document.getElementById("nav-auth");

  function getCurrentUser() {
    const str = localStorage.getItem(CURRENT_USER_KEY);
    if (!str) return null;
    try {
      return JSON.parse(str);
    } catch {
      return null;
    }
  }

  // --------- Affichage du bouton dans le header ----------
  if (navAuth) {
    const user = getCurrentUser();

    if (!user) {
      navAuth.innerHTML = '<a href="connexion.html" class="btn-outline">Connexion</a>';
    } else {
      const target = user.role === "producteur"
        ? "dashboard-producteur.html"
        : "dashboard-consommateur.html";

      navAuth.innerHTML = `<a href="${target}" class="btn-outline">Mon espace</a>`;
    }
  }

  // --------- Déconnexion automatique après inactivité ----------
  const INACTIVITY_LIMIT_MS = 15 * 60 * 1000; // 15 minutes
  let lastActivity = Date.now();

  function resetActivity() {
    lastActivity = Date.now();
  }

  function logoutForInactivity() {
    const user = getCurrentUser();
    if (!user) return; // déjà déconnecté

    localStorage.removeItem(CURRENT_USER_KEY);
    alert("Pour des raisons de sécurité, vous avez été déconnecté après une période d'inactivité.");
    window.location.href = "connexion.html";
  }

  const user = getCurrentUser();
  if (user) {
    ["click", "keydown", "mousemove", "touchstart"].forEach(evt => {
      document.addEventListener(evt, resetActivity, { passive: true });
    });

    setInterval(() => {
      const currentUser = getCurrentUser();
      if (!currentUser) return; // si l'utilisateur s'est déconnecté entre temps

      const now = Date.now();
      if (now - lastActivity > INACTIVITY_LIMIT_MS) {
        logoutForInactivity();
      }
    }, 30000); // on vérifie toutes les 30s
  }
});
