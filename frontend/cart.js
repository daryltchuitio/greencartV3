// cart.js — gestion compteur panier GreenCart (front-only)
const CART_KEY = "greencart_cart";

function getCart() {
  return JSON.parse(localStorage.getItem(CART_KEY) || "[]");
}

function getCartCount() {
  const cart = getCart();
  return cart.reduce((sum, item) => sum + (item.qty || 0), 0);
}

function updateCartCount() {
  const count = getCartCount();

  // Met à jour tous les éléments qui ont la classe "cart-count"
  document.querySelectorAll(".cart-count").forEach(el => {
    el.textContent = count;

    // Si panier vide = on masque le badge
    if (count <= 0) {
      el.style.display = "none";
    } else {
      el.style.display = "inline-flex";
    }
  });
}

// Mise à jour au chargement de chaque page
document.addEventListener("DOMContentLoaded", updateCartCount);

// Si une autre page modifie le panier et qu’on revient → mise à jour
window.addEventListener("storage", updateCartCount);
