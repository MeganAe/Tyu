// ================================
// Alert Bukavu — Config Frontend
// ================================

const API = '';

// ---- Auth ----
const AB = {
  saveToken: t => localStorage.setItem('ab_token', t),
  getToken: () => localStorage.getItem('ab_token'),
  saveUser: u => localStorage.setItem('ab_user', JSON.stringify(u)),
  getUser: () => { try { return JSON.parse(localStorage.getItem('ab_user')); } catch { return null; } },

  logout: async () => {
    const r = await showConfirm('Déconnexion ?', '', 'Oui, me déconnecter');
    if (r.isConfirmed) { localStorage.clear(); window.location.href = 'login.html'; }
  },

  requireAuth: () => {
    const token = localStorage.getItem('ab_token');
    if (!token) { window.location.href = 'login.html'; return null; }
    return JSON.parse(localStorage.getItem('ab_user'));
  },

  redirectIfAuth: () => {
    if (localStorage.getItem('ab_token')) window.location.href = 'index.html';
  },

  isAdmin: () => {
    try { return JSON.parse(localStorage.getItem('ab_user'))?.role === 'admin'; } catch { return false; }
  },

  api: async (endpoint, method = 'GET', body = null) => {
    const headers = { 'Content-Type': 'application/json' };
    const token = localStorage.getItem('ab_token');
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(`/api/${endpoint}`, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || data.message || 'Erreur serveur');
    return data;
  }
};

// ---- Données métier ----
const QUARTIERS = [
  'Kadutu','Ibanda','Bagira','Nyalukemba',
  'Kasha','Panzi','Ciherano','Essence','Nyawera','Kasali','Autre'
];

const CATEGORIES = {
  securite:   { label: 'Sécurité',   icon: 'shield',             color: '#FF3D71', bg: '#FFF0F5' },
  eau:        { label: 'Eau',         icon: 'water_drop',         color: '#840015', bg: '#ffdad8' },
  routes:     { label: 'Routes',      icon: 'traffic',            color: '#FF9F43', bg: '#FFF5EC' },
  sante:      { label: 'Santé',       icon: 'medical_services',   color: '#00C48C', bg: '#E6FAF5' },
  incendie:   { label: 'Incendie',    icon: 'local_fire_department', color: '#FF3D71', bg: '#FFF0F5' },
  inondation: { label: 'Inondation',  icon: 'water',              color: '#2471A3', bg: '#E0F7FA' },
  meteo:      { label: 'Météo',       icon: 'thunderstorm',       color: '#761f24', bg: '#ffdad8' },
  autre:      { label: 'Autre',       icon: 'more_horiz',         color: '#5b403e', bg: '#f0eded' }
};

const URGENCES = {
  faible:   { label: 'FAIBLE',   color: '#00C48C', bg: '#E6FAF5' },
  moyen:    { label: 'MOYEN',    color: '#FF9F43', bg: '#FFF5EC' },
  critique: { label: 'CRITIQUE', color: '#FF3D71', bg: '#FFF0F5' }
};

// ---- Utilitaires ----
function tempsRelatif(ts) {
  const diff = Date.now() - new Date(ts).getTime();
  const min = Math.floor(diff / 60000);
  if (min < 1) return "à l'instant";
  if (min < 60) return `il y a ${min} min`;
  const h = Math.floor(min / 60);
  if (h < 24) return `il y a ${h}h`;
  return `il y a ${Math.floor(h/24)}j`;
}

function escHtml(str) {
  if (!str) return '';
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function genererAvatar(nom, taille = 40) {
  const initiales = nom ? nom.trim().split(' ').map(p => p[0]||'').join('').substring(0,2).toUpperCase() : 'U';
  const couleurs = ['#840015','#761f24','#b00020','#5d5f5f','#906f6d'];
  const couleur = couleurs[nom ? nom.charCodeAt(0) % couleurs.length : 0];
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${taille}" height="${taille}" viewBox="0 0 ${taille} ${taille}">
    <circle cx="${taille/2}" cy="${taille/2}" r="${taille/2}" fill="${couleur}"/>
    <text x="${taille/2}" y="${taille/2 + taille*0.14}" text-anchor="middle" fill="white"
      font-family="Inter,sans-serif" font-weight="800" font-size="${taille*0.38}">${initiales}</text>
  </svg>`;
  return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));
}

// ---- SweetAlert2 helpers ----
const Toast = Swal.mixin({
  toast: true, position: 'bottom',
  showConfirmButton: false, timer: 3500, timerProgressBar: true,
  customClass: { popup: 'swal-toast-custom' }
});

function showToast(msg, type = 'success') {
  Toast.fire({ icon: type, title: msg });
}

function showConfirm(title, text, confirmText = 'Confirmer', icon = 'question') {
  return Swal.fire({
    title, text, icon, showCancelButton: true,
    confirmButtonColor: '#840015', cancelButtonColor: '#906f6d',
    confirmButtonText: confirmText, cancelButtonText: 'Annuler'
  });
}

function showAlert(title, text, icon = 'info') {
  return Swal.fire({ title, text, icon, confirmButtonColor: '#840015' });
}

// ---- Menu admin ----
function afficherMenuAdmin() {
  if (!AB.isAdmin()) return;
  const nav = document.querySelector('.bottom-nav');
  if (!nav || document.getElementById('adminNavItem')) return;
  const link = document.createElement('a');
  link.href = 'admin.html';
  link.id = 'adminNavItem';
  link.className = 'nav-item';
  link.innerHTML = `<span class="material-symbols-outlined ms-o" style="font-size:22px;font-variation-settings:'FILL' 0,'wght' 400,'GRAD' 0,'opsz' 24;">admin_panel_settings</span><span>Modération</span>`;
  nav.appendChild(link);
}
