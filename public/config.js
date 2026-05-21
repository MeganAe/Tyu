// ================================
// Alert Bukavu — Config Frontend
// ================================

const CLOUDINARY_CLOUD_NAME = 'duxhbgs3d';
const CLOUDINARY_UPLOAD_PRESET = 'alertbukavu_unsigned';

async function uploadImage(file, folder = 'alertbukavu') {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('upload_preset', CLOUDINARY_UPLOAD_PRESET);
  formData.append('folder', folder);
  const res = await fetch(`https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`, { method: 'POST', body: formData });
  const data = await res.json();
  if (!res.ok) throw new Error(data?.error?.message || 'Erreur upload image');
  return data.secure_url;
}

// ---- Auth ----
const AB = {
  saveToken: t => localStorage.setItem('ab_token', t),
  getToken: () => localStorage.getItem('ab_token'),
  saveUser: u => localStorage.setItem('ab_user', JSON.stringify(u)),
  getUser: () => { try { return JSON.parse(localStorage.getItem('ab_user')); } catch { return null; } },

  logout: async () => {
    const r = await showConfirm('Déconnexion', 'Voulez-vous vraiment vous déconnecter ?', 'Oui, déconnecter');
    if (r.isConfirmed) { localStorage.clear(); window.location.href = 'login.html'; }
  },

  requireAuth: () => {
    const token = localStorage.getItem('ab_token');
    if (!token) { window.location.href = 'login.html'; return null; }
    return JSON.parse(localStorage.getItem('ab_user') || 'null');
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

// Toutes les catégories originales restaurées
const CATEGORIES = {
  incendie:   { label: 'Incendie',        icon: 'local_fire_department', color: '#FF3D71', bg: '#FFF0F5' },
  route:      { label: 'Route dégradée',  icon: 'construction',          color: '#FF9F43', bg: '#FFF5EC' },
  inondation: { label: 'Inondation',      icon: 'water',                 color: '#2471A3', bg: '#E0F7FA' },
  accident:   { label: 'Accident',        icon: 'car_crash',             color: '#8E44AD', bg: '#F5EEF8' },
  securite:   { label: 'Sécurité',        icon: 'shield',                color: '#840015', bg: '#ffdad8' },
  sante:      { label: 'Santé',           icon: 'medical_services',      color: '#00C48C', bg: '#E6FAF5' },
  eau:        { label: 'Eau',             icon: 'water_drop',            color: '#0077B6', bg: '#E0F0FF' },
  meteo:      { label: 'Météo',           icon: 'thunderstorm',          color: '#761f24', bg: '#ffdad8' },
  autre:      { label: 'Autre',           icon: 'report',                color: '#5b403e', bg: '#f0eded' }
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
    <text x="${taille/2}" y="${taille/2+taille*0.14}" text-anchor="middle" fill="white"
      font-family="Plus Jakarta Sans,Inter,sans-serif" font-weight="800" font-size="${taille*0.38}">${initiales}</text>
  </svg>`;
  return 'data:image/svg+xml;base64,' + btoa(unescape(encodeURIComponent(svg)));
}

function getPhotoUrl(userData, taille = 40) {
  if (userData && userData.photo_url) return userData.photo_url;
  if (userData && userData.photoUrl) return userData.photoUrl;
  return genererAvatar(userData?.nom || userData?.username || 'U', taille);
}

function validerUsername(u) { return /^[a-zA-Z0-9_]{3,20}$/.test(u); }

function normaliserTelephone(digits) {
  return '+243' + String(digits).replace(/\D/g, '');
}

// ---- Géolocalisation ----
function obtenirPosition() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error('Géolocalisation non supportée par ce navigateur'));
      return;
    }
    navigator.geolocation.getCurrentPosition(
      pos => resolve({ lat: pos.coords.latitude.toFixed(5), lng: pos.coords.longitude.toFixed(5) }),
      err => {
        const msgs = {
          1: 'Permission refusée. Autorisez la localisation dans les paramètres du navigateur.',
          2: 'Position indisponible. Vérifiez votre connexion GPS.',
          3: 'Délai dépassé. Réessayez.'
        };
        reject(new Error(msgs[err.code] || 'Erreur de géolocalisation'));
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
    );
  });
}

// ---- Local Dev Detection ----
function estLocal() {
  const hn = window.location.hostname;
  const pr = window.location.protocol;
  return pr === 'file:' || !hn || hn === 'localhost' || hn === '127.0.0.1' || hn === '[::1]' || hn.startsWith('192.168.') || hn.startsWith('10.') || hn.startsWith('172.');
}

// ---- SweetAlert2 & Fallback ----
let isSwalFallback = false;
if (typeof Swal === 'undefined') {
  isSwalFallback = true;
  window.Swal = {
    fire: function(opts) {
      if (typeof opts === 'string') {
        alert(opts);
      } else {
        alert((opts.title ? opts.title + '\n\n' : '') + (opts.text || ''));
      }
      return Promise.resolve({ isConfirmed: true });
    },
    mixin: function() {
      return {
        fire: function(opts) {
          showToast(opts.title || opts.text || '');
        }
      };
    },
    close: function() {},
    showLoading: function() {}
  };
}

const Toast = Swal.mixin({
  toast: true, position: 'bottom',
  showConfirmButton: false, timer: 3500, timerProgressBar: true,
  customClass: { popup: 'swal-toast-custom' }
});

function showToast(msg, type = 'success') {
  if (!isSwalFallback) {
    Toast.fire({ icon: type, title: msg });
  } else {
    // Inject fallback toast style if not present
    if (!document.getElementById('fallback-toast-style')) {
      const style = document.createElement('style');
      style.id = 'fallback-toast-style';
      style.textContent = `
        #fallback-toast-container {
          position: fixed;
          bottom: 20px;
          left: 50%;
          transform: translateX(-50%);
          z-index: 9999;
          display: flex;
          flex-direction: column;
          gap: 8px;
          font-family: 'Plus Jakarta Sans', sans-serif;
          pointer-events: none;
        }
        .fallback-toast {
          color: white;
          padding: 12px 24px;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
          pointer-events: auto;
          min-width: 250px;
          text-align: center;
          animation: slideUpToast 0.3s ease both;
          transition: opacity 0.4s ease;
        }
        @keyframes slideUpToast {
          from { opacity: 0; transform: translateY(20px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `;
      document.head.appendChild(style);
    }
    
    // Create container if not present
    let container = document.getElementById('fallback-toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'fallback-toast-container';
      document.body.appendChild(container);
    }
    
    const t = document.createElement('div');
    t.className = 'fallback-toast';
    const colors = { success: '#00C48C', error: '#FF3D71', warning: '#FF9F43', info: '#840015' };
    t.style.backgroundColor = colors[type] || '#1a1a1a';
    t.textContent = msg;
    container.appendChild(t);
    
    setTimeout(() => {
      t.style.opacity = '0';
      setTimeout(() => t.remove(), 400);
    }, 3500);
  }
}

function showConfirm(title, text, confirmText = 'Confirmer', icon = 'question') {
  if (!isSwalFallback) {
    return Swal.fire({ title, text, icon, showCancelButton: true, confirmButtonColor: '#840015', cancelButtonColor: '#906f6d', confirmButtonText: confirmText, cancelButtonText: 'Annuler' });
  } else {
    const res = confirm(`${title}\n\n${text}`);
    return Promise.resolve({ isConfirmed: res });
  }
}

function showAlert(title, text, icon = 'info') {
  if (!isSwalFallback) {
    return Swal.fire({ title, text, icon, confirmButtonColor: '#840015' });
  } else {
    alert(`${title}\n\n${text}`);
    return Promise.resolve();
  }
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
  link.innerHTML = `<span class="material-symbols-outlined" style="font-size:22px;font-variation-settings:'FILL' 0,'wght' 400,'GRAD' 0,'opsz' 24;">admin_panel_settings</span><span>Admin</span>`;
  nav.appendChild(link);
}
