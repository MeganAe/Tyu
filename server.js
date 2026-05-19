const express = require('express');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const { createClient } = require('@supabase/supabase-js');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// ===== CONFIG =====
const SUPABASE_URL = 'https://czviftkijvzzymimqspa.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN6dmlmdGtpanZ6enltaW1xc3BhIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODQzMDY1MywiZXhwIjoyMDk0MDA2NjUzfQ.j8yyE4UlhknZSE5U3o6Cpb6YoKWvNm8KHQ9I7F8jbEc';
const JWT_SECRET = 'alertbukavu_2026_secret_kivu_xyz789!';
const MAIL_USER = 'alertbukavu@gmail.com';
const MAIL_PASS = 'mepwmtdjmvcnudzg';
const AUTHORITY_EMAILS = 'ntkhang969@gmail.com,walkermetoushela@gmail.com,shedaamurimedi@gmail.com';

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// ===== MIDDLEWARE AUTH =====
function verifyToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ error: 'Non autorise' });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalide' });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acces refuse' });
  next();
}

// ===== EMAIL =====
function getTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: { user: MAIL_USER, pass: MAIL_PASS }
  });
}

function escHtml(v = '') {
  return String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function buildEmailHTML(alert, auteur) {
  const urgColors = { critique: '#FF3D71', moyen: '#FF9F43', faible: '#00C48C' };
  const color = urgColors[alert.urgence] || '#FF9F43';
  return `
    <div style="font-family:Inter,Arial,sans-serif;max-width:600px;margin:auto;background:#1a1a1a;color:#fff;padding:32px;border-radius:12px;">
      <div style="background:${color};padding:4px 14px;border-radius:6px;display:inline-block;font-size:11px;font-weight:800;margin-bottom:16px;letter-spacing:.05em;">
        ALERTE ${escHtml((alert.urgence||'MOYEN').toUpperCase())}
      </div>
      <h2 style="margin:0 0 10px;font-size:20px;">${escHtml(alert.titre)}</h2>
      <p style="color:#aaa;font-size:13px;margin:0 0 4px;">
        Catégorie: ${escHtml(alert.categorie)} &nbsp;|&nbsp;
        Quartier: ${escHtml(alert.quartier)} &nbsp;|&nbsp;
        ${new Date().toLocaleString('fr-FR')}
      </p>
      <p style="color:#aaa;font-size:13px;margin:0 0 20px;">Publié par: ${escHtml(auteur)}</p>
      <p style="color:#ccc;line-height:1.7;font-size:14px;">${escHtml(alert.description)}</p>
      <p style="color:#555;margin-top:28px;font-size:11px;border-top:1px solid #2a2a2a;padding-top:16px;">
        Alert Bukavu — Plateforme d'alerte citoyenne — Bukavu, RDC
      </p>
    </div>`;
}

// ===========================
// ===== ROUTES AUTH =====
// ===========================

// Inscription
app.post('/api/auth/register', async (req, res) => {
  const { nom, email, telephone, quartier, password } = req.body;
  if (!nom || !email || !password) return res.status(400).json({ error: 'Champs requis manquants' });

  const { data: existing } = await supabase.from('users').select('id').eq('email', email.toLowerCase()).single();
  if (existing) return res.status(409).json({ error: 'Cet email est déjà utilisé' });

  const password_hash = await bcrypt.hash(password, 12);
  const { data: user, error } = await supabase.from('users')
    .insert([{ nom, email: email.toLowerCase(), telephone, quartier, password_hash, role: 'citizen', est_bloque: false, nb_fausses_alertes: 0 }])
    .select().single();

  if (error) return res.status(500).json({ error: 'Erreur lors de la création du compte' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nom: user.nom, quartier: user.quartier }, JWT_SECRET, { expiresIn: '7d' });
  return res.status(201).json({ token, user: { id: user.id, nom: user.nom, email: user.email, role: user.role, quartier: user.quartier } });
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis' });

  const { data: user } = await supabase.from('users').select('*').eq('email', email.toLowerCase()).single();
  if (!user) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
  if (user.est_bloque) return res.status(403).json({ error: 'Compte suspendu pour fausses alertes' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });

  const token = jwt.sign({ id: user.id, email: user.email, role: user.role, nom: user.nom, quartier: user.quartier }, JWT_SECRET, { expiresIn: '7d' });
  return res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, role: user.role, quartier: user.quartier } });
});

// ===========================
// ===== ROUTES ALERTES =====
// ===========================

// Toutes les alertes
app.get('/api/alertes', verifyToken, async (req, res) => {
  const { data: alertes, error } = await supabase
    .from('alertes').select('*, users(nom, quartier)')
    .neq('statut', 'suspendue')
    .order('created_at', { ascending: false }).limit(60);

  if (error) return res.status(500).json({ error: 'Erreur serveur' });
  const formatted = (alertes || []).map(a => ({ ...a, auteur_nom: a.users?.nom || 'Habitant', auteur_quartier: a.users?.quartier || '' }));
  return res.json({ alertes: formatted });
});

// Mes alertes
app.get('/api/alertes/mes-alertes', verifyToken, async (req, res) => {
  const { data: alertes } = await supabase.from('alertes').select('*')
    .eq('user_id', req.user.id).order('created_at', { ascending: false }).limit(20);
  return res.json({ alertes: alertes || [] });
});

// Publier une alerte
app.post('/api/alertes', verifyToken, async (req, res) => {
  const { data: userData } = await supabase.from('users').select('est_bloque').eq('id', req.user.id).single();
  if (userData?.est_bloque) return res.status(403).json({ error: 'Votre compte est suspendu' });

  const { titre, description, categorie, quartier, urgence, lat, lng } = req.body;
  if (!titre || !description || !categorie || !quartier) return res.status(400).json({ error: 'Champs requis manquants' });

  const { data: alerte, error } = await supabase.from('alertes').insert([{
    titre, description, categorie, quartier, urgence: urgence || 'moyen',
    lat: lat || null, lng: lng || null,
    statut: 'active', nb_confirmations: 0, nb_signalements: 0,
    user_id: req.user.id
  }]).select().single();

  if (error) return res.status(500).json({ error: 'Erreur lors de la publication' });

  // Email aux autorités
  try {
    await getTransporter().sendMail({
      from: `"Alert Bukavu" <${MAIL_USER}>`,
      to: AUTHORITY_EMAILS,
      subject: `[${(urgence||'MOYEN').toUpperCase()}] ${categorie.toUpperCase()} — ${titre}`,
      html: buildEmailHTML(alerte, req.user.nom)
    });
  } catch(e) { console.error('Email error:', e.message); }

  return res.status(201).json({ alerte, message: 'Alerte publiée avec succès' });
});

// Confirmer une alerte
app.post('/api/alertes/:id/confirmer', verifyToken, async (req, res) => {
  const alertId = req.params.id;
  const { data: existing } = await supabase.from('confirmations')
    .select('id').eq('alerte_id', alertId).eq('user_id', req.user.id).single();
  if (existing) return res.status(409).json({ error: 'Vous avez déjà confirmé cette alerte' });

  await supabase.from('confirmations').insert([{ alerte_id: alertId, user_id: req.user.id }]);
  const { data: alerte } = await supabase.from('alertes').select('nb_confirmations').eq('id', alertId).single();
  await supabase.from('alertes').update({ nb_confirmations: (alerte?.nb_confirmations || 0) + 1 }).eq('id', alertId);

  return res.json({ message: 'Confirmation enregistrée' });
});

// Signaler une fausse alerte
app.post('/api/alertes/:id/signaler', verifyToken, async (req, res) => {
  const alertId = req.params.id;
  const { data: alerte } = await supabase.from('alertes').select('user_id, nb_signalements').eq('id', alertId).single();
  if (!alerte) return res.status(404).json({ error: 'Alerte introuvable' });
  if (alerte.user_id === req.user.id) return res.status(403).json({ error: 'Vous ne pouvez pas signaler votre propre alerte' });

  const { data: existing } = await supabase.from('signalements')
    .select('id').eq('alerte_id', alertId).eq('user_id', req.user.id).single();
  if (existing) return res.status(409).json({ error: 'Vous avez déjà signalé cette alerte' });

  await supabase.from('signalements').insert([{ alerte_id: alertId, user_id: req.user.id }]);
  const nouveauNb = (alerte.nb_signalements || 0) + 1;
  const update = { nb_signalements: nouveauNb };

  if (nouveauNb >= 5) {
    update.statut = 'suspendue';
    const { data: auteur } = await supabase.from('users').select('nb_fausses_alertes').eq('id', alerte.user_id).single();
    const nbFausses = (auteur?.nb_fausses_alertes || 0) + 1;
    await supabase.from('users').update({ nb_fausses_alertes: nbFausses, est_bloque: nbFausses >= 3 }).eq('id', alerte.user_id);
  }
  await supabase.from('alertes').update(update).eq('id', alertId);

  return res.json({ message: nouveauNb >= 5 ? 'Alerte suspendue après 5 signalements' : `Signalement enregistré (${nouveauNb}/5)` });
});

// Changer statut (admin)
app.put('/api/alertes/:id/statut', verifyToken, requireAdmin, async (req, res) => {
  const { statut } = req.body;
  const allowed = ['active', 'resolue', 'suspendue'];
  if (!allowed.includes(statut)) return res.status(400).json({ error: 'Statut invalide' });
  await supabase.from('alertes').update({ statut }).eq('id', req.params.id);
  return res.json({ message: 'Statut mis à jour' });
});

// ===========================
// ===== ROUTES ADMIN =====
// ===========================

app.get('/api/admin/users', verifyToken, requireAdmin, async (req, res) => {
  const { data: users } = await supabase.from('users')
    .select('id, nom, email, role, quartier, nb_fausses_alertes, est_bloque, created_at')
    .order('created_at', { ascending: false });
  return res.json({ users: users || [] });
});

app.put('/api/admin/users/:id/bloquer', verifyToken, requireAdmin, async (req, res) => {
  const { est_bloque } = req.body;
  await supabase.from('users').update({ est_bloque }).eq('id', req.params.id);
  return res.json({ message: est_bloque ? 'Utilisateur bloqué' : 'Utilisateur débloqué' });
});

// ===========================
// ===== FICHIERS STATIQUES =====
// ===========================
app.use(express.static(path.join(__dirname, 'public')));

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

app.listen(PORT, () => console.log(`AlertBukavu running on http://localhost:${PORT}`));
