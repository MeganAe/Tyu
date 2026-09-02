const express = require("express");
const cors = require("cors");
const path = require("path");
const nodemailer = require("nodemailer");
const { createClient } = require("@supabase/supabase-js");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const compression = require("compression");
const morgan = require("morgan");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(compression());
app.use(morgan("dev"));

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'",
          "'unsafe-eval'",
          "https://www.hcaptcha.com",
          "https://*.hcaptcha.com",
          "https://cdn.jsdelivr.net",
          "https://www.google.com/recaptcha/",
          "https://www.gstatic.com/recaptcha/",
        ],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
          "https://cdn.jsdelivr.net",
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        imgSrc: [
          "'self'",
          "data:",
          "https://res.cloudinary.com",
          "https://api.cloudinary.com",
          "https://*.hcaptcha.com",
          "https://www.google.com/recaptcha/",
          "https://www.gstatic.com/recaptcha/",
        ],
        frameSrc: [
          "'self'",
          "https://www.hcaptcha.com",
          "https://*.hcaptcha.com",
          "https://maps.google.com",
          "https://www.google.com",
          "https://www.google.com/recaptcha/",
          "https://recaptcha.google.com/recaptcha/",
        ],
        connectSrc: [
          "'self'",
          "https://czviftkijvzzymimqspa.supabase.co",
          "https://api.cloudinary.com",
          "https://www.hcaptcha.com",
          "https://*.hcaptcha.com",
          "https://www.google.com/recaptcha/",
          "https://www.gstatic.com/recaptcha/",
        ],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

app.use(cors());
app.use(express.json());

const SUPABASE_URL = "https://czviftkijvzzymimqspa.supabase.co";
const SUPABASE_KEY =
  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImN6dmlmdGtpanZ6enltaW1xc3BhIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc3ODQzMDY1MywiZXhwIjoyMDk0MDA2NjUzfQ.j8yyE4UlhknZSE5U3o6Cpb6YoKWvNm8KHQ9I7F8jbEc";
const JWT_SECRET = "alertbukavu_2026_secret_kivu_xyz789!";
const MAIL_USER = "alertbukavu@gmail.com";
const MAIL_PASS = "mepwmtdjmvcnudzg";
const AUTHORITY_EMAILS =
  "ntkhang969@gmail.com,walkermetoushela@gmail.com,shedaamurimedi@gmail.com";

const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

const dbSchema = {
  users: {
    hasUsername: true,
    hasPhotoUrl: true,
    hasLastLogin: false,
    hasNbAlertes: false,
  },
  alertes: {
    hasPhotoUrl: true,
    hasPhotoAuteur: false,
    hasAuteurUsername: true,
    hasAuteurQuartier: false,
    hasResolvedAt: false,
  },
};

async function detectDbSchema() {
  try {
    const { data: users, error } = await supabase
      .from("users")
      .select("*")
      .limit(1);
    if (!error && users && users.length > 0) {
      const keys = Object.keys(users[0]);
      dbSchema.users.hasUsername = keys.includes("username");
      dbSchema.users.hasPhotoUrl = keys.includes("photo_url");
      dbSchema.users.hasLastLogin = keys.includes("last_login");
      dbSchema.users.hasNbAlertes = keys.includes("nb_alertes");
    }
  } catch (e) {
    console.warn(e.message);
  }

  try {
    const { data: alertes, error } = await supabase
      .from("alertes")
      .select("*")
      .limit(1);
    if (!error && alertes && alertes.length > 0) {
      const keys = Object.keys(alertes[0]);
      dbSchema.alertes.hasPhotoUrl = keys.includes("photo_url");
      dbSchema.alertes.hasPhotoAuteur = keys.includes("photo_auteur");
      dbSchema.alertes.hasAuteurUsername = keys.includes("auteur_username");
      dbSchema.alertes.hasAuteurQuartier = keys.includes("auteur_quartier");
      dbSchema.alertes.hasResolvedAt = keys.includes("resolved_at");
    }
  } catch (e) {
    console.warn(e.message);
  }
}

detectDbSchema().catch(console.error);

const RECAPTCHA_SECRET_KEY =
  process.env.RECAPTCHA_SECRET_KEY ||
  "6LfCfv8sAAAAAOiwws2GtPJbmWiAiizh__LQg7Z6";

async function verifyRecaptcha(token, ip) {
  if (!token) return false;
  try {
    const url = "https://www.google.com/recaptcha/api/siteverify";
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: `secret=${RECAPTCHA_SECRET_KEY}&response=${token}${ip ? `&remoteip=${ip}` : ""}`,
    });
    const data = await response.json();
    return !!data.success;
  } catch (err) {
    console.error(err);
    return false;
  }
}

const ALLOWED_QUARTIERS = [
  "Kadutu",
  "Ibanda",
  "Bagira",
  "Nyalukemba",
  "Kasha",
  "Panzi",
  "Ciherano",
  "Essence",
  "Nyawera",
  "Kasali",
  "Autre",
];
const ALLOWED_CATEGORIES = [
  "incendie",
  "route",
  "inondation",
  "accident",
  "securite",
  "sante",
  "eau",
  "meteo",
  "autre",
];

function verifyToken(req, res, next) {
  const auth =
    req.headers.authorization ||
    (req.query.token ? "Bearer " + req.query.token : null);
  if (!auth || !auth.startsWith("Bearer "))
    return res.status(401).json({ error: "Non autorisé" });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token invalide" });
  }
}

function requireAdmin(req, res, next) {
  if (req.user.role !== "admin")
    return res.status(403).json({ error: "Accès refusé" });
  next();
}

const authLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 10,
  message: { error: "Trop de requêtes, veuillez patienter une minute." },
  standardHeaders: true,
  legacyHeaders: false,
});

const alertPublishLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  keyGenerator: (req) => req.user?.id || req.ip,
  message: { error: "Limite de 5 alertes par heure dépassée pour ce compte." },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { keyGeneratorIpFallback: false },
});

async function dbQuery(promise) {
  return Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error("TIMEOUT")), 8000),
    ),
  ]).catch((err) => {
    if (err.message === "TIMEOUT") {
      throw new Error(
        "Le serveur de base de données ne répond pas. Veuillez réessayer.",
      );
    }
    throw err;
  });
}

const handleError = (res, err, defaultMsg = "Une erreur est survenue") => {
  console.error(err.message || err);
  const status = err.message && err.message.includes("Supabase") ? 503 : 500;
  return res.status(status).json({ error: err.message || defaultMsg });
};

function getTransporter() {
  return nodemailer.createTransport({
    service: "gmail",
    auth: { user: MAIL_USER, pass: MAIL_PASS },
  });
}

function escHtml(v = "") {
  return String(v)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function buildEmailHTML(alert, auteur) {
  const colors = {
    critique: "#ef4444",
    moyen: "#f59e0b",
    faible: "#10b981",
  };
  const accentColor = colors[alert.urgence] || colors.moyen;
  const formattedDate = new Date().toLocaleDateString("fr-FR", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  let imageHtml = "";
  if (alert.photo_url) {
    imageHtml = `
      <div style="margin-bottom: 24px;">
        <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">Documentation photographique</span>
        <div style="border-radius: 12px; overflow: hidden; border: 1px solid #e2e8f0; background-color: #f8fafc; text-align: center;">
          <img src="${alert.photo_url}" alt="Incident" style="width: 100%; max-height: 380px; object-fit: cover; display: block; margin: 0 auto;" />
        </div>
      </div>
    `;
  }

  let mapHtml = "";
  if (alert.lat && alert.lng) {
    mapHtml = `
      <div style="margin-top: 28px; text-align: center;">
        <a href="https://www.google.com/maps/search/?api=1&query=${alert.lat},${alert.lng}" target="_blank" style="display: inline-block; background-color: #0f172a; color: #ffffff; padding: 12px 24px; border-radius: 10px; font-size: 13px; font-weight: 600; text-decoration: none; box-shadow: 0 2px 4px rgba(15,23,42,0.1); text-align: center;">
          Consulter la localisation sur Google Maps
        </a>
        <div style="margin-top: 6px; font-size: 11px; color: #64748b;">
          Coordonnées geographiques : ${alert.lat}, ${alert.lng}
        </div>
      </div>
    `;
  }

  return `
    <div style="background-color: #f8fafc; padding: 40px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
      <div style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.03); border: 1px solid #e2e8f0;">
        <div style="height: 6px; background-color: ${accentColor};"></div>
        <div style="padding: 36px;">
          <div style="margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between;">
            <span style="font-size: 16px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">
              AlertBukavu
            </span>
            <span style="background-color: #f8fafc; color: #334155; border: 1px solid #e2e8f0; padding: 6px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;">
              Niveau : ${escHtml((alert.urgence || "moyen").toUpperCase())}
            </span>
          </div>
          <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; line-height: 1.3; margin: 0 0 20px 0; letter-spacing: -0.01em;">
            ${escHtml(alert.titre)}
          </h2>
          <div style="background-color: #f8fafc; border: 1px solid #f1f5f9; border-radius: 12px; padding: 16px; margin-bottom: 24px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td width="50%" style="padding-bottom: 12px; vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Secteur / Quartier</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${escHtml(alert.quartier)}</span>
                </td>
                <td width="50%" style="padding-bottom: 12px; vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Type d'incident</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155; text-transform: capitalize;">${escHtml(alert.categorie)}</span>
                </td>
              </tr>
              <tr>
                <td width="50%" style="vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Signalé par</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${escHtml(auteur)}</span>
                </td>
                <td width="50%" style="vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Date et heure</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${formattedDate}</span>
                </td>
              </tr>
            </table>
          </div>
          <div style="margin-bottom: 24px;">
            <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">Description des faits</span>
            <div style="font-size: 14px; line-height: 1.6; color: #334155; margin: 0; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; white-space: pre-line;">${escHtml(alert.description)}</div>
          </div>
          ${imageHtml}
          ${mapHtml}
        </div>
        <div style="background-color: #f8fafc; border-top: 1px solid #f1f5f9; padding: 24px 36px; text-align: center;">
          <p style="font-size: 11px; line-height: 1.5; color: #94a3b8; margin: 0 0 8px 0;">
            Ce message vous est adressé de manière automatique par la plateforme de sécurité civile AlertBukavu afin d'informer les entités compétentes.
          </p>
          <p style="font-size: 10px; color: #cbd5e1; margin: 0; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">
            Réseau de Vigilance Citoyenne — Bukavu, RDC
          </p>
        </div>
      </div>
    </div>
  `;
}

function buildNeighborhoodNotificationHTML(alert) {
  const colors = {
    critique: "#ef4444",
    moyen: "#f59e0b",
    faible: "#10b981",
  };
  const accentColor = colors[alert.urgence] || colors.moyen;
  const formattedDate = new Date().toLocaleDateString("fr-FR", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  let imageHtml = "";
  if (alert.photo_url) {
    imageHtml = `
      <div style="margin-bottom: 24px;">
        <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">Aperçu visuel</span>
        <div style="border-radius: 12px; overflow: hidden; border: 1px solid #e2e8f0; background-color: #f8fafc; text-align: center;">
          <img src="${alert.photo_url}" alt="Visualisation" style="width: 100%; max-height: 380px; object-fit: cover; display: block; margin: 0 auto;" />
        </div>
      </div>
    `;
  }

  let mapHtml = "";
  if (alert.lat && alert.lng) {
    mapHtml = `
      <div style="margin-top: 28px; text-align: center;">
        <a href="https://www.google.com/maps/search/?api=1&query=${alert.lat},${alert.lng}" target="_blank" style="display: inline-block; background-color: #0f172a; color: #ffffff; padding: 12px 24px; border-radius: 10px; font-size: 13px; font-weight: 600; text-decoration: none; box-shadow: 0 2px 4px rgba(15,23,42,0.1); text-align: center;">
          Consulter la localisation sur Google Maps
        </a>
        <div style="margin-top: 6px; font-size: 11px; color: #64748b;">
          Coordonnées geographiques : ${alert.lat}, ${alert.lng}
        </div>
      </div>
    `;
  }

  return `
    <div style="background-color: #f8fafc; padding: 40px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
      <div style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.03); border: 1px solid #e2e8f0;">
        <div style="height: 6px; background-color: ${accentColor};"></div>
        <div style="padding: 36px;">
          <div style="margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between;">
            <span style="font-size: 16px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">
              AlertBukavu
            </span>
            <span style="background-color: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; padding: 6px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;">
              Avis de vigilance quartier
            </span>
          </div>
          <h2 style="font-size: 22px; font-weight: 800; color: #0f172a; line-height: 1.3; margin: 0 0 20px 0; letter-spacing: -0.01em;">
            ${escHtml(alert.titre)}
          </h2>
          <div style="background-color: #fffbeb; border: 1px solid #fef3c7; border-radius: 12px; padding: 16px; margin-bottom: 24px; color: #b45309; font-size: 13px; font-weight: 500; line-height: 1.5;">
            Message de sécurité : Un incident de niveau ${escHtml((alert.urgence || "moyen").toUpperCase())} a été signalé dans votre secteur (${escHtml(alert.quartier)}). Nous vous invitons à faire preuve de vigilance et à prendre vos dispositions.
          </div>
          <div style="background-color: #f8fafc; border: 1px solid #f1f5f9; border-radius: 12px; padding: 16px; margin-bottom: 24px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td width="50%" style="padding-bottom: 12px; vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Quartier concerné</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${escHtml(alert.quartier)}</span>
                </td>
                <td width="50%" style="padding-bottom: 12px; vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Type de risque</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155; text-transform: capitalize;">${escHtml(alert.categorie)}</span>
                </td>
              </tr>
              <tr>
                <td width="50%" style="vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Urgence</span>
                  <span style="font-size: 13px; font-weight: 700; color: ${accentColor}; text-transform: capitalize;">${escHtml(alert.urgence)}</span>
                </td>
                <td width="50%" style="vertical-align: top;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 2px;">Date d'émission</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${formattedDate}</span>
                </td>
              </tr>
            </table>
          </div>
          <div style="margin-bottom: 24px;">
            <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px;">Détails de la situation</span>
            <div style="font-size: 14px; line-height: 1.6; color: #334155; margin: 0; background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 16px; white-space: pre-line;">${escHtml(alert.description)}</div>
          </div>
          ${imageHtml}
          ${mapHtml}
        </div>
        <div style="background-color: #f8fafc; border-top: 1px solid #f1f5f9; padding: 24px 36px; text-align: center;">
          <p style="font-size: 11px; line-height: 1.5; color: #94a3b8; margin: 0 0 8px 0;">
            Vous recevez cette notification de sécurité car vous êtes enregistré comme résident du quartier ${escHtml(alert.quartier)}.
          </p>
          <p style="font-size: 10px; color: #cbd5e1; margin: 0; text-transform: uppercase; letter-spacing: 0.05em; font-weight: 600;">
            AlertBukavu — Coordination de la Protection Civile — RDC
          </p>
        </div>
      </div>
    </div>
  `;
}

function buildRevocationEmailHTML(alert, reason = "Signalée comme non fondée / fausse alerte") {
  const formattedDate = new Date().toLocaleDateString("fr-FR", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });

  return `
    <div style="background-color: #f8fafc; padding: 40px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;">
      <div style="max-width: 580px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.03); border: 1px solid #fee2e2;">
        <div style="height: 6px; background-color: #dc2626;"></div>
        <div style="padding: 36px;">
          <div style="margin-bottom: 24px; display: flex; align-items: center; justify-content: space-between;">
            <span style="font-size: 16px; font-weight: 800; color: #0f172a; letter-spacing: -0.02em;">
              AlertBukavu
            </span>
            <span style="background-color: #fee2e2; color: #dc2626; border: 1px solid #fecdd3; padding: 6px 12px; border-radius: 9999px; font-size: 11px; font-weight: 700; letter-spacing: 0.05em; text-transform: uppercase;">
              Avis d'Annulation
            </span>
          </div>
          <h2 style="font-size: 20px; font-weight: 800; color: #dc2626; line-height: 1.3; margin: 0 0 16px 0;">
            ANNULATION : Incident suspendu (Fausse alerte)
          </h2>
          <div style="background-color: #fef2f2; border: 1px solid #fee2e2; border-radius: 12px; padding: 16px; margin-bottom: 20px; color: #991b1b; font-size: 13px; line-height: 1.5;">
            L'incident préalablement transmis a été <strong>suspendu</strong> par le système de vigilance suite aux signalements concordants de riverains ou à une modération. Aucune intervention n'est requise.
          </div>
          <div style="background-color: #f8fafc; border: 1px solid #f1f5f9; border-radius: 12px; padding: 16px; margin-bottom: 20px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td width="50%" style="padding-bottom: 8px;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase;">Titre initial</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${escHtml(alert.titre)}</span>
                </td>
                <td width="50%" style="padding-bottom: 8px;">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase;">Quartier</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${escHtml(alert.quartier)}</span>
                </td>
              </tr>
              <tr>
                <td width="50%">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase;">Statut</span>
                  <span style="font-size: 13px; font-weight: 700; color: #dc2626;">Suspendue / Annulée</span>
                </td>
                <td width="50%">
                  <span style="display: block; font-size: 10px; font-weight: 600; color: #64748b; text-transform: uppercase;">Date d'annulation</span>
                  <span style="font-size: 13px; font-weight: 700; color: #334155;">${formattedDate}</span>
                </td>
              </tr>
            </table>
          </div>
        </div>
        <div style="background-color: #f8fafc; border-top: 1px solid #f1f5f9; padding: 20px 36px; text-align: center;">
          <p style="font-size: 11px; line-height: 1.5; color: #94a3b8; margin: 0;">
            Ce message rectificatif est transmis automatiquement par AlertBukavu pour éviter tout déplacement inutile des services de secours.
          </p>
        </div>
      </div>
    </div>
  `;
}

app.post("/api/auth/register", authLimiter, async (req, res) => {
  try {
    const {
      nom,
      username,
      email,
      telephone,
      quartier,
      password,
      recaptchaToken,
    } = req.body;

    const isLocalRequest =
      req.hostname === "localhost" || req.hostname === "127.0.0.1";
    if (!isLocalRequest) {
      const captchaValid = await verifyRecaptcha(recaptchaToken, req.ip);
      if (!captchaValid) {
        return res
          .status(400)
          .json({ error: "Validation captcha échouée. Veuillez réessayer." });
      }
    }

    if (!nom || !username || !email || !telephone || !quartier || !password) {
      return res
        .status(400)
        .json({ error: "Tous les champs sont obligatoires" });
    }

    if (nom.length < 2 || nom.length > 100)
      return res
        .status(400)
        .json({ error: "Le nom doit faire entre 2 et 100 caractères" });

    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res
        .status(400)
        .json({
          error:
            "Le nom d'utilisateur doit contenir entre 3 et 20 caractères (lettres, chiffres, _)",
        });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res
        .status(400)
        .json({ error: "L'adresse email n'est pas valide" });
    }

    const digits = String(telephone)
      .replace(/\D/g, "")
      .replace(/^243(?=\d{9}$)/, "");
    if (digits.length !== 9) {
      return res
        .status(400)
        .json({
          error: "Le numéro de téléphone doit contenir exactement 9 chiffres",
        });
    }

    if (!ALLOWED_QUARTIERS.includes(quartier)) {
      return res
        .status(400)
        .json({ error: "Le quartier sélectionné est invalide" });
    }

    if (password.length < 8) {
      return res
        .status(400)
        .json({ error: "Le mot de passe doit faire au moins 8 caractères" });
    }

    const telFormatted = "+243" + digits;

    const { data: existingEmail } = await dbQuery(
      supabase
        .from("users")
        .select("id")
        .eq("email", email.toLowerCase())
        .maybeSingle(),
    );
    if (existingEmail)
      return res.status(409).json({ error: "Cet email est déjà utilisé" });

    const { data: existingUser } = await dbQuery(
      supabase
        .from("users")
        .select("id")
        .eq("username", username.toLowerCase())
        .maybeSingle(),
    );
    if (existingUser)
      return res
        .status(409)
        .json({ error: "Ce nom d'utilisateur est déjà pris" });

    const password_hash = await bcrypt.hash(password, 12);

    const insertObj = {
      nom,
      username: username.toLowerCase(),
      email: email.toLowerCase(),
      telephone: telFormatted,
      quartier,
      password_hash,
      role: "citizen",
      est_bloque: false,
      nb_fausses_alertes: 0,
    };
    if (dbSchema.users.hasNbAlertes) {
      insertObj.nb_alertes = 0;
    }

    const { data: user, error: insertErr } = await dbQuery(
      supabase.from("users").insert([insertObj]).select().single(),
    );

    if (insertErr || !user) {
      console.error(insertErr);
      return res
        .status(500)
        .json({
          error: insertErr?.message || "Erreur lors de la création du compte",
        });
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        nom: user.nom,
        quartier: user.quartier,
        nb_fausses_alertes: user.nb_fausses_alertes,
        est_bloque: user.est_bloque,
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    );

    return res
      .status(201)
      .json({
        token,
        user: {
          id: user.id,
          nom: user.nom,
          username: user.username,
          email: user.email,
          role: user.role,
          quartier: user.quartier,
          nb_fausses_alertes: user.nb_fausses_alertes,
        },
      });
  } catch (err) {
    return handleError(res, err, "Erreur lors de l'inscription");
  }
});

app.post("/api/auth/login", authLimiter, async (req, res) => {
  try {
    const { email, password, recaptchaToken } = req.body;

    const isLocalRequest =
      req.hostname === "localhost" || req.hostname === "127.0.0.1";
    if (!isLocalRequest) {
      const captchaValid = await verifyRecaptcha(recaptchaToken, req.ip);
      if (!captchaValid) {
        return res
          .status(400)
          .json({ error: "Validation captcha échouée. Veuillez réessayer." });
      }
    }

    if (!email || !password)
      return res.status(400).json({ error: "Email et mot de passe requis" });

    const { data: user, error } = await dbQuery(
      supabase
        .from("users")
        .select("*")
        .eq("email", email.toLowerCase())
        .maybeSingle(),
    );

    if (error || !user)
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });
    if (user.est_bloque)
      return res
        .status(403)
        .json({ error: "Compte suspendu pour fausses alertes" });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid)
      return res.status(401).json({ error: "Email ou mot de passe incorrect" });

    if (dbSchema.users.hasLastLogin) {
      await dbQuery(
        supabase
          .from("users")
          .update({ last_login: new Date().toISOString() })
          .eq("id", user.id),
      );
    }

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        nom: user.nom,
        quartier: user.quartier,
        nb_fausses_alertes: user.nb_fausses_alertes,
        est_bloque: user.est_bloque,
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    );

    return res.json({
      token,
      user: {
        id: user.id,
        nom: user.nom,
        username: user.username,
        email: user.email,
        role: user.role,
        quartier: user.quartier,
        nb_fausses_alertes: user.nb_fausses_alertes,
      },
    });
  } catch (err) {
    return handleError(res, err, "Erreur lors de la connexion");
  }
});

app.get("/api/auth/check-username", async (req, res) => {
  const { username } = req.query;
  if (!username) return res.json({ available: false });
  try {
    const { data } = await dbQuery(
      supabase
        .from("users")
        .select("id")
        .eq("username", username.toLowerCase())
        .maybeSingle(),
    );
    return res.json({ available: !data });
  } catch {
    return res.json({ available: false });
  }
});

app.put("/api/auth/update-photo", verifyToken, async (req, res) => {
  const { photoUrl } = req.body;
  if (!photoUrl) return res.status(400).json({ error: "URL photo manquante" });
  try {
    const { error } = await dbQuery(
      supabase
        .from("users")
        .update({ photo_url: photoUrl })
        .eq("id", req.user.id),
    );
    if (error) throw error;
    return res.json({ message: "Photo mise à jour" });
  } catch (err) {
    return handleError(res, err, "Erreur lors de la mise à jour de la photo");
  }
});

app.put("/api/auth/profile", verifyToken, async (req, res) => {
  try {
    const { nom, quartier, telephone } = req.body;
    if (!nom || !quartier || !telephone)
      return res.status(400).json({ error: "Champs requis manquants" });

    if (nom.length < 2 || nom.length > 100)
      return res
        .status(400)
        .json({ error: "Le nom doit faire entre 2 et 100 caractères" });
    if (!ALLOWED_QUARTIERS.includes(quartier))
      return res.status(400).json({ error: "Quartier invalide" });

    const digits = String(telephone).replace(/\D/g, "");
    if (digits.length !== 9) {
      return res
        .status(400)
        .json({
          error: "Le numéro de téléphone doit contenir exactement 9 chiffres",
        });
    }
    const telFormatted = "+243" + digits;

    const { data: user, error } = await dbQuery(
      supabase
        .from("users")
        .update({ nom, quartier, telephone: telFormatted })
        .eq("id", req.user.id)
        .select()
        .single(),
    );

    if (error || !user)
      return res.status(500).json({ error: "Erreur lors de la mise à jour" });

    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
        nom: user.nom,
        quartier: user.quartier,
        nb_fausses_alertes: user.nb_fausses_alertes,
        est_bloque: user.est_bloque,
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    );

    return res.json({
      token,
      user: {
        id: user.id,
        nom: user.nom,
        username: user.username,
        email: user.email,
        role: user.role,
        quartier: user.quartier,
        nb_fausses_alertes: user.nb_fausses_alertes,
      },
    });
  } catch (err) {
    return handleError(res, err, "Erreur de mise à jour du profil");
  }
});

app.get("/api/auth/me", verifyToken, async (req, res) => {
  try {
    const { data: user, error } = await dbQuery(
      supabase
        .from("users")
        .select(
          "id, nom, username, email, role, quartier, photo_url, nb_fausses_alertes, est_bloque, notifs_last_read",
        )
        .eq("id", req.user.id)
        .maybeSingle(),
    );
    if (error || !user)
      return res.status(404).json({ error: "Utilisateur introuvable" });
    return res.json({ user });
  } catch (err) {
    return handleError(res, err, "Erreur lors de la récupération du profil");
  }
});

app.get("/api/auth/notifications/read-at", verifyToken, async (req, res) => {
  try {
    const { data: user, error } = await dbQuery(
      supabase
        .from("users")
        .select("notifs_last_read")
        .eq("id", req.user.id)
        .maybeSingle(),
    );
    if (error || !user) return res.json({ readAt: null });
    return res.json({ readAt: user.notifs_last_read || null });
  } catch (err) {
    console.warn(err.message);
    return res.json({ readAt: null });
  }
});

app.put("/api/auth/notifications/mark-read", verifyToken, async (req, res) => {
  try {
    const now = new Date().toISOString();
    const { error } = await dbQuery(
      supabase
        .from("users")
        .update({ notifs_last_read: now })
        .eq("id", req.user.id),
    );
    if (error) {
      console.warn(error.message);
      return res.json({ readAt: now, warning: "Champ indisponible" });
    }
    return res.json({ readAt: now });
  } catch (err) {
    console.warn(err.message);
    return res.json({ readAt: new Date().toISOString() });
  }
});

app.get("/api/alertes", verifyToken, async (req, res) => {
  try {
    let baseQuery = supabase
      .from("alertes")
      .select("*, users(nom, username, quartier, photo_url)");

    if (req.user.role !== "admin") {
      baseQuery = baseQuery.neq("statut", "suspendue");
    }

    const { data: alertes, error } = await dbQuery(
      baseQuery.order("created_at", { ascending: false }).limit(100),
    );

    if (error) throw error;

    const formatted = (alertes || []).map((a) => ({
      ...a,
      auteur_nom: a.users?.nom || "Habitant",
      auteur_username: a.users?.username || null,
      auteur_quartier: a.users?.quartier || "",
      photo_auteur: a.users?.photo_url || null,
    }));
    return res.json({ alertes: formatted });
  } catch (err) {
    return handleError(res, err, "Impossible de charger les alertes");
  }
});

app.get("/api/alertes/mes-alertes", verifyToken, async (req, res) => {
  try {
    const { data: alertes, error } = await dbQuery(
      supabase
        .from("alertes")
        .select("*, users(nom, username, quartier, photo_url)")
        .eq("user_id", req.user.id)
        .order("created_at", { ascending: false })
        .limit(50),
    );
    if (error) throw error;
    return res.json({ alertes: alertes || [] });
  } catch (err) {
    return handleError(res, err, "Impossible de charger vos alertes");
  }
});

app.get("/api/alertes/:id", verifyToken, async (req, res) => {
  try {
    const { data: alerte, error } = await dbQuery(
      supabase
        .from("alertes")
        .select("*, users(nom, username, quartier, photo_url)")
        .eq("id", req.params.id)
        .maybeSingle(),
    );
    if (error || !alerte)
      return res.status(404).json({ error: "Alerte introuvable" });

    const formatted = {
      ...alerte,
      auteur_nom: alerte.users?.nom || "Habitant",
      auteur_username: alerte.users?.username || null,
      auteur_quartier: alerte.users?.quartier || "",
      photo_auteur: alerte.users?.photo_url || null,
    };
    return res.json({ alerte: formatted });
  } catch (err) {
    return handleError(
      res,
      err,
      "Impossible de récupérer les détails de l'alerte",
    );
  }
});

let clientsSSE = [];

app.get("/api/alertes/flux", verifyToken, (req, res) => {
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  if (typeof res.flushHeaders === "function") {
    res.flushHeaders();
  }

  res.write("event: init\ndata: connected\n\n");

  clientsSSE.push(res);

  const heartbeat = setInterval(() => {
    try {
      res.write(": keep-alive\n\n");
    } catch {
      clearInterval(heartbeat);
    }
  }, 25000);

  req.on("close", () => {
    clearInterval(heartbeat);
    clientsSSE = clientsSSE.filter((client) => client !== res);
  });
});

function diffuserNouvelleAlerte(alerte) {
  const payload = `data: ${JSON.stringify({ alerte })}\n\n`;
  clientsSSE.forEach((client) => {
    try {
      client.write(payload);
    } catch (e) {
      console.warn("Erreur envoi SSE:", e.message);
    }
  });
}

app.post("/api/alertes", verifyToken, alertPublishLimiter, async (req, res) => {
  try {
    const { data: user, error: userErr } = await dbQuery(
      supabase
        .from("users")
        .select("est_bloque")
        .eq("id", req.user.id)
        .single(),
    );
    if (userErr || !user)
      return res.status(404).json({ error: "Utilisateur introuvable" });
    if (user.est_bloque)
      return res
        .status(403)
        .json({ error: "Votre compte est bloqué pour fausses alertes." });

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { data: recentAlerts, error: countErr } = await dbQuery(
      supabase
        .from("alertes")
        .select("id")
        .eq("user_id", req.user.id)
        .gte("created_at", oneDayAgo),
    );
    if (countErr) throw countErr;
    if (recentAlerts && recentAlerts.length >= 5) {
      return res
        .status(403)
        .json({
          error: "Vous ne pouvez publier plus de 5 alertes par période de 24h.",
        });
    }

    const {
      titre,
      description,
      categorie,
      quartier,
      urgence,
      lat,
      lng,
      photo_url,
      recaptchaToken,
    } = req.body;

    const isLocalRequest =
      req.hostname === "localhost" || req.hostname === "127.0.0.1";
    if (!isLocalRequest) {
      const captchaValid = await verifyRecaptcha(recaptchaToken, req.ip);
      if (!captchaValid) {
        return res
          .status(400)
          .json({ error: "Validation captcha échouée. Veuillez réessayer." });
      }
    }

    if (!titre || !description || !categorie || !quartier) {
      return res.status(400).json({ error: "Champs requis manquants" });
    }

    if (titre.length > 80)
      return res
        .status(400)
        .json({ error: "Le titre dépasse la limite de 80 caractères." });
    if (description.length > 500)
      return res
        .status(400)
        .json({ error: "La description dépasse la limite de 500 caractères." });

    if (!ALLOWED_CATEGORIES.includes(categorie))
      return res.status(400).json({ error: "Catégorie invalide." });
    if (!ALLOWED_QUARTIERS.includes(quartier))
      return res.status(400).json({ error: "Quartier invalide." });
    if (urgence && !["faible", "moyen", "critique"].includes(urgence)) {
      return res.status(400).json({ error: "Niveau d'urgence invalide." });
    }

    const { data: auteurDetail } = await dbQuery(
      supabase
        .from("users")
        .select("username, nom, quartier, photo_url")
        .eq("id", req.user.id)
        .single(),
    );

    const alertInsertObj = {
      titre,
      description,
      categorie,
      quartier,
      urgence: urgence || "moyen",
      lat: lat || null,
      lng: lng || null,
      statut: "active",
      nb_confirmations: 0,
      nb_signalements: 0,
      user_id: req.user.id,
    };
    if (dbSchema.alertes.hasPhotoUrl)
      alertInsertObj.photo_url = photo_url || null;
    if (dbSchema.alertes.hasPhotoAuteur)
      alertInsertObj.photo_auteur = auteurDetail?.photo_url || null;
    if (dbSchema.alertes.hasAuteurUsername)
      alertInsertObj.auteur_username = auteurDetail?.username || null;
    if (dbSchema.alertes.hasAuteurQuartier)
      alertInsertObj.auteur_quartier = auteurDetail?.quartier || null;

    const { data: alerte, error: insertErr } = await dbQuery(
      supabase.from("alertes").insert([alertInsertObj]).select().single(),
    );

    if (insertErr || !alerte) {
      console.error(insertErr);
      return res.status(500).json({ error: "Erreur lors de la publication" });
    }

    if (dbSchema.users.hasNbAlertes) {
      const { data: auteurStats } = await dbQuery(
        supabase
          .from("users")
          .select("nb_alertes")
          .eq("id", req.user.id)
          .single(),
      );
      await dbQuery(
        supabase
          .from("users")
          .update({ nb_alertes: (auteurStats?.nb_alertes || 0) + 1 })
          .eq("id", req.user.id),
      );
    }

    const outputAlerte = {
      ...alerte,
      auteur_nom: auteurDetail?.nom || "Habitant",
      auteur_username: auteurDetail?.username || null,
      auteur_quartier: auteurDetail?.quartier || "",
      photo_auteur: auteurDetail?.photo_url || null,
    };

    diffuserNouvelleAlerte(outputAlerte);

    if (alerte.urgence === "critique") {
      try {
        await getTransporter().sendMail({
          from: `"AlertBukavu" <${MAIL_USER}>`,
          to: AUTHORITY_EMAILS,
          subject: `🚨 [URGENCE CRITIQUE] ${categorie.toUpperCase()} — ${titre}`,
          html: buildEmailHTML(alerte, req.user.nom),
        });
      } catch (e) {
        console.error("Erreur envoi email autorite critique:", e.message);
      }
    }

    return res
      .status(201)
      .json({ alerte: outputAlerte, message: "Alerte publiée avec succès" });
  } catch (err) {
    return handleError(res, err, "Erreur lors de la publication de l'alerte");
  }
});

app.delete("/api/alertes/:id", verifyToken, async (req, res) => {
  try {
    const { data: alerte, error: fetchErr } = await dbQuery(
      supabase
        .from("alertes")
        .select("*")
        .eq("id", req.params.id)
        .maybeSingle(),
    );
    if (fetchErr || !alerte)
      return res.status(404).json({ error: "Alerte introuvable" });

    if (alerte.user_id !== req.user.id && req.user.role !== "admin") {
      return res
        .status(403)
        .json({ error: "Non autorisé à supprimer cette alerte" });
    }

    const { error: delErr } = await dbQuery(
      supabase.from("alertes").delete().eq("id", req.params.id),
    );
    if (delErr) throw delErr;

    if (dbSchema.users.hasNbAlertes) {
      const { data: auteurStats } = await dbQuery(
        supabase
          .from("users")
          .select("nb_alertes")
          .eq("id", alerte.user_id)
          .single(),
      );
      if (auteurStats) {
        await dbQuery(
          supabase
            .from("users")
            .update({
              nb_alertes: Math.max(0, (auteurStats.nb_alertes || 0) - 1),
            })
            .eq("id", alerte.user_id),
        );
      }
    }

    return res.json({ message: "Alerte supprimée avec succès" });
  } catch (err) {
    return handleError(res, err, "Erreur de suppression");
  }
});

app.post("/api/alertes/:id/confirmer", verifyToken, async (req, res) => {
  const alertId = req.params.id;
  try {
    const { data: alerte, error: fetchErr } = await dbQuery(
      supabase
        .from("alertes")
        .select("*")
        .eq("id", alertId)
        .maybeSingle(),
    );
    if (fetchErr || !alerte)
      return res.status(404).json({ error: "Alerte introuvable" });

    if (alerte.user_id === req.user.id) {
      return res
        .status(400)
        .json({ error: "Vous ne pouvez pas confirmer votre propre alerte." });
    }

    const { data: existing } = await dbQuery(
      supabase
        .from("confirmations")
        .select("id")
        .eq("alerte_id", alertId)
        .eq("user_id", req.user.id)
        .maybeSingle(),
    );
    if (existing)
      return res
        .status(409)
        .json({ error: "Vous avez déjà confirmé cette alerte" });

    await dbQuery(
      supabase
        .from("confirmations")
        .insert([{ alerte_id: alertId, user_id: req.user.id }]),
    );

    const nouveauNbConf = (alerte.nb_confirmations || 0) + 1;
    await dbQuery(
      supabase
        .from("alertes")
        .update({ nb_confirmations: nouveauNbConf })
        .eq("id", alertId),
    );

    if (nouveauNbConf === 2 && alerte.urgence !== "critique" && alerte.statut !== "suspendue") {
      try {
        await getTransporter().sendMail({
          from: `"AlertBukavu" <${MAIL_USER}>`,
          to: AUTHORITY_EMAILS,
          subject: `[CONFIRMÉ PAR RIVERAINS] ${alerte.categorie.toUpperCase()} — ${alerte.titre} (${alerte.quartier})`,
          html: buildEmailHTML(alerte, "Citoyens vérifiés de " + alerte.quartier),
        });
      } catch (e) {
        console.error("Erreur envoi email autorite confirme:", e.message);
      }
    }

    return res.json({ message: "Confirmation enregistrée" });
  } catch (err) {
    return handleError(res, err, "Erreur lors de la confirmation");
  }
});

app.post("/api/alertes/:id/signaler", verifyToken, async (req, res) => {
  const alertId = req.params.id;
  try {
    const { data: userVotant } = await dbQuery(
      supabase
        .from("users")
        .select("created_at")
        .eq("id", req.user.id)
        .single(),
    );

    if (userVotant && userVotant.created_at) {
      const ageCompteMs = Date.now() - new Date(userVotant.created_at).getTime();
      if (ageCompteMs < 10 * 60 * 1000) {
        return res.status(403).json({
          error:
            "Votre compte doit avoir au moins 10 minutes d'ancienneté pour pouvoir signaler une alerte.",
        });
      }
    }

    const { data: alerte, error: fetchErr } = await dbQuery(
      supabase
        .from("alertes")
        .select("*")
        .eq("id", alertId)
        .maybeSingle(),
    );
    if (fetchErr || !alerte)
      return res.status(404).json({ error: "Alerte introuvable" });

    if (alerte.user_id === req.user.id) {
      return res
        .status(400)
        .json({ error: "Vous ne pouvez pas signaler votre propre alerte." });
    }

    const { data: existing } = await dbQuery(
      supabase
        .from("signalements")
        .select("id")
        .eq("alerte_id", alertId)
        .eq("user_id", req.user.id)
        .maybeSingle(),
    );
    if (existing)
      return res
        .status(409)
        .json({ error: "Vous avez déjà signalé cette alerte" });

    await dbQuery(
      supabase
        .from("signalements")
        .insert([{ alerte_id: alertId, user_id: req.user.id }]),
    );

    const nouveauNb = (alerte.nb_signalements || 0) + 1;
    const nbConfirmations = alerte.nb_confirmations || 0;
    const update = { nb_signalements: nouveauNb };

    const doitSuspendre = nouveauNb >= 5 && nouveauNb > 2 * nbConfirmations;

    if (doitSuspendre) {
      update.statut = "suspendue";
      const { data: auteur } = await dbQuery(
        supabase
          .from("users")
          .select("nb_fausses_alertes")
          .eq("id", alerte.user_id)
          .single(),
      );
      const nbFausses = (auteur?.nb_fausses_alertes || 0) + 1;
      await dbQuery(
        supabase
          .from("users")
          .update({ nb_fausses_alertes: nbFausses, est_bloque: nbFausses >= 3 })
          .eq("id", alerte.user_id),
      );

      if (alerte.urgence === "critique" || nbConfirmations >= 2) {
        try {
          await getTransporter().sendMail({
            from: `"AlertBukavu" <${MAIL_USER}>`,
            to: AUTHORITY_EMAILS,
            subject: `[ANNULATION] Fausse alerte suspendue — ${alerte.titre}`,
            html: buildRevocationEmailHTML(
              alerte,
              "Suspendue suite à des signalements de riverains",
            ),
          });
        } catch (e) {
          console.error("Erreur envoi révocation email:", e.message);
        }
      }
    }

    await dbQuery(supabase.from("alertes").update(update).eq("id", alertId));

    if (doitSuspendre) {
      return res.json({
        message: "Alerte suspendue après signalements concordants.",
      });
    }

    return res.json({
      message: `Signalement enregistré (${nouveauNb} signalement(s) / ${nbConfirmations} confirmation(s))`,
    });
  } catch (err) {
    return handleError(res, err, "Erreur lors du signalement");
  }
});

app.put(
  "/api/alertes/:id/statut",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    const { statut } = req.body;
    const allowed = ["active", "resolue", "suspendue"];
    if (!allowed.includes(statut))
      return res.status(400).json({ error: "Statut invalide" });

    try {
      const updateObj = { statut };
      if (dbSchema.alertes.hasResolvedAt) {
        if (statut === "resolue") {
          updateObj.resolved_at = new Date().toISOString();
        } else {
          updateObj.resolved_at = null;
        }
      }

      const { data: alerteExistante } = await dbQuery(
        supabase.from("alertes").select("*").eq("id", req.params.id).maybeSingle(),
      );

      const { error } = await dbQuery(
        supabase.from("alertes").update(updateObj).eq("id", req.params.id),
      );
      if (error) throw error;

      if (statut === "suspendue" && alerteExistante) {
        if (alerteExistante.urgence === "critique" || (alerteExistante.nb_confirmations || 0) >= 2) {
          try {
            await getTransporter().sendMail({
              from: `"AlertBukavu" <${MAIL_USER}>`,
              to: AUTHORITY_EMAILS,
              subject: `[ANNULATION] Fausse alerte suspendue par la modération — ${alerteExistante.titre}`,
              html: buildRevocationEmailHTML(alerteExistante, "Suspendue manuellement par l'administration après vérification"),
            });
          } catch (e) {
            console.error("Erreur envoi révocation admin:", e.message);
          }
        }
      }

      return res.json({ message: "Statut mis à jour" });
    } catch (err) {
      return handleError(res, err, "Erreur de mise à jour du statut");
    }
  },
);

app.get("/api/alertes/:id/commentaires", verifyToken, async (req, res) => {
  try {
    const { data: comments, error } = await dbQuery(
      supabase
        .from("commentaires")
        .select("*")
        .eq("alerte_id", req.params.id)
        .order("created_at", { ascending: true }),
    );
    if (error) throw error;
    return res.json({ commentaires: comments || [] });
  } catch (err) {
    return handleError(res, err, "Impossible de charger les commentaires");
  }
});

app.post("/api/alertes/:id/commentaires", verifyToken, async (req, res) => {
  try {
    const { contenu } = req.body;
    if (!contenu || contenu.trim().length === 0) {
      return res
        .status(400)
        .json({ error: "Le contenu du commentaire est obligatoire" });
    }
    if (contenu.length > 500) {
      return res
        .status(400)
        .json({ error: "Le commentaire ne peut pas dépasser 500 caractères" });
    }

    const { data: user, error: userErr } = await dbQuery(
      supabase
        .from("users")
        .select("nom, username, photo_url")
        .eq("id", req.user.id)
        .single(),
    );
    if (userErr || !user)
      return res.status(404).json({ error: "Utilisateur introuvable" });

    const insertObj = {
      alerte_id: req.params.id,
      user_id: req.user.id,
      auteur_nom: user.nom,
      auteur_username: user.username,
      photo_auteur: user.photo_url || null,
      contenu: contenu.trim(),
    };

    const { data: comment, error: insertErr } = await dbQuery(
      supabase.from("commentaires").insert([insertObj]).select().single(),
    );
    if (insertErr || !comment) {
      throw insertErr || new Error("Erreur d'insertion");
    }

    return res.status(201).json({ commentaire: comment });
  } catch (err) {
    return handleError(
      res,
      err,
      "Erreur lors de la publication du commentaire",
    );
  }
});

app.get("/api/stats", verifyToken, async (req, res) => {
  try {
    const { data: alertes, error } = await dbQuery(
      supabase.from("alertes").select("*"),
    );
    if (error) throw error;

    const total = alertes.length;
    let resolues = 0;
    let critiques = 0;
    let totalConfirmations = 0;
    const parCat = {};
    const parQuartier = {};
    const parUrgence = { faible: 0, moyen: 0, critique: 0 };

    const timeline = {};
    for (let i = 6; i >= 0; i--) {
      const d = new Date();
      d.setDate(d.getDate() - i);
      const dayLabel = d.toLocaleDateString("fr-FR", {
        weekday: "short",
        day: "numeric",
      });
      const isoDate = d.toISOString().split("T")[0];
      timeline[isoDate] = { label: dayLabel, count: 0 };
    }

    let sumResTime = 0;
    let countResTime = 0;

    alertes.forEach((a) => {
      if (a.statut === "resolue") {
        resolues++;
        if (a.resolved_at && a.created_at) {
          const timeDiff =
            new Date(a.resolved_at).getTime() -
            new Date(a.created_at).getTime();
          if (timeDiff > 0) {
            sumResTime += timeDiff;
            countResTime++;
          }
        }
      }
      if (a.urgence === "critique") critiques++;
      totalConfirmations += a.nb_confirmations || 0;

      parCat[a.categorie] = (parCat[a.categorie] || 0) + 1;
      parQuartier[a.quartier] = (parQuartier[a.quartier] || 0) + 1;
      parUrgence[a.urgence] = (parUrgence[a.urgence] || 0) + 1;

      const dateKey = new Date(a.created_at).toISOString().split("T")[0];
      if (timeline[dateKey]) {
        timeline[dateKey].count++;
      }
    });

    const tempsMoyenResolution =
      countResTime > 0
        ? (sumResTime / (1000 * 60 * 60 * countResTime)).toFixed(1)
        : 0;
    const txResolution = total > 0 ? Math.round((resolues / total) * 100) : 0;

    return res.json({
      total,
      resolues,
      critiques,
      totalConfirmations,
      parCat,
      parQuartier,
      parUrgence,
      timeline: Object.values(timeline),
      txResolution,
      tempsMoyenResolution,
    });
  } catch (err) {
    return handleError(res, err, "Erreur de chargement des statistiques");
  }
});

app.get("/api/admin/users", verifyToken, requireAdmin, async (req, res) => {
  try {
    const selectFields = [
      "id",
      "nom",
      "email",
      "role",
      "quartier",
      "nb_fausses_alertes",
      "est_bloque",
      "created_at",
    ];
    if (dbSchema.users.hasNbAlertes) {
      selectFields.push("nb_alertes");
    }
    const { data: users, error } = await dbQuery(
      supabase
        .from("users")
        .select(selectFields.join(", "))
        .order("created_at", { ascending: false }),
    );
    if (error) throw error;
    return res.json({ users: users || [] });
  } catch (err) {
    return handleError(res, err, "Erreur de chargement des utilisateurs");
  }
});

app.put(
  "/api/admin/users/:id/bloquer",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    if (req.params.id === req.user.id) {
      return res
        .status(400)
        .json({ error: "Vous ne pouvez pas vous bloquer vous-même" });
    }
    const { est_bloque } = req.body;
    try {
      const { error } = await dbQuery(
        supabase.from("users").update({ est_bloque }).eq("id", req.params.id),
      );
      if (error) throw error;
      return res.json({
        message: est_bloque ? "Utilisateur bloqué" : "Utilisateur débloqué",
      });
    } catch (err) {
      return handleError(res, err, "Erreur de blocage");
    }
  },
);

app.put(
  "/api/admin/users/:id/promouvoir",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { error } = await dbQuery(
        supabase
          .from("users")
          .update({ role: "admin" })
          .eq("id", req.params.id),
      );
      if (error) throw error;
      return res.json({
        message: "Utilisateur promu au rôle Administrateur avec succès",
      });
    } catch (err) {
      return handleError(res, err, "Erreur de promotion");
    }
  },
);

app.delete(
  "/api/admin/users/:id",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    if (req.params.id === req.user.id) {
      return res
        .status(400)
        .json({ error: "Vous ne pouvez pas vous supprimer vous-même" });
    }
    const userId = req.params.id;
    try {
      await dbQuery(
        supabase.from("confirmations").delete().eq("user_id", userId),
      );
      await dbQuery(
        supabase.from("signalements").delete().eq("user_id", userId),
      );
      await dbQuery(
        supabase.from("commentaires").delete().eq("user_id", userId),
      );
      await dbQuery(supabase.from("alertes").delete().eq("user_id", userId));
      const { error } = await dbQuery(
        supabase.from("users").delete().eq("id", userId),
      );
      if (error) throw error;
      return res.json({ message: "Utilisateur supprimé avec succès" });
    } catch (err) {
      return handleError(res, err, "Erreur de suppression de l'utilisateur");
    }
  },
);

app.post(
  "/api/admin/alertes/:id/notifier",
  verifyToken,
  requireAdmin,
  async (req, res) => {
    try {
      const { data: alerte, error: fetchErr } = await dbQuery(
        supabase
          .from("alertes")
          .select("*")
          .eq("id", req.params.id)
          .maybeSingle(),
      );
      if (fetchErr || !alerte)
        return res.status(404).json({ error: "Alerte introuvable" });

      const { data: users, error: usersErr } = await dbQuery(
        supabase
          .from("users")
          .select("email, nom")
          .eq("quartier", alerte.quartier),
      );
      if (usersErr) throw usersErr;

      const emails = (users || [])
        .map((u) => u.email)
        .filter((e) => e && e !== req.user.email);
      if (!emails.length)
        return res.json({
          message: "Aucun résident à notifier dans ce quartier",
        });

      await getTransporter().sendMail({
        from: `"AlertBukavu" <${MAIL_USER}>`,
        to: emails,
        subject: `[VIGILANCE] Secteur ${alerte.quartier.toUpperCase()} — ${alerte.titre}`,
        html: buildNeighborhoodNotificationHTML(alerte),
      });

      return res.json({
        message: `Notification envoyée à ${emails.length} habitant(s) du quartier ${alerte.quartier}.`,
      });
    } catch (err) {
      return handleError(res, err, "Erreur d'envoi de la notification");
    }
  },
);

app.use(express.static(path.join(__dirname, "public")));

app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html")),
);
app.get("*", (req, res) =>
  res.status(404).sendFile(path.join(__dirname, "public", "404.html")),
);

app.listen(PORT, () =>
  console.log(`AlertBukavu running on http://localhost:${PORT}`),
);
