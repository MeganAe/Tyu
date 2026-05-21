CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

DROP TABLE IF EXISTS signalements CASCADE;
DROP TABLE IF EXISTS confirmations CASCADE;
DROP TABLE IF EXISTS alertes CASCADE;
DROP TABLE IF EXISTS alerts CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- Table utilisateurs
CREATE TABLE users (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  nom VARCHAR(100) NOT NULL,
  email VARCHAR(150) UNIQUE NOT NULL,
  telephone VARCHAR(20),
  password_hash TEXT NOT NULL,
  role VARCHAR(20) DEFAULT 'citizen',
  quartier VARCHAR(100),
  nb_fausses_alertes INTEGER DEFAULT 0,
  est_bloque BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table alertes
CREATE TABLE alertes (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  titre VARCHAR(200) NOT NULL,
  description TEXT NOT NULL,
  categorie VARCHAR(30) NOT NULL,
  quartier VARCHAR(100),
  urgence VARCHAR(20) DEFAULT 'moyen',
  statut VARCHAR(20) DEFAULT 'active',
  lat DECIMAL(10,7),
  lng DECIMAL(10,7),
  nb_confirmations INTEGER DEFAULT 0,
  nb_signalements INTEGER DEFAULT 0,
  user_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table confirmations
CREATE TABLE confirmations (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  alerte_id UUID REFERENCES alertes(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table signalements
CREATE TABLE signalements (
  id UUID DEFAULT uuid_generate_v4() PRIMARY KEY,
  alerte_id UUID REFERENCES alertes(id) ON DELETE CASCADE,
  user_id UUID REFERENCES users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index
CREATE INDEX idx_alertes_statut ON alertes(statut);
CREATE INDEX idx_alertes_created ON alertes(created_at DESC);
CREATE INDEX idx_alertes_quartier ON alertes(quartier);
CREATE INDEX idx_alertes_user ON alertes(user_id);

-- RLS
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE alertes ENABLE ROW LEVEL SECURITY;
ALTER TABLE confirmations ENABLE ROW LEVEL SECURITY;
ALTER TABLE signalements ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_all" ON users FOR ALL USING (true);
CREATE POLICY "alertes_select" ON alertes FOR SELECT USING (true);
CREATE POLICY "alertes_insert" ON alertes FOR INSERT WITH CHECK (true);
CREATE POLICY "alertes_update" ON alertes FOR UPDATE USING (true);
CREATE POLICY "confirmations_all" ON confirmations FOR ALL USING (true);
CREATE POLICY "signalements_all" ON signalements FOR ALL USING (true);

-- Colonnes supplémentaires 
ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(30) UNIQUE;
ALTER TABLE users ADD COLUMN IF NOT EXISTS photo_url TEXT;
ALTER TABLE alertes ADD COLUMN IF NOT EXISTS photo_url TEXT;
ALTER TABLE alertes ADD COLUMN IF NOT EXISTS photo_auteur TEXT;
ALTER TABLE alertes ADD COLUMN IF NOT EXISTS auteur_username VARCHAR(30);
ALTER TABLE alertes ADD COLUMN IF NOT EXISTS auteur_quartier VARCHAR(100);
ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login TIMESTAMPTZ;
ALTER TABLE users ADD COLUMN IF NOT EXISTS nb_alertes INTEGER DEFAULT 0;
ALTER TABLE alertes ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;

