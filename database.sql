create extension if not exists "uuid-ossp";

drop table if exists signalements cascade;
drop table if exists confirmations cascade;
drop table if exists commentaires cascade;
drop table if exists alertes cascade;
drop table if exists alerts cascade;
drop table if exists users cascade;

create table users (
  id uuid default uuid_generate_v4() primary key,
  nom varchar(100) not null,
  email varchar(150) unique not null,
  telephone varchar(20),
  password_hash text not null,
  role varchar(20) default 'citizen',
  quartier varchar(100),
  nb_fausses_alertes integer default 0,
  est_bloque boolean default false,
  created_at timestamptz default now()
);

create table alertes (
  id uuid default uuid_generate_v4() primary key,
  titre varchar(200) not null,
  description text not null,
  categorie varchar(30) not null,
  quartier varchar(100),
  urgence varchar(20) default 'moyen',
  statut varchar(20) default 'active',
  lat decimal(10,7),
  lng decimal(10,7),
  nb_confirmations integer default 0,
  nb_signalements integer default 0,
  user_id uuid references users(id),
  created_at timestamptz default now()
);

create table confirmations (
  id uuid default uuid_generate_v4() primary key,
  alerte_id uuid references alertes(id) on delete cascade,
  user_id uuid references users(id),
  created_at timestamptz default now()
);

create table signalements (
  id uuid default uuid_generate_v4() primary key,
  alerte_id uuid references alertes(id) on delete cascade,
  user_id uuid references users(id),
  created_at timestamptz default now()
);

create table commentaires (
  id uuid default uuid_generate_v4() primary key,
  alerte_id uuid references alertes(id) on delete cascade,
  user_id uuid references users(id) on delete cascade,
  auteur_nom varchar(100) not null,
  auteur_username varchar(30),
  photo_auteur text,
  contenu text not null,
  created_at timestamptz default now()
);

create index idx_alertes_statut on alertes(statut);
create index idx_alertes_created on alertes(created_at desc);
create index idx_alertes_quartier on alertes(quartier);
create index idx_alertes_user on alertes(user_id);

alter table users enable row level security;
alter table alertes enable row level security;
alter table confirmations enable row level security;
alter table signalements enable row level security;
alter table commentaires enable row level security;

create policy "users_all" on users for all using (true);
create policy "alertes_select" on alertes for select using (true);
create policy "alertes_insert" on alertes for insert with check (true);
create policy "alertes_update" on alertes for update using (true);
create policy "confirmations_all" on confirmations for all using (true);
create policy "signalements_all" on signalements for all using (true);
create policy "commentaires_select" on commentaires for select using (true);
create policy "commentaires_insert" on commentaires for insert with check (true);

alter table users add column if not exists username varchar(30) unique;
alter table users add column if not exists photo_url text;
alter table alertes add column if not exists photo_url text;
alter table alertes add column if not exists photo_auteur text;
alter table alertes add column if not exists auteur_username varchar(30);
alter table alertes add column if not exists auteur_quartier varchar(100);
alter table users add column if not exists last_login timestamptz;
alter table users add column if not exists nb_alertes integer default 0;
alter table alertes add column if not exists resolved_at timestamptz;
alter table users add column if not exists notifs_last_read timestamptz;
