-- ============================================================================
-- COORDO EPS — CONFIGURATION SUPABASE COMPLÈTE (MULTI-ÉTABLISSEMENT)
-- Fichier prêt à être copié-collé et exécuté dans le SQL Editor de Supabase.
-- ============================================================================

-- 0. Extension de chiffrement pour le hachage sécurisé (bcrypt) des mots de passe
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- 1. TABLES PRINCIPALES (Cloisonnées par etablissement_id)
-- ============================================================================

-- 1.1 Table des profils et droits d'accès par établissement
CREATE TABLE IF NOT EXISTS public.app_profils (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    etablissement_id TEXT NOT NULL DEFAULT 'lfp-pekin',
    nom_affiche TEXT NOT NULL,
    role TEXT NOT NULL,
    mot_de_passe_hash TEXT NOT NULL,
    droits JSONB NOT NULL DEFAULT '{}'::jsonb,
    actif BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT app_profils_etab_nom_unique UNIQUE (etablissement_id, nom_affiche)
);

CREATE INDEX IF NOT EXISTS idx_app_profils_etab ON public.app_profils (etablissement_id);

-- 1.2 Table de stockage structuré de l'état de l'application par établissement
CREATE TABLE IF NOT EXISTS public.app_donnees (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    etablissement_id TEXT NOT NULL DEFAULT 'lfp-pekin',
    cle TEXT NOT NULL DEFAULT 'etat_global',
    donnees JSONB NOT NULL DEFAULT '{}'::jsonb,
    version TEXT NOT NULL DEFAULT '1.0.0',
    updated_by_nom TEXT,
    updated_by_role TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT app_donnees_etab_cle_unique UNIQUE (etablissement_id, cle)
);

CREATE INDEX IF NOT EXISTS idx_app_donnees_etab ON public.app_donnees (etablissement_id);

-- 1.3 Table du journal d'audit / historique des modifications
CREATE TABLE IF NOT EXISTS public.historique_modifications (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    etablissement_id TEXT NOT NULL DEFAULT 'lfp-pekin',
    auteur_nom TEXT NOT NULL,
    auteur_role TEXT NOT NULL,
    action_resume TEXT NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_hist_modif_etab_date ON public.historique_modifications (etablissement_id, created_at DESC);

-- ============================================================================
-- 2. INSERTION DES PROFILS PAR DÉFAUT ('lfp-pekin')
-- ============================================================================

INSERT INTO public.app_profils (etablissement_id, nom_affiche, role, mot_de_passe_hash, droits, actif)
VALUES
    (
        'lfp-pekin',
        'Coordinateur EPS',
        'coord',
        crypt('Zidane_10', gen_salt('bf')),
        '{"admin": true, "edit_all": true}'::jsonb,
        true
    ),
    (
        'lfp-pekin',
        'Enseignant EPS',
        'eps',
        crypt('eps2026', gen_salt('bf')),
        '{"admin": false, "edit_eps": true, "read_all": true}'::jsonb,
        true
    ),
    (
        'lfp-pekin',
        'Professeur des écoles (Primaire)',
        'primaire',
        crypt('primaire2026', gen_salt('bf')),
        '{"admin": false, "edit_primaire": true, "read_all": true}'::jsonb,
        true
    ),
    (
        'lfp-pekin',
        'Administration / Vie scolaire',
        'secr',
        crypt('admin2026', gen_salt('bf')),
        '{"admin": false, "read_all": true}'::jsonb,
        true
    ),
    (
        'lfp-pekin',
        'Élève / Consultation',
        'eleve',
        crypt('eleve2026', gen_salt('bf')),
        '{"admin": false, "read_poles": true}'::jsonb,
        true
    )
ON CONFLICT (etablissement_id, nom_affiche) DO UPDATE
SET
    role = EXCLUDED.role,
    mot_de_passe_hash = EXCLUDED.mot_de_passe_hash,
    droits = EXCLUDED.droits,
    actif = EXCLUDED.actif,
    updated_at = now();

-- Initialisation d'une entrée d'état pour lfp-pekin si absente
INSERT INTO public.app_donnees (etablissement_id, cle, donnees, version, updated_by_nom, updated_by_role)
VALUES ('lfp-pekin', 'etat_global', '{}'::jsonb, '0.9.8', 'Système', 'coord')
ON CONFLICT (etablissement_id, cle) DO NOTHING;

-- ============================================================================
-- 3. SÉCURITÉ ROW LEVEL SECURITY (RLS) STRICTE
-- ============================================================================
-- Aucun accès direct non contrôlé aux tables (lecture/écriture uniquement via RPC SECURITY DEFINER)

ALTER TABLE public.app_profils ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.app_donnees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.historique_modifications ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.app_profils FORCE ROW LEVEL SECURITY;
ALTER TABLE public.app_donnees FORCE ROW LEVEL SECURITY;
ALTER TABLE public.historique_modifications FORCE ROW LEVEL SECURITY;

-- Suppression d'éventuelles anciennes politiques permissives
DROP POLICY IF EXISTS "Acces bloque par defaut app_profils" ON public.app_profils;
DROP POLICY IF EXISTS "Acces bloque par defaut app_donnees" ON public.app_donnees;
DROP POLICY IF EXISTS "Acces bloque par defaut historique_modifications" ON public.historique_modifications;

-- Politiques restrictives explicites (aucun accès direct via l'API REST PostgREST sur les tables)
CREATE POLICY "Acces bloque par defaut app_profils"
    ON public.app_profils FOR ALL TO anon, authenticated USING (false) WITH CHECK (false);

CREATE POLICY "Acces bloque par defaut app_donnees"
    ON public.app_donnees FOR ALL TO anon, authenticated USING (false) WITH CHECK (false);

CREATE POLICY "Acces bloque par defaut historique_modifications"
    ON public.historique_modifications FOR ALL TO anon, authenticated USING (false) WITH CHECK (false);

-- Révocation des privilèges directs sur la colonne mot_de_passe_hash par sécurité en profondeur
REVOKE ALL ON public.app_profils FROM anon, authenticated;
REVOKE ALL ON public.app_donnees FROM anon, authenticated;
REVOKE ALL ON public.historique_modifications FROM anon, authenticated;

-- ============================================================================
-- 4. FONCTIONS RPC SÉCURISÉES (SECURITY DEFINER)
-- ============================================================================

-- 4.0 Fonction utilitaire publique : lister les profils actifs d'un établissement (sans exposer mot_de_passe_hash)
CREATE OR REPLACE FUNCTION public.lister_profils_publics(
    p_etablissement TEXT DEFAULT 'lfp-pekin'
)
RETURNS TABLE (
    id UUID,
    etablissement_id TEXT,
    nom_affiche TEXT,
    role TEXT,
    droits JSONB,
    actif BOOLEAN
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
    SELECT p.id, p.etablissement_id, p.nom_affiche, p.role, p.droits, p.actif
    FROM public.app_profils p
    WHERE p.etablissement_id = COALESCE(NULLIF(trim(p_etablissement), ''), 'lfp-pekin')
      AND p.actif = true
    ORDER BY
        CASE p.role
            WHEN 'coord' THEN 1
            WHEN 'eps' THEN 2
            WHEN 'primaire' THEN 3
            WHEN 'secr' THEN 4
            WHEN 'eleve' THEN 5
            ELSE 9
        END,
        p.nom_affiche;
$$;

-- 4.1 Vérifier la connexion d'un profil côté serveur (sans jamais exposer les hash de mots de passe)
-- p_profil_id accepte l'UUID du profil, son code de rôle (ex: 'coord') ou son nom_affiche
CREATE OR REPLACE FUNCTION public.verifier_connexion(
    p_etablissement TEXT,
    p_profil_id TEXT,
    p_mot_de_passe TEXT
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
    v_etab TEXT := COALESCE(NULLIF(trim(p_etablissement), ''), 'lfp-pekin');
    v_prof public.app_profils%ROWTYPE;
BEGIN
    SELECT *
    INTO v_prof
    FROM public.app_profils p
    WHERE p.etablissement_id = v_etab
      AND p.actif = true
      AND (
          p.id::text = trim(p_profil_id)
          OR lower(p.role) = lower(trim(p_profil_id))
          OR lower(p.nom_affiche) = lower(trim(p_profil_id))
      )
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'ok', false,
            'error', 'Profil introuvable ou inactif pour cet établissement.'
        );
    END IF;

    IF v_prof.mot_de_passe_hash IS NULL
       OR v_prof.mot_de_passe_hash <> crypt(COALESCE(p_mot_de_passe, ''), v_prof.mot_de_passe_hash) THEN
        RETURN jsonb_build_object(
            'ok', false,
            'error', 'Mot de passe incorrect.'
        );
    END IF;

    RETURN jsonb_build_object(
        'ok', true,
        'profil', jsonb_build_object(
            'id', v_prof.id,
            'etablissement_id', v_prof.etablissement_id,
            'nom_affiche', v_prof.nom_affiche,
            'role', v_prof.role,
            'droits', v_prof.droits,
            'actif', v_prof.actif
        )
    );
END;
$$;

-- 4.2 Gérer un profil (Création, Modification, Changement de mot de passe, Activation/Suppression)
-- Strictement réservé au Coordinateur (vérification du mot de passe admin côté serveur)
CREATE OR REPLACE FUNCTION public.gerer_profil(
    p_etablissement TEXT,
    p_admin_mot_de_passe TEXT,
    p_action TEXT,                     -- 'create' | 'update' | 'password' | 'delete'
    p_cible_id UUID DEFAULT NULL,
    p_nom_affiche TEXT DEFAULT NULL,
    p_role TEXT DEFAULT NULL,
    p_nouveau_mot_de_passe TEXT DEFAULT NULL,
    p_droits JSONB DEFAULT NULL,
    p_actif BOOLEAN DEFAULT true
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
    v_etab TEXT := COALESCE(NULLIF(trim(p_etablissement), ''), 'lfp-pekin');
    v_admin public.app_profils%ROWTYPE;
    v_cible public.app_profils%ROWTYPE;
    v_act TEXT := lower(trim(COALESCE(p_action, '')));
BEGIN
    -- 1. Authentification stricte du Coordinateur de l'établissement
    SELECT *
    INTO v_admin
    FROM public.app_profils p
    WHERE p.etablissement_id = v_etab
      AND p.actif = true
      AND ((p.droits->>'admin')::boolean = true OR p.role = 'coord')
      AND p.mot_de_passe_hash = crypt(COALESCE(p_admin_mot_de_passe, ''), p.mot_de_passe_hash)
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'ok', false,
            'error', 'Accès refusé : authentification Coordinateur EPS invalide.'
        );
    END IF;

    -- 2. Exécution de l'action demandée
    IF v_act = 'create' THEN
        IF NULLIF(trim(COALESCE(p_nom_affiche, '')), '') IS NULL
           OR NULLIF(trim(COALESCE(p_role, '')), '') IS NULL
           OR NULLIF(COALESCE(p_nouveau_mot_de_passe, ''), '') IS NULL THEN
            RETURN jsonb_build_object('ok', false, 'error', 'Nom, rôle et mot de passe sont obligatoires pour créer un profil.');
        END IF;

        INSERT INTO public.app_profils (etablissement_id, nom_affiche, role, mot_de_passe_hash, droits, actif)
        VALUES (
            v_etab,
            trim(p_nom_affiche),
            trim(p_role),
            crypt(p_nouveau_mot_de_passe, gen_salt('bf')),
            COALESCE(p_droits, '{}'::jsonb),
            COALESCE(p_actif, true)
        )
        RETURNING * INTO v_cible;

        INSERT INTO public.historique_modifications (etablissement_id, auteur_nom, auteur_role, action_resume, details_json)
        VALUES (
            v_etab,
            v_admin.nom_affiche,
            v_admin.role,
            'Création du profil ' || v_cible.nom_affiche,
            jsonb_build_object('profil_id', v_cible.id, 'role', v_cible.role, 'droits', v_cible.droits)
        );

    ELSIF v_act IN ('update', 'password') THEN
        IF p_cible_id IS NULL THEN
            RETURN jsonb_build_object('ok', false, 'error', 'Identifiant du profil cible requis.');
        END IF;

        UPDATE public.app_profils p
        SET
            nom_affiche = COALESCE(NULLIF(trim(p_nom_affiche), ''), p.nom_affiche),
            role = COALESCE(NULLIF(trim(p_role), ''), p.role),
            droits = COALESCE(p_droits, p.droits),
            actif = COALESCE(p_actif, p.actif),
            mot_de_passe_hash = CASE
                WHEN NULLIF(COALESCE(p_nouveau_mot_de_passe, ''), '') IS NOT NULL
                THEN crypt(p_nouveau_mot_de_passe, gen_salt('bf'))
                ELSE p.mot_de_passe_hash
            END,
            updated_at = now()
        WHERE p.id = p_cible_id
          AND p.etablissement_id = v_etab
        RETURNING * INTO v_cible;

        IF NOT FOUND THEN
            RETURN jsonb_build_object('ok', false, 'error', 'Profil cible introuvable dans cet établissement.');
        END IF;

        INSERT INTO public.historique_modifications (etablissement_id, auteur_nom, auteur_role, action_resume, details_json)
        VALUES (
            v_etab,
            v_admin.nom_affiche,
            v_admin.role,
            CASE WHEN v_act = 'password' THEN 'Changement du mot de passe de ' ELSE 'Mise à jour du profil ' END || v_cible.nom_affiche,
            jsonb_build_object('profil_id', v_cible.id, 'role', v_cible.role, 'actif', v_cible.actif, 'droits', v_cible.droits)
        );

    ELSIF v_act = 'delete' THEN
        IF p_cible_id IS NULL THEN
            RETURN jsonb_build_object('ok', false, 'error', 'Identifiant du profil à supprimer requis.');
        END IF;

        IF p_cible_id = v_admin.id THEN
            RETURN jsonb_build_object('ok', false, 'error', 'Impossible de supprimer votre propre profil Coordinateur actif.');
        END IF;

        DELETE FROM public.app_profils p
        WHERE p.id = p_cible_id
          AND p.etablissement_id = v_etab
        RETURNING * INTO v_cible;

        IF NOT FOUND THEN
            RETURN jsonb_build_object('ok', false, 'error', 'Profil introuvable dans cet établissement.');
        END IF;

        INSERT INTO public.historique_modifications (etablissement_id, auteur_nom, auteur_role, action_resume, details_json)
        VALUES (
            v_etab,
            v_admin.nom_affiche,
            v_admin.role,
            'Suppression du profil ' || v_cible.nom_affiche,
            jsonb_build_object('profil_id', v_cible.id, 'role', v_cible.role)
        );

    ELSE
        RETURN jsonb_build_object('ok', false, 'error', 'Action non reconnue (attendu: create, update, password, delete).');
    END IF;

    RETURN jsonb_build_object(
        'ok', true,
        'profil', jsonb_build_object(
            'id', v_cible.id,
            'etablissement_id', v_cible.etablissement_id,
            'nom_affiche', v_cible.nom_affiche,
            'role', v_cible.role,
            'droits', v_cible.droits,
            'actif', v_cible.actif,
            'updated_at', v_cible.updated_at
        )
    );
END;
$$;

-- 4.3 Enregistrer une modification de données et tracer automatiquement dans historique_modifications
CREATE OR REPLACE FUNCTION public.enregistrer_modification(
    p_etablissement TEXT,
    p_profil_id TEXT,
    p_mot_de_passe TEXT,
    p_cle TEXT,
    p_donnees JSONB,
    p_action_resume TEXT DEFAULT 'Mise à jour des données',
    p_details_json JSONB DEFAULT '{}'::jsonb,
    p_auteur_nom TEXT DEFAULT NULL,
    p_version TEXT DEFAULT '1.0.0'
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
    v_etab TEXT := COALESCE(NULLIF(trim(p_etablissement), ''), 'lfp-pekin');
    v_cle TEXT := COALESCE(NULLIF(trim(p_cle), ''), 'etat_global');
    v_prof public.app_profils%ROWTYPE;
    v_can_edit BOOLEAN := false;
    v_auteur TEXT;
    v_row public.app_donnees%ROWTYPE;
    v_hist_id BIGINT;
BEGIN
    -- 1. Vérifier le profil et son mot de passe
    SELECT *
    INTO v_prof
    FROM public.app_profils p
    WHERE p.etablissement_id = v_etab
      AND p.actif = true
      AND (
          p.id::text = trim(p_profil_id)
          OR lower(p.role) = lower(trim(p_profil_id))
          OR lower(p.nom_affiche) = lower(trim(p_profil_id))
      )
      AND p.mot_de_passe_hash = crypt(COALESCE(p_mot_de_passe, ''), p.mot_de_passe_hash)
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object(
            'ok', false,
            'error', 'Authentification invalide ou profil inactif.'
        );
    END IF;

    -- 2. Contrôler que le profil possède un droit d'écriture
    v_can_edit := COALESCE((v_prof.droits->>'admin')::boolean, false)
               OR COALESCE((v_prof.droits->>'edit_all')::boolean, false)
               OR COALESCE((v_prof.droits->>'edit_eps')::boolean, false)
               OR COALESCE((v_prof.droits->>'edit_primaire')::boolean, false);

    IF NOT v_can_edit THEN
        RETURN jsonb_build_object(
            'ok', false,
            'error', 'Droits insuffisants : ce profil est en lecture seule.'
        );
    END IF;

    v_auteur := COALESCE(NULLIF(trim(p_auteur_nom), ''), v_prof.nom_affiche);

    -- 3. Sauvegarder / fusionner les données dans app_donnees
    INSERT INTO public.app_donnees (
        etablissement_id,
        cle,
        donnees,
        version,
        updated_by_nom,
        updated_by_role,
        updated_at
    )
    VALUES (
        v_etab,
        v_cle,
        CASE
            WHEN v_cle = 'etat_global' THEN COALESCE(p_donnees, '{}'::jsonb)
            ELSE jsonb_build_object(v_cle, p_donnees)
        END,
        COALESCE(p_version, '1.0.0'),
        v_auteur,
        v_prof.role,
        now()
    )
    ON CONFLICT (etablissement_id, cle) DO UPDATE
    SET
        donnees = CASE
            WHEN v_cle = 'etat_global' AND jsonb_typeof(public.app_donnees.donnees) = 'object' AND jsonb_typeof(EXCLUDED.donnees) = 'object'
            THEN public.app_donnees.donnees || EXCLUDED.donnees
            ELSE EXCLUDED.donnees
        END,
        version = EXCLUDED.version,
        updated_by_nom = EXCLUDED.updated_by_nom,
        updated_by_role = EXCLUDED.updated_by_role,
        updated_at = now()
    RETURNING * INTO v_row;

    -- 4. Écrire automatiquement une ligne dans historique_modifications
    INSERT INTO public.historique_modifications (
        etablissement_id,
        auteur_nom,
        auteur_role,
        action_resume,
        details_json,
        created_at
    )
    VALUES (
        v_etab,
        v_auteur,
        v_prof.role,
        COALESCE(NULLIF(trim(p_action_resume), ''), 'Modification (' || v_cle || ')'),
        COALESCE(p_details_json, '{}'::jsonb) || jsonb_build_object('cle', v_cle, 'profil_id', v_prof.id),
        now()
    )
    RETURNING id INTO v_hist_id;

    RETURN jsonb_build_object(
        'ok', true,
        'etablissement_id', v_row.etablissement_id,
        'cle', v_row.cle,
        'updated_at', v_row.updated_at,
        'updated_by_nom', v_row.updated_by_nom,
        'updated_by_role', v_row.updated_by_role,
        'historique_id', v_hist_id
    );
END;
$$;

-- 4.4 Lecture sécurisée des données d'un établissement (après vérification du profil)
CREATE OR REPLACE FUNCTION public.charger_donnees(
    p_etablissement TEXT,
    p_profil_id TEXT,
    p_mot_de_passe TEXT,
    p_cle TEXT DEFAULT NULL
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
    v_etab TEXT := COALESCE(NULLIF(trim(p_etablissement), ''), 'lfp-pekin');
    v_prof public.app_profils%ROWTYPE;
    v_result JSONB;
BEGIN
    SELECT *
    INTO v_prof
    FROM public.app_profils p
    WHERE p.etablissement_id = v_etab
      AND p.actif = true
      AND (
          p.id::text = trim(p_profil_id)
          OR lower(p.role) = lower(trim(p_profil_id))
          OR lower(p.nom_affiche) = lower(trim(p_profil_id))
      )
      AND p.mot_de_passe_hash = crypt(COALESCE(p_mot_de_passe, ''), p.mot_de_passe_hash)
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Authentification invalide.');
    END IF;

    SELECT COALESCE(
        jsonb_object_agg(
            d.cle,
            jsonb_build_object(
                'donnees', d.donnees,
                'version', d.version,
                'updated_by_nom', d.updated_by_nom,
                'updated_by_role', d.updated_by_role,
                'updated_at', d.updated_at
            )
        ),
        '{}'::jsonb
    )
    INTO v_result
    FROM public.app_donnees d
    WHERE d.etablissement_id = v_etab
      AND (p_cle IS NULL OR d.cle = p_cle);

    RETURN jsonb_build_object(
        'ok', true,
        'etablissement_id', v_etab,
        'profil', jsonb_build_object(
            'id', v_prof.id,
            'nom_affiche', v_prof.nom_affiche,
            'role', v_prof.role,
            'droits', v_prof.droits
        ),
        'items', v_result
    );
END;
$$;

-- ============================================================================
-- 5. DROITS D'EXÉCUTION SUR LES FONCTIONS RPC
-- ============================================================================

GRANT EXECUTE ON FUNCTION public.lister_profils_publics(TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.verifier_connexion(TEXT, TEXT, TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.gerer_profil(TEXT, TEXT, TEXT, UUID, TEXT, TEXT, TEXT, JSONB, BOOLEAN) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.enregistrer_modification(TEXT, TEXT, TEXT, TEXT, JSONB, TEXT, JSONB, TEXT, TEXT) TO anon, authenticated;
GRANT EXECUTE ON FUNCTION public.charger_donnees(TEXT, TEXT, TEXT, TEXT) TO anon, authenticated;


-- ============================================================================
-- 4.5 lister_historique : journal des modifications (réservé au Coordinateur)
--     À exécuter seul si le reste du script est déjà installé.
-- ============================================================================
CREATE OR REPLACE FUNCTION public.lister_historique(
    p_etablissement TEXT,
    p_profil_id TEXT,
    p_mot_de_passe TEXT,
    p_limite INT DEFAULT 500
)
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, extensions
AS $$
DECLARE
    v_etab TEXT := COALESCE(NULLIF(trim(p_etablissement), ''), 'lfp-pekin');
    v_prof public.app_profils%ROWTYPE;
    v_items JSONB;
BEGIN
    SELECT *
    INTO v_prof
    FROM public.app_profils p
    WHERE p.etablissement_id = v_etab
      AND p.actif = true
      AND (
          p.id::text = trim(p_profil_id)
          OR lower(p.role) = lower(trim(p_profil_id))
          OR lower(p.nom_affiche) = lower(trim(p_profil_id))
      )
      AND (COALESCE((p.droits->>'admin')::boolean, false) = true OR p.role = 'coord')
      AND p.mot_de_passe_hash = crypt(COALESCE(p_mot_de_passe, ''), p.mot_de_passe_hash)
    LIMIT 1;

    IF NOT FOUND THEN
        RETURN jsonb_build_object('ok', false, 'error', 'Accès réservé au Coordinateur.');
    END IF;

    SELECT COALESCE(jsonb_agg(to_jsonb(h) ORDER BY h.created_at DESC), '[]'::jsonb)
    INTO v_items
    FROM (
        SELECT id, auteur_nom, auteur_role, action_resume, details_json, created_at
        FROM public.historique_modifications
        WHERE etablissement_id = v_etab
        ORDER BY created_at DESC
        LIMIT GREATEST(1, LEAST(COALESCE(p_limite, 500), 2000))
    ) h;

    RETURN jsonb_build_object('ok', true, 'items', v_items);
END;
$$;

GRANT EXECUTE ON FUNCTION public.lister_historique(TEXT, TEXT, TEXT, INT) TO anon, authenticated;
