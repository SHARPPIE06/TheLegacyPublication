-- The Legacy Publication (URS Morong) — Supabase Postgres + RLS + Trigger + Realtime
CREATE TABLE IF NOT EXISTS profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  email TEXT NOT NULL,
  role TEXT CHECK (role IN ('EIC','Associate Editor','Section Editor','Writer','Photojournalist','MoJo / Broadcaster','Layout / Cartoonist','Copyreader','Student')) DEFAULT 'Student',
  approval_status TEXT CHECK (approval_status IN ('pending','approved','rejected')) DEFAULT 'approved',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS issues (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  format TEXT CHECK (format IN ('Tabloid','Literary Folio','Magazine')),
  is_published BOOLEAN DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS pieces (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  issue_id UUID REFERENCES issues(id) ON DELETE CASCADE,
  section TEXT NOT NULL,
  title TEXT NOT NULL,
  wu_done BOOLEAN DEFAULT FALSE,
  art_done BOOLEAN DEFAULT FALSE,
  copy_done BOOLEAN DEFAULT FALSE,
  wu_file_url TEXT,
  art_file_url TEXT,
  author_id UUID REFERENCES profiles(id)
);

CREATE TABLE IF NOT EXISTS publications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  category TEXT NOT NULL,
  title TEXT NOT NULL,
  excerpt TEXT,
  body JSONB DEFAULT '[]'::jsonb,
  photos JSONB DEFAULT '[]'::jsonb,
  author_id UUID REFERENCES profiles(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS campus_visits (
  campus TEXT PRIMARY KEY,
  visits INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS app_settings (
  id TEXT PRIMARY KEY DEFAULT 'main',
  latest_version TEXT DEFAULT '1.2.0',
  apk_download_url TEXT
);

ALTER TABLE pieces ADD COLUMN IF NOT EXISTS author_id UUID REFERENCES profiles(id);
ALTER TABLE publications ADD COLUMN IF NOT EXISTS media_src TEXT;
ALTER TABLE publications ADD COLUMN IF NOT EXISTS media_type TEXT;
ALTER TABLE publications ADD COLUMN IF NOT EXISTS media_url TEXT;

-- Security-definer helpers (prevents RLS recursion)
CREATE OR REPLACE FUNCTION public.is_eic()
RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(auth.jwt()->>'email' = 'legacy.eic@gmail.com', FALSE)
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND role = 'EIC' AND approval_status = 'approved');
$$;

CREATE OR REPLACE FUNCTION public.is_approved_staff()
RETURNS BOOLEAN LANGUAGE sql SECURITY DEFINER SET search_path = public AS $$
  SELECT COALESCE(auth.jwt()->>'email' = 'legacy.eic@gmail.com', FALSE)
    OR EXISTS (SELECT 1 FROM public.profiles WHERE id = auth.uid() AND approval_status = 'approved' AND role <> 'Student');
$$;

-- Auto-create profile row on signUp (works even when email confirmation is ON)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  INSERT INTO public.profiles (id, full_name, email, role, approval_status)
  VALUES (
    NEW.id,
    COALESCE(NEW.raw_user_meta_data->>'full_name', split_part(NEW.email, '@', 1)),
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'role', CASE WHEN NEW.email = 'legacy.eic@gmail.com' THEN 'EIC' ELSE 'Writer' END),
    CASE WHEN NEW.email = 'legacy.eic@gmail.com' THEN 'approved' ELSE 'approved' END
  )
  ON CONFLICT (id) DO NOTHING;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE issues ENABLE ROW LEVEL SECURITY;
ALTER TABLE pieces ENABLE ROW LEVEL SECURITY;
ALTER TABLE publications ENABLE ROW LEVEL SECURITY;
ALTER TABLE campus_visits ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Public reads published issues" ON issues;
CREATE POLICY "Public reads published issues" ON issues FOR SELECT USING (is_published = TRUE);
DROP POLICY IF EXISTS "EIC manages issues" ON issues;
CREATE POLICY "EIC manages issues" ON issues FOR ALL USING (public.is_eic());

DROP POLICY IF EXISTS "Staff read pieces" ON pieces;
CREATE POLICY "Staff read pieces" ON pieces FOR SELECT USING (public.is_approved_staff());
DROP POLICY IF EXISTS "Writers edit own drafts" ON pieces;
CREATE POLICY "Writers edit own drafts" ON pieces FOR UPDATE USING (author_id = auth.uid());
DROP POLICY IF EXISTS "Editors & EIC manage all pieces" ON pieces;
CREATE POLICY "Editors & EIC manage all pieces" ON pieces FOR ALL USING (public.is_approved_staff());

DROP POLICY IF EXISTS "Anyone can read publications" ON publications;
CREATE POLICY "Anyone can read publications" ON publications FOR SELECT USING (TRUE);
DROP POLICY IF EXISTS "Approved staff publish" ON publications;
CREATE POLICY "Approved staff publish" ON publications FOR INSERT WITH CHECK (public.is_approved_staff());
DROP POLICY IF EXISTS "Approved staff edit or delete" ON publications;
CREATE POLICY "Approved staff edit or delete" ON publications FOR ALL USING (public.is_approved_staff());

DROP POLICY IF EXISTS "Users insert own profile" ON profiles;
CREATE POLICY "Users insert own profile" ON profiles FOR INSERT WITH CHECK (auth.uid() = id);
DROP POLICY IF EXISTS "Users read own profile" ON profiles;
CREATE POLICY "Users read own profile" ON profiles FOR SELECT USING (auth.uid() = id);
DROP POLICY IF EXISTS "EIC manages all profiles" ON profiles;
CREATE POLICY "EIC manages all profiles" ON profiles FOR ALL USING (public.is_eic());

DROP POLICY IF EXISTS "Anyone reads campus visits" ON campus_visits;
CREATE POLICY "Anyone reads campus visits" ON campus_visits FOR SELECT USING (TRUE);
DROP POLICY IF EXISTS "Anyone logs campus visit" ON campus_visits;
CREATE POLICY "Anyone logs campus visit" ON campus_visits FOR ALL USING (TRUE);

CREATE OR REPLACE FUNCTION increment_campus_visit(p_campus TEXT)
RETURNS VOID LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
  INSERT INTO campus_visits (campus, visits) VALUES (p_campus, 1)
  ON CONFLICT (campus) DO UPDATE SET visits = campus_visits.visits + 1;
END;
$$;

-- Enable Realtime on profiles, publications, campus_visits
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE profiles;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE publications;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
DO $$
BEGIN
  ALTER PUBLICATION supabase_realtime ADD TABLE campus_visits;
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
-- EIC Temporary Password Reset Trigger (hashes temp_password into auth.users and clears plaintext)
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE public.profiles ADD COLUMN IF NOT EXISTS temp_password TEXT;

CREATE OR REPLACE FUNCTION public.apply_temp_password()
RETURNS TRIGGER LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, extensions AS $$
BEGIN
  IF NEW.temp_password IS NOT NULL AND length(btrim(NEW.temp_password)) >= 6 THEN
    UPDATE auth.users
    SET encrypted_password = crypt(NEW.temp_password, gen_salt('bf')),
        updated_at = NOW()
    WHERE id = NEW.id;
    NEW.temp_password := NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS on_profile_temp_password ON public.profiles;
CREATE TRIGGER on_profile_temp_password
  BEFORE INSERT OR UPDATE OF temp_password ON public.profiles
  FOR EACH ROW
  WHEN (NEW.temp_password IS NOT NULL AND length(btrim(NEW.temp_password)) >= 6)
  EXECUTE FUNCTION public.apply_temp_password();
