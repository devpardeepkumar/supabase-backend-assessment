-- Enable uuid-ossp for uuid_generate_v4()
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
-- Enable pgcrypto for password hashing (used in seed.sql and general security)
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Create profiles table
CREATE TABLE public.profiles (
    id uuid REFERENCES auth.users (id) ON DELETE CASCADE PRIMARY KEY,
    full_name text,
    avatar_url text,
    updated_at timestamptz DEFAULT now()
);

-- Secure the profiles table with RLS. Policies will be added later.
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

-- Create organisations table
CREATE TABLE public.organisations (
    id uuid DEFAULT uuid_generate_v4() PRIMARY KEY,
    name text NOT NULL,
    status text DEFAULT 'active' NOT NULL, -- e.g., 'active', 'inactive', 'suspended'
    created_at timestamptz DEFAULT now() NOT NULL,
    owner_id uuid REFERENCES public.profiles (id) ON DELETE RESTRICT
);

-- Secure the organisations table with RLS. Policies will be added later.
ALTER TABLE public.organisations ENABLE ROW LEVEL SECURITY;

-- Set up Row Level Security (RLS) policies for profiles and organisations
-- These are basic policies to allow initial setup. More refined policies will be added later.

-- Allow authenticated users to view their own profile
CREATE POLICY "Users can view their own profile."
ON public.profiles FOR SELECT
USING (auth.uid() = id);

-- Allow authenticated users to update their own profile
CREATE POLICY "Users can update their own profile."
ON public.profiles FOR UPDATE
USING (auth.uid() = id);

-- Allow organisation owner to view, insert, update, delete their own organisation
CREATE POLICY "Organisation owners can manage their organisation."
ON public.organisations FOR ALL
USING (auth.uid() = (SELECT id FROM public.profiles WHERE id = owner_id));

-- Optionally, you might want to create a trigger to update 'updated_at' automatically
CREATE OR REPLACE FUNCTION public.handle_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER on_profiles_updated_at
BEFORE UPDATE ON public.profiles
FOR EACH ROW EXECUTE FUNCTION public.handle_updated_at();
