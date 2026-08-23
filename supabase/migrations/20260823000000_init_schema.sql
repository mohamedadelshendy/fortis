-- Step 1: Database Schema & Security for Secure File Encryption App

-- Create the table to store encrypted file metadata and KeyShare_B
CREATE TABLE public.encrypted_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_email TEXT NOT NULL,
    key_share_b TEXT NOT NULL, -- Stored as Base64 encoded string
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create the table to store OTP hashes for Multi-Factor Authentication
CREATE TABLE public.file_otps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES public.encrypted_files(id) ON DELETE CASCADE,
    otp_hash TEXT NOT NULL, -- SHA-256 hash of the 6-digit OTP
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INT DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security (RLS) on both tables
ALTER TABLE public.encrypted_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.file_otps ENABLE ROW LEVEL SECURITY;

-- Note on Security Policies:
-- We intentionally DO NOT create any RLS policies for `public` or `authenticated` roles.
-- By default, PostgreSQL blocks all SELECT, INSERT, UPDATE, and DELETE operations 
-- for tables with RLS enabled unless a policy explicitly allows it.
-- This ensures that NO ONE (not even authenticated users) can directly read the `key_share_b` column.
-- Our Edge Functions will use the Supabase Service Role key, which automatically bypasses RLS,
-- allowing them to securely interact with this data on behalf of the user after OTP verification.
