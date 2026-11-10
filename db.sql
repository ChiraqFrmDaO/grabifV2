-- Users table for multi-tenancy
CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT UNIQUE NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',
  invite_token TEXT UNIQUE,
  api_token TEXT UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Trackers table with extended features
CREATE TABLE trackers (
  tracker_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  destination_url TEXT NOT NULL,
  management_key TEXT UNIQUE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  
  -- Webhook configurations
  discord_webhook TEXT,
  telegram_webhook TEXT,
  custom_webhook TEXT,
  
  -- Bot filtering settings
  filter_bots BOOLEAN DEFAULT true,
  filter_search_engines BOOLEAN DEFAULT true,
  filter_social_media BOOLEAN DEFAULT true,
  
  -- Alternative domain settings
  alternative_domain TEXT,
  
  -- Custom landing page
  custom_landing_page TEXT,
  
  -- Tracker status
  is_active BOOLEAN DEFAULT true,
  
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Logs table with extended telemetry
CREATE TABLE logs (
  id SERIAL PRIMARY KEY,
  tracker_id TEXT NOT NULL REFERENCES trackers(tracker_id) ON DELETE CASCADE,
  tracker_name TEXT,
  timestamp TIMESTAMPTZ NOT NULL DEFAULT now(),
  
  -- Network data
  ip TEXT,
  country TEXT,
  city TEXT,
  region TEXT,
  zip_code TEXT,
  isp TEXT,
  asn TEXT,
  latitude NUMERIC,
  longitude NUMERIC,
  
  -- Device/browser data
  browser TEXT,
  os TEXT,
  device TEXT,
  useragent TEXT,
  referer TEXT,
  screen_resolution TEXT,
  color_depth TEXT,
  
  -- Security flags
  is_vpn BOOLEAN,
  is_proxy BOOLEAN,
  is_tor BOOLEAN,
  is_datacenter BOOLEAN,
  
  -- Pixel flag
  is_pixel BOOLEAN DEFAULT false
);

-- Create indexes for performance
CREATE INDEX idx_logs_tracker_id ON logs(tracker_id);
CREATE INDEX idx_logs_timestamp ON logs(timestamp DESC);
CREATE INDEX idx_logs_ip ON logs(ip);
CREATE INDEX idx_trackers_user_id ON trackers(user_id);