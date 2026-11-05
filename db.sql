CREATE TABLE logs (
  id SERIAL PRIMARY KEY,
  tracker_id VARCHAR(50) NOT NULL,
  ip VARCHAR(45) NOT NULL,
  country VARCHAR(100),
  city VARCHAR(100),
  isp VARCHAR(255),
  browser VARCHAR(100),
  os VARCHAR(100),
  device VARCHAR(50),
  useragent TEXT,
  referer TEXT,
  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);