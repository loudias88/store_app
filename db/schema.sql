-- db/schema.sql

CREATE TABLE IF NOT EXISTS store_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    color_theme VARCHAR(50) NOT NULL,
    logo_path VARCHAR(255) DEFAULT '',
    pgp_key TEXT DEFAULT '',
    btc_address VARCHAR(255) DEFAULT '',
    xmr_address VARCHAR(255) DEFAULT '',
    contact_email VARCHAR(255) DEFAULT '',
    onion_url VARCHAR(255) DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admin_user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(255) NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    image_path VARCHAR(255) DEFAULT '',
    price_usd DECIMAL(10, 2) NOT NULL
);

CREATE TABLE IF NOT EXISTS shipping_addresses (
    id INT AUTO_INCREMENT PRIMARY KEY,
    country VARCHAR(100) NOT NULL,
    region VARCHAR(100) NOT NULL,
    price_usd DECIMAL(10, 2) NOT NULL
);