#!/bin/bash

echo "[*] Starting secure store setup..."

# Generate random DB credentials and admin password
DB_USER="store_user"
DB_PASS=$(openssl rand -hex 16)
ADMIN_PASS=$(openssl rand -hex 12)
CONFIG_FILE="/var/www/store_app/config.ini"
SCHEMA_SQL="/var/www/store_app/db/schema.sql"

# Prompt for MySQL root password
echo "[?] Enter MySQL root password (for setup):"
read -s MYSQL_ROOT_PASS

# Recreate database and user
mysql -u root -p$MYSQL_ROOT_PASS <<EOF
DROP DATABASE IF EXISTS sql_onion;
DROP USER IF EXISTS '$DB_USER'@'localhost';
CREATE DATABASE sql_onion CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER '$DB_USER'@'localhost' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON sql_onion.* TO '$DB_USER'@'localhost';
FLUSH PRIVILEGES;
EOF

echo "[+] MySQL database and user created."

# Generate config.ini
cat <<EOL > $CONFIG_FILE
[database]
host = localhost
user = $DB_USER
password = $DB_PASS
database = sql_onion

[admin]
username = admin
password = $ADMIN_PASS
EOL

echo "[+] config.ini created."

# Import database schema
mysql -u $DB_USER -p$DB_PASS sql_onion < $SCHEMA_SQL
echo "[+] Database schema imported."

# Regenerate .onion address if needed (optional)
echo "[*] Checking .onion address..."
ONION_PATH="/var/lib/tor/store_hidden_service/hostname"
if [ -f "$ONION_PATH" ]; then
    ONION_ADDR=$(cat $ONION_PATH)
    echo "[+] Onion address: $ONION_ADDR"
else
    echo "[!] Onion address not found. Make sure Tor is configured."
fi

# Set file permissions
chown -R www-data:www-data /var/www/store_app
chmod -R 755 /var/www/store_app

# Restart services
systemctl restart apache2
systemctl restart tor

# Show credentials
echo ""
echo "✅ Installation complete!"
echo "🔐 Admin username: admin"
echo "🔐 Admin password: $ADMIN_PASS"
echo "🛢️  MySQL user: $DB_USER"
echo "🛢️  MySQL password: $DB_PASS"
echo "🌐 Onion address: $ONION_ADDR"
