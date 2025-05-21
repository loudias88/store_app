; config.ini
; Este arquivo será sobrescrito pelo install.sh
; Ajuste manualmente se quiser parâmetros fixos

[database]
host = localhost
user = db_user
password = db_password
name = db_name

[admin]
username = admin
password_hash = <hash gerado>

[general]
secret_key = RANDOM_GENERATED_KEY

[paths]
upload_folder = static/uploads
logo_folder = static/uploads
