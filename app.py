# app.py
import os
import re
import bcrypt
import secrets
import pymysql
import configparser
from jinja2 import Environment, FileSystemLoader
from urllib.parse import parse_qs
from http.cookies import SimpleCookie
from datetime import datetime, timedelta

# -----------------------------------------------------------------------------
# CONFIG LOADING
# -----------------------------------------------------------------------------
config = configparser.ConfigParser()
config.read(os.path.join(os.path.dirname(__file__), 'config.ini'))

DB_HOST = config.get('database', 'host')
DB_USER = config.get('database', 'user')
DB_PASS = config.get('database', 'password')
DB_NAME = config.get('database', 'name')

ADMIN_USERNAME = config.get('admin', 'username')
ADMIN_PASSHASH = config.get('admin', 'password_hash')

SECRET_KEY      = config.get('general', 'secret_key')
ONION_URL       = config.get('general', 'onion_url', fallback='')

UPLOAD_FOLDER   = config.get('paths', 'upload_folder')
LOGO_FOLDER     = config.get('paths', 'logo_folder')

# -----------------------------------------------------------------------------
# JINJA2 SETUP
# -----------------------------------------------------------------------------
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), 'templates')
env = Environment(loader=FileSystemLoader(TEMPLATE_PATH))

# -----------------------------------------------------------------------------
# DATABASE HELPER
# -----------------------------------------------------------------------------
def get_db():
    return pymysql.connect(
        host=DB_HOST, 
        user=DB_USER, 
        password=DB_PASS, 
        database=DB_NAME, 
        charset='utf8mb4'
    )

# -----------------------------------------------------------------------------
# SIMPLE SESSION MANAGEMENT
# -----------------------------------------------------------------------------
sessions = {}

def generate_session_id():
    return secrets.token_hex(16)

def get_session_id(environ):
    """Extract the session ID from cookies (if present)."""
    cookies = SimpleCookie(environ.get('HTTP_COOKIE', ''))
    session_cookie = cookies.get('SESSION_ID')
    return session_cookie.value if session_cookie else None

def set_session_cookie(start_response, session_id):
    """Set the session ID in a cookie (HttpOnly, 1 day expiration)."""
    expires = (datetime.utcnow() + timedelta(days=1)).strftime("%a, %d-%b-%Y %H:%M:%S GMT")
    cookie_string = f"SESSION_ID={session_id}; Path=/; Expires={expires}; HttpOnly"
    start_response('200 OK', [('Content-type','text/html; charset=utf-8'), ('Set-Cookie', cookie_string)])

def is_admin_logged_in(session_id):
    """Check if the given session belongs to an admin user."""
    return session_id in sessions and sessions[session_id].get('admin_logged_in', False)

# -----------------------------------------------------------------------------
# RENDER + RESPONSES
# -----------------------------------------------------------------------------
def render_template(template_name, **context):
    template = env.get_template(template_name)
    return template.render(**context)

def redirect(location, start_response):
    start_response('302 Found', [('Location', location)])
    return [b'']

def not_found(start_response):
    start_response('404 Not Found', [('Content-Type', 'text/plain')])
    return [b'404 Not Found']

# -----------------------------------------------------------------------------
# PUBLIC ROUTES
# -----------------------------------------------------------------------------
def index(environ, start_response):
    """Homepage: list all products."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT title, color_theme, logo_path, onion_url FROM store_settings LIMIT 1")
            settings = cur.fetchone()
            if settings:
                store_title, color_theme, logo_path, onion_url = settings
            else:
                store_title, color_theme, logo_path, onion_url = "My Store", "theme_default", "", ""

            cur.execute("SELECT id, name, description, image_path, price_usd FROM products")
            products = cur.fetchall()
    finally:
        db.close()

    html = render_template("index.html",
        store_title=store_title,
        color_theme=color_theme,
        logo_path=logo_path,
        onion_url=onion_url,
        products=products
    )

    start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
    return [html.encode('utf-8')]

def product_detail(environ, start_response, product_id):
    """Show details of a single product, with a dynamic shipping dropdown."""
    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT title, color_theme, logo_path, onion_url FROM store_settings LIMIT 1")
            settings = cur.fetchone()
            if settings:
                store_title, color_theme, logo_path, onion_url = settings
            else:
                store_title, color_theme, logo_path, onion_url = "My Store", "theme_default", "", ""

            cur.execute("SELECT id, name, description, image_path, price_usd FROM products WHERE id = %s", (product_id,))
            product = cur.fetchone()

            cur.execute("SELECT id, country, region, price_usd FROM shipping_addresses")
            shipping_options = cur.fetchall()
    finally:
        db.close()

    if not product:
        return not_found(start_response)

    html = render_template("product_detail.html",
        store_title=store_title,
        color_theme=color_theme,
        logo_path=logo_path,
        onion_url=onion_url,
        product=product,
        shipping_options=shipping_options
    )
    start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
    return [html.encode('utf-8')]

def checkout(environ, start_response):
    """Process checkout form and display payment instructions."""
    if environ['REQUEST_METHOD'] == 'POST':
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')
        post_data = parse_qs(request_body)

        product_id  = post_data.get('product_id', [''])[0]
        quantity    = post_data.get('quantity', ['1'])[0]
        shipping_id = post_data.get('shipping_id', [''])[0]

        db = get_db()
        try:
            with db.cursor() as cur:
                cur.execute("""
                    SELECT title, color_theme, logo_path, pgp_key,
                           btc_address, xmr_address, onion_url
                    FROM store_settings LIMIT 1
                """)
                settings = cur.fetchone()
                if settings:
                    store_title, color_theme, logo_path, pgp_key, btc_addr, xmr_addr, onion_url = settings
                else:
                    store_title, color_theme, logo_path, pgp_key, btc_addr, xmr_addr, onion_url = (
                        "My Store", "theme_default", "", "", "", "", ""
                    )

                cur.execute("SELECT id, name, price_usd FROM products WHERE id = %s", (product_id,))
                product = cur.fetchone()

                cur.execute("SELECT id, country, region, price_usd FROM shipping_addresses WHERE id = %s", (shipping_id,))
                shipping = cur.fetchone()
        finally:
            db.close()

        if not product or not shipping:
            return not_found(start_response)

        # Calculate totals
        qty = int(quantity)
        product_total  = float(product[2]) * qty
        shipping_total = float(shipping[3])
        total_usd      = product_total + shipping_total

        # Example offline crypto rates (should be updated manually via DB or JSON)
        btc_rate = 27000.0
        xmr_rate = 150.0
        btc_amount = total_usd / btc_rate
        xmr_amount = total_usd / xmr_rate

        html = render_template("checkout.html",
            store_title=store_title,
            color_theme=color_theme,
            logo_path=logo_path,
            onion_url=onion_url,
            pgp_key=pgp_key,
            product=product,
            shipping=shipping,
            quantity=qty,
            total_usd=total_usd,
            btc_address=btc_addr,
            xmr_address=xmr_addr,
            btc_amount=btc_amount,
            xmr_amount=xmr_amount
        )
        start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
        return [html.encode('utf-8')]
    else:
        return not_found(start_response)

# -----------------------------------------------------------------------------
# ADMIN ROUTES
# -----------------------------------------------------------------------------
def admin_login(environ, start_response):
    """Admin login page."""
    if environ['REQUEST_METHOD'] == 'POST':
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')
        post_data = parse_qs(request_body)

        username = post_data.get('username', [''])[0]
        password = post_data.get('password', [''])[0]

        if username == ADMIN_USERNAME and bcrypt.checkpw(password.encode('utf-8'), ADMIN_PASSHASH.encode('utf-8')):
            session_id = generate_session_id()
            sessions[session_id] = {'admin_logged_in': True}
            set_session_cookie(start_response, session_id)
            return redirect('/admin', start_response)
        else:
            html = render_template('admin_login.html', error="Invalid credentials.")
            start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
            return [html.encode('utf-8')]
    else:
        html = render_template('admin_login.html', error=None)
        start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
        return [html.encode('utf-8')]

def admin_logout(environ, start_response):
    """Admin logout."""
    session_id = get_session_id(environ)
    if session_id and session_id in sessions:
        del sessions[session_id]
    return redirect('/', start_response)

def admin_dashboard(environ, start_response):
    """Admin dashboard home."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT title, color_theme, logo_path, onion_url FROM store_settings LIMIT 1")
            settings = cur.fetchone()
            if settings:
                store_title, color_theme, logo_path, onion_url = settings
            else:
                store_title, color_theme, logo_path, onion_url = "My Store", "theme_default", "", ""
    finally:
        db.close()

    html = render_template("admin_panel.html",
        store_title=store_title,
        color_theme=color_theme,
        logo_path=logo_path,
        onion_url=onion_url
    )
    start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
    return [html.encode('utf-8')]

def admin_settings(environ, start_response):
    """Admin page to manage store settings."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    if environ['REQUEST_METHOD'] == 'POST':
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')
        post_data = parse_qs(request_body)

        new_title       = post_data.get('store_title',       ['My Store'])[0]
        new_theme       = post_data.get('color_theme',       ['theme_default'])[0]
        new_pgp         = post_data.get('pgp_key',           [''])[0]
        new_btc_address = post_data.get('btc_address',       [''])[0]
        new_xmr_address = post_data.get('xmr_address',       [''])[0]
        new_contact     = post_data.get('contact_email',     [''])[0]
        new_onion_url   = post_data.get('onion_url',         [''])[0]

        with db.cursor() as cur:
            cur.execute("SELECT id FROM store_settings LIMIT 1")
            existing = cur.fetchone()
            if existing:
                cur.execute("""
                    UPDATE store_settings
                    SET title=%s, color_theme=%s, pgp_key=%s,
                        btc_address=%s, xmr_address=%s, contact_email=%s,
                        onion_url=%s
                    WHERE id=%s
                """, (
                    new_title, new_theme, new_pgp,
                    new_btc_address, new_xmr_address, new_contact,
                    new_onion_url,
                    existing[0]
                ))
            else:
                cur.execute("""
                    INSERT INTO store_settings
                    (title, color_theme, pgp_key, btc_address, xmr_address, contact_email, onion_url)
                    VALUES (%s,%s,%s,%s,%s,%s,%s)
                """, (
                    new_title, new_theme, new_pgp,
                    new_btc_address, new_xmr_address, new_contact, new_onion_url
                ))
            db.commit()

    try:
        with db.cursor() as cur:
            cur.execute("""
                SELECT title, color_theme, pgp_key, btc_address, xmr_address,
                       contact_email, onion_url
                FROM store_settings
                LIMIT 1
            """)
            row = cur.fetchone()
            if row:
                (store_title, color_theme, pgp_key,
                 btc_addr, xmr_addr, contact_email, onion_url) = row
            else:
                (store_title, color_theme, pgp_key,
                 btc_addr, xmr_addr, contact_email, onion_url) = (
                    "My Store", "theme_default", "", "", "", "", ""
                )
    finally:
        db.close()

    html = render_template("admin_settings.html",
        store_title=store_title,
        color_theme=color_theme,
        pgp_key=pgp_key,
        btc_address=btc_addr,
        xmr_address=xmr_addr,
        contact_email=contact_email,
        onion_url=onion_url
    )
    start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
    return [html.encode('utf-8')]

def admin_products(environ, start_response):
    """Admin page to list and manage products."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id, name, price_usd FROM products")
            product_list = cur.fetchall()
    finally:
        db.close()

    html = render_template("admin_products.html", products=product_list)
    start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
    return [html.encode('utf-8')]

def admin_edit_product(environ, start_response, product_id=None):
    """Admin page to create or edit a product."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    if environ['REQUEST_METHOD'] == 'POST':
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')
        post_data = parse_qs(request_body)

        name        = post_data.get('name', [''])[0]
        description = post_data.get('description', [''])[0]
        price_usd   = post_data.get('price_usd', ['0'])[0]

        if product_id:
            with db.cursor() as cur:
                cur.execute("""
                    UPDATE products
                    SET name=%s, description=%s, price_usd=%s
                    WHERE id=%s
                """, (name, description, price_usd, product_id))
            db.commit()
        else:
            with db.cursor() as cur:
                cur.execute("""
                    INSERT INTO products (name, description, price_usd)
                    VALUES (%s, %s, %s)
                """, (name, description, price_usd))
            db.commit()

        return redirect('/admin/products', start_response)
    else:
        product = None
        if product_id:
            with db.cursor() as cur:
                cur.execute("SELECT id, name, description, price_usd FROM products WHERE id=%s", (product_id,))
                product = cur.fetchone()

        html = render_template("admin_edit_product.html", product=product)
        start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
        return [html.encode('utf-8')]

def admin_delete_product(environ, start_response, product_id):
    """Admin action to delete a product."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM products WHERE id=%s", (product_id,))
        db.commit()
    finally:
        db.close()

    return redirect('/admin/products', start_response)

def admin_shipping(environ, start_response):
    """Admin page to create, list, and delete shipping options."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    if environ['REQUEST_METHOD'] == 'POST':
        # Insert new shipping option
        try:
            request_body_size = int(environ.get('CONTENT_LENGTH', 0))
        except:
            request_body_size = 0
        request_body = environ['wsgi.input'].read(request_body_size).decode('utf-8')
        post_data = parse_qs(request_body)

        country = post_data.get('country', [''])[0]
        region  = post_data.get('region', [''])[0]
        price   = post_data.get('price_usd', ['0'])[0]

        with db.cursor() as cur:
            cur.execute("""
                INSERT INTO shipping_addresses (country, region, price_usd)
                VALUES (%s, %s, %s)
            """, (country, region, price))
        db.commit()

    # List existing shipping options
    try:
        with db.cursor() as cur:
            cur.execute("SELECT id, country, region, price_usd FROM shipping_addresses")
            shipping_list = cur.fetchall()
    finally:
        db.close()

    html = render_template("admin_shipping.html", shipping_list=shipping_list)
    start_response('200 OK', [('Content-Type','text/html; charset=utf-8')])
    return [html.encode('utf-8')]

def admin_delete_shipping(environ, start_response, shipping_id):
    """Admin action to delete a shipping option."""
    session_id = get_session_id(environ)
    if not is_admin_logged_in(session_id):
        return redirect('/admin/login', start_response)

    db = get_db()
    try:
        with db.cursor() as cur:
            cur.execute("DELETE FROM shipping_addresses WHERE id=%s", (shipping_id,))
        db.commit()
    finally:
        db.close()

    return redirect('/admin/shipping', start_response)

# -----------------------------------------------------------------------------
# DISPATCH / ROUTER
# -----------------------------------------------------------------------------
def application(environ, start_response):
    path = environ['PATH_INFO']
    method = environ['REQUEST_METHOD']

    # Public routes
    if path == '/':
        return index(environ, start_response)
    if path.startswith('/product/'):
        match = re.match(r'^/product/(\d+)$', path)
        if match:
            product_id = match.group(1)
            return product_detail(environ, start_response, product_id)
        else:
            return not_found(start_response)
    if path == '/checkout':
        return checkout(environ, start_response)

    # Admin routes
    if path == '/admin':
        return admin_dashboard(environ, start_response)
    if path == '/admin/login':
        return admin_login(environ, start_response)
    if path == '/admin/logout':
        return admin_logout(environ, start_response)
    if path == '/admin/settings':
        return admin_settings(environ, start_response)
    if path == '/admin/products':
        return admin_products(environ, start_response)
    if path.startswith('/admin/product/edit'):
        # /admin/product/edit/123
        match = re.match(r'^/admin/product/edit/(\d+)$', path)
        if match:
            product_id = match.group(1)
            return admin_edit_product(environ, start_response, product_id)
        else:
            # No ID means create new
            return admin_edit_product(environ, start_response, None)
    if path.startswith('/admin/product/delete'):
        match = re.match(r'^/admin/product/delete/(\d+)$', path)
        if match:
            product_id = match.group(1)
            return admin_delete_product(environ, start_response, product_id)
        else:
            return not_found(start_response)
    if path == '/admin/shipping':
        return admin_shipping(environ, start_response)
    if path.startswith('/admin/shipping/delete/'):
        match = re.match(r'^/admin/shipping/delete/(\d+)$', path)
        if match:
            shipping_id = match.group(1)
            return admin_delete_shipping(environ, start_response, shipping_id)
        else:
            return not_found(start_response)

    return not_found(start_response)

app = application