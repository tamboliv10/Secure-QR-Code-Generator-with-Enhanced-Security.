from flask import Flask, render_template, request, redirect, url_for, session
import qrcode
import os
import sqlite3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from io import BytesIO
import base64

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# SQLite database setup
conn = sqlite3.connect('db.sqlite')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS qr_codes (
        id INTEGER PRIMARY KEY,
        data TEXT,
        salt BLOB,
        qr_code BLOB
    )
''')

conn.commit()
conn.close()

# Fixed key for demonstration purposes (128 bits or 16 bytes)
fixed_key = b'ThisIsAFixedKey'

sbox = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
]

# Encryption function using S-box
def encrypt(pt, key):
    cipher_text = ''
    for char in pt:
        row = int(char[0], 16)
        col = int(char[1], 16)
        cipher_text += format(sbox[row][col], 'x')
    return cipher_text

@app.route('/')
def home():
    return render_template('input.html')

@app.route('/generate_qr_code', methods=['POST'])
def generate_qr_code():
    data = request.form['data']

    # Encrypt the data using the fixed key and S-box
    encrypted_data = encrypt(data, fixed_key)

    # Store the QR code and salt in the database
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO qr_codes (data, qr_code) VALUES (?, ?)',
                   (encrypted_data, fixed_key))
    conn.commit()
    conn.close()

    # Generate a QR code for the fixed key
    secret_key_qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=20,
        border=4,
    )
    secret_key_qr.add_data(base64.b64encode(fixed_key).decode())
    secret_key_qr.make(fit=True)

    img = secret_key_qr.make_image(fill_color="black", back_color="white")

    # Convert the fixed key QR code image to bytes
    secret_key_qr_bytes = BytesIO()
    img.save(secret_key_qr_bytes, format='PNG')
    secret_key_qr_bytes = secret_key_qr_bytes.getvalue()

    qr_code = base64.b64encode(secret_key_qr_bytes).decode() 

    return render_template('result.html', qr_code=base64.b64encode(secret_key_qr_bytes).decode())

@app.route('/enter_secret_key')
def enter_secret_key():
    return render_template('secret_key_input.html')

@app.route('/decrypt_data', methods=['POST'])
def decrypt_data():
    if request.method == 'POST':
        secret_key = request.form['secret_key']

        # Retrieve the latest encrypted data from the database
        conn = sqlite3.connect('db.sqlite')
        cursor = conn.cursor()
        cursor.execute('SELECT data FROM qr_codes ORDER BY id DESC LIMIT 1')
        row = cursor.fetchone()
        conn.close()

        if row:
            encrypted_data = row[0]

            # Decrypt the data using the fixed key and S-box
            decrypted_data = encrypt(encrypted_data, fixed_key)

            # Display the decrypted data
            return render_template('decrypted_data.html', result=decrypted_data)

    return render_template('secret_key_input.html')

@app.route('/scan_qr', methods=['POST'])
def scan_qr():
    scanned_secret_key = request.form['secret_key']

    if scanned_secret_key:
        # Redirect to the route where the user can enter the fixed key
        return redirect(url_for('enter_secret_key'))

    return "Invalid secret key."

@app.route('/view_data')
def view_data():
    # Retrieve all data from the database
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM qr_codes')
    records = cursor.fetchall()
    conn.close()

    # Render a template to display the data
    return render_template('view_data.html', records=records)

if __name__ == '__main__':
    app.run(debug=True)
