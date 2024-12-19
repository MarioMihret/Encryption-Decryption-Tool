from flask import Flask, render_template, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from flask_cors import CORS
import os
import logging

# Flask app setup
app = Flask(__name__)
logging.basicConfig(level=logging.DEBUG)
CORS(app)

# Encryption settings
DES_KEY = os.urandom(8)  # DES requires an 8-byte key
AES_KEY = os.urandom(32)  # AES-256 requires a 32-byte key

@app.route('/')
def index():
    return render_template('index.html')

# Encrypt route
@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        app.logger.debug(f"Received data for encryption: {data}")

        algorithm = data.get('algorithm', '').lower()
        message = data.get('message', '')

        if not message:
            return jsonify({'error': 'Message is required'}), 400

        if algorithm == 'aes':
            cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())  # Use ECB mode
            padder = padding.PKCS7(128).padder()
            padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_message) + encryptor.finalize()
            return jsonify({'encrypted': encrypted.hex()})

        elif algorithm == 'des':
            cipher = Cipher(algorithms.TripleDES(DES_KEY), modes.ECB(), backend=default_backend())  # Use ECB mode
            padder = padding.PKCS7(64).padder()
            padded_message = padder.update(message.encode('utf-8')) + padder.finalize()
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_message) + encryptor.finalize()
            return jsonify({'encrypted': encrypted.hex()})

        else:
            return jsonify({'error': 'Invalid algorithm selected. Please choose AES or DES.'}), 400

    except Exception as e:
        app.logger.error(f"Encryption error: {str(e)}")
        return jsonify({'error': f"Internal server error during encryption: {str(e)}"}), 500

# Decrypt route
@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        app.logger.debug(f"Received data for decryption: {data}")

        algorithm = data.get('algorithm', '').lower()
        encrypted_message = data.get('encrypted_message', '')

        if not encrypted_message:
            return jsonify({'error': 'Encrypted message is required'}), 400

        encrypted_message = bytes.fromhex(encrypted_message)

        if algorithm == 'aes':
            cipher = Cipher(algorithms.AES(AES_KEY), modes.ECB(), backend=default_backend())  # Use ECB mode
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
            unpadder = padding.PKCS7(128).unpadder()
            decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
            return jsonify({'decrypted': decrypted_message.decode('utf-8')})

        elif algorithm == 'des':
            cipher = Cipher(algorithms.TripleDES(DES_KEY), modes.ECB(), backend=default_backend())  # Use ECB mode
            decryptor = cipher.decryptor()
            decrypted_padded = decryptor.update(encrypted_message) + decryptor.finalize()
            unpadder = padding.PKCS7(64).unpadder()
            decrypted_message = unpadder.update(decrypted_padded) + unpadder.finalize()
            return jsonify({'decrypted': decrypted_message.decode('utf-8')})

        else:
            return jsonify({'error': 'Invalid algorithm selected. Please choose AES or DES.'}), 400

    except Exception as e:
        app.logger.error(f"Decryption error: {str(e)}")
        return jsonify({'error': f"Internal server error during decryption: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)