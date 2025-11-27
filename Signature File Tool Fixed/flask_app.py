import os
import logging
import tempfile
import secrets
import json
from datetime import datetime
from logging.handlers import RotatingFileHandler

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file, flash
from werkzeug.utils import secure_filename


app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Configuration
PRIVATE_KEY_PATH = 'keys/private_key.pem'
PUBLIC_KEY_PATH = 'keys/public_key.pem'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'doc', 'docx', 'zip', 'png', 'jpg', 'jpeg'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB

# STIG-compliant logging configuration
class STIGFormatter(logging.Formatter):
    """STIG-compliant JSON logging format"""
    def format(self, record):
        log_entry = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'event': record.getMessage(),
            'source_ip': getattr(record, 'source_ip', 'N/A'),
            'user': getattr(record, 'user', 'anonymous'),
            'action': getattr(record, 'action', 'N/A'),
            'result': getattr(record, 'result', 'N/A'),
            'module': record.name,
            'additional_info': getattr(record, 'additional_info', {})
        }
        return json.dumps(log_entry)

# Configure rotating file handler
file_handler = RotatingFileHandler(
    '/app/logs/flask_app.log',
    maxBytes=10485760,  # 10MB
    backupCount=10
)
file_handler.setFormatter(STIGFormatter())
file_handler.setLevel(logging.INFO)

# Console handler for operational monitoring
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
))
console_handler.setLevel(logging.INFO)

# Configure app logger
app.logger.addHandler(file_handler)
app.logger.addHandler(console_handler)
app.logger.setLevel(logging.INFO)

# Remove default Flask logger to prevent duplicate logs
app.logger.removeHandler(logging.root.handlers[0] if logging.root.handlers else None)


def log_security_event(message, action, result, **kwargs):
    """Helper function for security audit logging"""
    extra = {
        'source_ip': request.remote_addr if request else 'N/A',
        'user': 'system',  # Replace with actual user ID when auth is implemented
        'action': action,
        'result': result,
        'additional_info': kwargs
    }
    if result == 'SUCCESS':
        app.logger.info(message, extra=extra)
    elif result == 'FAILURE':
        app.logger.warning(message, extra=extra)
    else:
        app.logger.error(message, extra=extra)


def generate_secure_keys():
    """
    Generate STIG-compliant RSA key pair
    APSC-DV-000160: Use FIPS 140-2 validated cryptographic modules
    Key size: 3072 bits (exceeds NIST minimum of 2048)
    """
    try:
        # Generate RSA private key with FIPS-compliant parameters
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=3072,  # STIG compliant (NIST recommends 2048 minimum)
            backend=default_backend()
        )

        # Get password from environment or generate secure default
        password = os.environ.get('PRIVATE_KEY_PASSWORD')
        if not password:
            app.logger.warning('No PRIVATE_KEY_PASSWORD set, using default (NOT PRODUCTION SAFE)')
            password = 'ChangeMeInProduction!'
        password = password.encode()

        # Save private key with password protection
        # APSC-DV-001620: Protect private cryptographic keys
        with open(PRIVATE_KEY_PATH, 'wb') as private_key_file:
            private_key_file.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.BestAvailableEncryption(password)
                )
            )
        # Secure file permissions
        os.chmod(PRIVATE_KEY_PATH, 0o600)

        # Generate and save public key
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, 'wb') as public_key_file:
            public_key_file.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )

        os.chmod(PUBLIC_KEY_PATH, 0o644)

        log_security_event(
            'RSA key pair generated successfully',
            action='KEY_GENERATION',
            result='SUCCESS',
            key_size=3072,
            algorithm='RSA'
        )

        return True

    except Exception as e:
        log_security_event(
            f'Key generation failed: {str(e)}',
            action='KEY_GENERATION',
            result='ERROR',
            error=str(e)
        )
        return False


def check_keys():
    """Initialize cryptographic keys if they don't exist"""
    os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)

    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        app.logger.info('Cryptographic keys not found, generating new key pair')
        if generate_secure_keys():
            app.logger.info('Key pair generated successfully')
        else:
            app.logger.error('Failed to generate key pair')
            raise RuntimeError('Failed to initialize cryptographic keys')
    else:
        app.logger.info('Using existing cryptographic keys')


def allowed_file(filename):
    """Validate file extension"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_file_upload(file):
    """
    APSC-DV-003270: Validate all input
    Comprehensive file upload validation
    """
    if not file or file.filename == '':
        raise ValueError("No file selected")

    if not allowed_file(file.filename):
        raise ValueError(f"File type not allowed. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}")

    # Check file size
    file.seek(0, os.SEEK_END)
    size = file.tell()
    file.seek(0)

    if size > MAX_FILE_SIZE:
        raise ValueError(f"File size exceeds limit ({MAX_FILE_SIZE / 1024 / 1024}MB)")

    if size == 0:
        raise ValueError("File is empty")

    return True


def load_private_key():
    """Load and decrypt private key securely"""
    password = os.environ.get('PRIVATE_KEY_PASSWORD')
    if not password:
        password = 'ChangeMeInProduction!'

    password = password.encode()

    try:
        with open(PRIVATE_KEY_PATH, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
                backend=default_backend()
            )
        return private_key
    except Exception as e:
        log_security_event(
            'Failed to load private key',
            action='KEY_LOAD',
            result='ERROR',
            error=str(e)
        )
        raise


def load_public_key():
    """Load public key"""
    try:
        with open(PUBLIC_KEY_PATH, 'rb') as key_file:
            public_key = serialization.load_pem_public_key(
                key_file.read(),
                backend=default_backend()
            )
        return public_key
    except Exception as e:
        log_security_event(
            'Failed to load public key',
            action='KEY_LOAD',
            result='ERROR',
            error=str(e)
        )
        raise


@app.route('/')
def index():
    """Home page"""
    log_security_event(
        'User accessed home page',
        action='ACCESS_HOME',
        result='SUCCESS'
    )
    return render_template('index.html')


@app.route('/sign', methods=['GET', 'POST'])
def sign():
    """
    Sign a file using RSA-PSS with SHA-256
    APSC-DV-000170: Use SHA-2 or higher for hashing
    APSC-DV-000160: Use FIPS 140-2 validated cryptographic modules
    """
    if request.method == 'POST':
        try:
            # Get uploaded file
            file = request.files.get('file')

            if not file:
                raise ValueError("No file provided")

            # Validate file
            validate_file_upload(file)

            # Secure filename
            filename = secure_filename(file.filename)

            # Read file content
            file_content = file.read()

            # Load private key securely (with password protection)
            private_key = load_private_key()

            # Sign using RSA-PSS with SHA-256 (STIG compliant)
            # APSC-DV-000170: SHA-256 is approved by NIST FIPS 180-4
            signature = private_key.sign(
                file_content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            # Use secure temporary file with random name
            sig_filename = f"{secrets.token_hex(16)}.sig"
            sig_path = os.path.join(tempfile.gettempdir(), sig_filename)

            with open(sig_path, 'wb') as f:
                f.write(signature)

            # Secure file permissions
            os.chmod(sig_path, 0o600)

            # CRITICAL: NEVER log private key material
            # APSC-DV-001940: Generate audit records
            log_security_event(
                'File signed successfully',
                action='SIGN_FILE',
                result='SUCCESS',
                original_filename=filename,
                file_size=len(file_content),
                signature_algorithm='RSA-PSS',
                hash_algorithm='SHA-256'
            )

            # Send signature file for download
            return send_file(
                sig_path, 
                as_attachment=True, 
                download_name=f"{filename}.sig",
                mimetype='application/octet-stream'
            )

        except ValueError as e:
            log_security_event(
                f'File signing validation error: {str(e)}',
                action='SIGN_FILE',
                result='FAILURE',
                error_type='VALIDATION_ERROR',
                error=str(e)
            )
            flash(f'Error: {str(e)}', 'error')
            return render_template('sign.html'), 400

        except Exception as e:
            log_security_event(
                f'File signing failed: {str(e)}',
                action='SIGN_FILE',
                result='ERROR',
                error_type='SYSTEM_ERROR',
                error=str(e)
            )
            flash('An error occurred while signing the file', 'error')
            return render_template('sign.html'), 500

    # GET request
    log_security_event(
        'User accessed sign page',
        action='ACCESS_SIGN',
        result='SUCCESS'
    )
    return render_template('sign.html')


@app.route('/verify', methods=['GET', 'POST'])
def verify():
    """
    Verify a file signature using RSA-PSS with SHA-256
    APSC-DV-000170: Use SHA-2 or higher for hashing
    """
    if request.method == 'POST':
        try:
            # Get uploaded files
            original_file = request.files.get('file')
            signature_file = request.files.get('signature')

            if not original_file or not signature_file:
                raise ValueError("Both original file and signature file are required")

            # Validate original file
            validate_file_upload(original_file)

            # Secure filenames
            original_filename = secure_filename(original_file.filename)

            # Read file contents
            original_content = original_file.read()
            signature = signature_file.read()

            # Basic signature validation
            if len(signature) == 0:
                raise ValueError("Signature file is empty")

            # Load public key
            public_key = load_public_key()

            # Verify signature using RSA-PSS with SHA-256
            try:
                public_key.verify(
                    signature,
                    original_content,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                result = "VALID"
                message = "✓ Signature is valid - The file has not been tampered with"

                log_security_event(
                    'Signature verification successful',
                    action='VERIFY_SIGNATURE',
                    result='SUCCESS',
                    filename=original_filename,
                    verification_result='VALID'
                )

            except InvalidSignature:
                result = "INVALID"
                message = "✗ Signature is invalid - The file may have been tampered with or the signature does not match"

                log_security_event(
                    'Signature verification failed - invalid signature',
                    action='VERIFY_SIGNATURE',
                    result='FAILURE',
                    filename=original_filename,
                    verification_result='INVALID',
                    reason='Signature does not match'
                )

            return render_template('verify.html', 
                                 result=result, 
                                 message=message,
                                 filename=original_filename)

        except ValueError as e:
            log_security_event(
                f'Signature verification validation error: {str(e)}',
                action='VERIFY_SIGNATURE',
                result='FAILURE',
                error_type='VALIDATION_ERROR',
                error=str(e)
            )
            return render_template('verify.html', 
                                 result='ERROR', 
                                 message=f'Validation Error: {str(e)}'), 400

        except Exception as e:
            log_security_event(
                f'Signature verification error: {str(e)}',
                action='VERIFY_SIGNATURE',
                result='ERROR',
                error_type='SYSTEM_ERROR',
                error=str(e)
            )
            return render_template('verify.html', 
                                 result='ERROR', 
                                 message='An error occurred during verification'), 500

    # GET request
    log_security_event(
        'User accessed verify page',
        action='ACCESS_VERIFY',
        result='SUCCESS'
    )
    return render_template('verify.html')


@app.route('/health')
def health():
    """Health check endpoint for monitoring"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat() + 'Z'
    })


@app.errorhandler(404)
def not_found(error):
    log_security_event(
        f'404 Not Found: {request.path}',
        action='ACCESS_INVALID_PATH',
        result='FAILURE',
        path=request.path
    )
    return render_template('index.html'), 404


@app.errorhandler(500)
def internal_error(error):
    log_security_event(
        f'500 Internal Server Error',
        action='SYSTEM_ERROR',
        result='ERROR',
        error=str(error)
    )
    return jsonify({'error': 'Internal server error'}), 500


# Security headers middleware
@app.after_request
def set_security_headers(response):
    """
    APSC-DV-002440: Protect from XSS attacks
    Set security headers for defense in depth
    """
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'

    # Remove server identification
    response.headers.pop('Server', None)

    return response


if __name__ == '__main__':
    # Initialize cryptographic keys
    check_keys()

    # Log application startup
    log_security_event(
        'Application started',
        action='APP_START',
        result='SUCCESS',
        version='1.0-STIG-COMPLIANT'
    )

    # CRITICAL: NEVER use debug=True in production
    # APSC-DV-001995: Disable debug mode in production
    app.run(host='0.0.0.0', port=5000, debug=False)
