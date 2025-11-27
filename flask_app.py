import os
import logging

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dsa, padding
from flask import Flask, render_template, request, redirect, url_for, jsonify, send_file


app = Flask(__name__)

#TODO - Need to check what the logging requirements for the STIG are
logging.basicConfig(level=logging.DEBUG,
					format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s',
					handlers=[
						logging.FileHandler("/app/logs/flask_app.log"),
						logging.StreamHandler()
					])

# Path to the keys (update this as per your environment)
PRIVATE_KEY_PATH = 'keys/private_key.pem'
PUBLIC_KEY_PATH = 'keys/public_key.pem'

#TODO - Need to check what sort of ciphers we should be using here...
def generate_dummy_keys():
	private_key = dsa.generate_private_key(
		key_size=1024,  # Old and insecure key size
		backend=default_backend()
	)

	with open(PRIVATE_KEY_PATH, 'wb') as private_key_file:
		private_key_file.write(
			private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption()
			)
		)

	public_key = private_key.public_key()

	with open(PUBLIC_KEY_PATH, 'wb') as public_key_file:
		public_key_file.write(
			public_key.public_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PublicFormat.SubjectPublicKeyInfo
			)
		)
def check_keys():
	os.makedirs(os.path.dirname(PRIVATE_KEY_PATH), exist_ok=True)

	if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
		generate_dummy_keys()
		print("Generated dummy DSA keys for PoC.")

@app.route('/')
def index():
	return render_template('index.html')


@app.route('/sign', methods=['GET', 'POST'])
def sign():
	if request.method == 'POST':
		file = request.files['file']

		if file:
			file_content = file.read()

			#TODO - Maybe we should set up passwords to ensure the sig files are secure...?
			with open(PRIVATE_KEY_PATH, 'rb') as key_file:
				private_key = serialization.load_pem_private_key(
					key_file.read(),
					password=None,
					backend=default_backend()
				)

			# Convert the private key to PEM format for logging
			pem_key = private_key.private_bytes(
				encoding=serialization.Encoding.PEM,
				format=serialization.PrivateFormat.TraditionalOpenSSL,
				encryption_algorithm=serialization.NoEncryption()  # No encryption for logging
			).decode('utf-8')

			#TODO - Should probably check if SHA1 is ok to use...
			signature = private_key.sign(
				file_content,
				hashes.SHA1()
			)
			signature_filename = f"{file.filename}.sig"
			with open(signature_filename, 'wb') as f:
				f.write(signature)

			app.logger.info(f'File {file.filename} signed with key {pem_key}')

			return send_file(signature_filename, as_attachment=True)


	return render_template('sign.html')

#TODO - We probably need to add a way to verify the files...
#@app.route('/verify', methods=['GET', 'POST'])
#def verify():

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        try:
            # Get uploaded files
            original_file = request.files['file']
            signature_file = request.files['signature']
            
            if not original_file or not signature_file:
                return render_template('verify.html', 
                                     result='ERROR', 
                                     message='Both files are required')
            
            # Read file contents
            original_content = original_file.read()
            signature = signature_file.read()
            
            # Load public key
            with open(PUBLIC_KEY_PATH, 'rb') as key_file:
                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )
            
            # Verify signature using DSA with SHA-1 (matching the sign function)
            try:
                public_key.verify(
                    signature,
                    original_content,
                    hashes.SHA1()  # Still using SHA-1 to match original
                )
                result = "VALID"
                message = "Signature is valid"
            except Exception:
                result = "INVALID"
                message = "Signature is invalid"
            
            return render_template('verify.html', 
                                 result=result, 
                                 message=message,
                                 filename=original_file.filename)
        
        except Exception as e:
            return render_template('verify.html', 
                                 result='ERROR', 
                                 message=f'Error: {str(e)}')
    
    return render_template('verify.html')
    
    
if __name__ == '__main__':
	check_keys()
	app.run(debug=True, host='0.0.0.0')
