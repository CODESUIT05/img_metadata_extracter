from flask import Flask, request, jsonify, render_template
from PIL import Image
import hashlib
import exifread # type: ignore
import io

app = Flask(__name__)

# Function to read metadata
def read_metadata(image_path):
    try:
        with open(image_path, 'rb') as f:
            tags = exifread.process_file(f)
        return tags
    except Exception as e:
        return {"Error": str(e)}

# Function to calculate hash values
def calculate_hash(image_path):
    try:
        hash_md5 = hashlib.md5()
        hash_sha1 = hashlib.sha1()
        hash_sha256 = hashlib.sha256()

        with open(image_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_md5.update(byte_block)
                hash_sha1.update(byte_block)
                hash_sha256.update(byte_block)

        return {
            "MD5": hash_md5.hexdigest(),
            "SHA1": hash_sha1.hexdigest(),
            "SHA256": hash_sha256.hexdigest()
        }
    except Exception as e:
        return {"Error": str(e)}

# Route to upload image and extract metadata
@app.route('/upload', methods=['POST'])
def upload_image():
    file = request.files['image']
    if file:
        image_path = f"uploads/{file.filename}"
        file.save(image_path)

        # Extract metadata and hash
        tags = read_metadata(image_path)
        hashes = calculate_hash(image_path)

        return render_template("index.html", metadata=tags, hashes=hashes)
    return jsonify({"Error": "No image file uploaded"}), 400

# Home page (optional)
@app.route('/')
def home():
    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
