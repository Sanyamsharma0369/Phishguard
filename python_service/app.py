from flask import Flask, request, jsonify
import numpy as np
import io
import os
import sys
import traceback

# Add python_service directory to path
sys.path.insert(0, os.path.dirname(__file__))

from preprocess import preprocess_image, BRANDS
from cnn_model import predict, load_model

app = Flask(__name__)

# Brand → legitimate domains mapping
BRAND_DOMAINS = {
    "PayPal":    ["paypal.com", "www.paypal.com"],
    "SBI":       ["onlinesbi.sbi", "sbi.co.in", "www.sbi.co.in"],
    "HDFC":      ["hdfcbank.com", "netbanking.hdfcbank.com"],
    "ICICI":     ["icicibank.com", "www.icicibank.com"],
    "Google":    ["google.com", "www.google.com", "accounts.google.com"],
    "Microsoft": ["microsoft.com", "login.microsoftonline.com", "www.microsoft.com"],
    "Amazon":    ["amazon.com", "amazon.in", "www.amazon.in"],
    "Apple":     ["apple.com", "appleid.apple.com", "www.apple.com"],
    "Netflix":   ["netflix.com", "www.netflix.com"],
    "Facebook":  ["facebook.com", "www.facebook.com", "fb.com"],
    "Unknown":   []
}

CONFIDENCE_THRESHOLD = 0.60  # minimum confidence to claim brand detection

def extract_domain(url):
    """Extract clean domain from URL"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        return domain
    except:
        return ""

def is_domain_legitimate(brand, domain):
    """Check if domain matches expected brand domains"""
    legitimate = BRAND_DOMAINS.get(brand, [])
    return any(domain == d or domain.endswith("." + d) for d in legitimate)

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint — Java calls this to detect if Flask is running"""
    return jsonify({
        "status": "running",
        "service": "PhishGuard CNN Visual Analyzer",
        "version": "1.0",
        "brands": len(BRANDS),
        "model_loaded": True
    }), 200

@app.route("/analyze", methods=["POST"])
def analyze():
    """
    Main endpoint — receive screenshot + URL, return brand analysis
    
    Input (multipart/form-data):
      screenshot: image file (PNG/JPEG)
      url: string (the URL being analyzed)
    
    Output (JSON):
      brand: detected brand name
      confidence: float 0.0-1.0
      phishing: boolean
      actual_domain: string
      expected_domain: string
      score: float (visual risk score 0.0-1.0)
      message: human readable summary
    """
    try:
        # Validate inputs
        if "screenshot" not in request.files:
            return jsonify({"error": "No screenshot provided"}), 400
        
        url = request.form.get("url", "")
        screenshot_file = request.files["screenshot"]
        image_bytes = screenshot_file.read()
        
        if len(image_bytes) == 0:
            return jsonify({"error": "Empty screenshot"}), 400
        
        # Preprocess image
        image_array = preprocess_image(image_bytes=image_bytes)
        
        # Run CNN prediction
        brand, confidence, all_probs = predict(image_array)
        
        # Extract actual domain from URL
        actual_domain = extract_domain(url)
        
        # Determine if phishing
        is_phishing = False
        expected_domain = ""
        score = 0.0
        
        if brand != "Unknown" and confidence >= CONFIDENCE_THRESHOLD:
            expected_domain = BRAND_DOMAINS[brand][0] if BRAND_DOMAINS[brand] else ""
            domain_ok = is_domain_legitimate(brand, actual_domain)
            
            if not domain_ok:
                is_phishing = True
                score = min(0.95, confidence)  # high confidence = high risk
            else:
                score = 0.05  # legitimate domain — low risk
        else:
            # Unknown brand or low confidence
            score = 0.0
            brand = "Unknown"
        
        # Build message
        if is_phishing:
            message = (f"PHISHING: Page looks like {brand} ({confidence*100:.0f}% confidence) "
                      f"but domain is '{actual_domain}' not '{expected_domain}'")
        elif brand != "Unknown":
            message = (f"LEGITIMATE: {brand} detected ({confidence*100:.0f}% confidence) "
                      f"on correct domain '{actual_domain}'")
        else:
            message = "No known brand detected in screenshot"
        
        print(f"[CNN] {message}")
        
        response = {
            "brand": brand,
            "confidence": confidence,
            "phishing": is_phishing,
            "actual_domain": actual_domain,
            "expected_domain": expected_domain,
            "score": score,
            "message": message,
            "all_brands": dict(zip(BRANDS, all_probs))
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        print(f"[CNN] Error in /analyze: {e}")
        traceback.print_exc()
        return jsonify({
            "error": str(e),
            "brand": "Unknown",
            "confidence": 0.0,
            "phishing": False,
            "score": 0.0,
            "message": "Analysis failed — defaulting to safe"
        }), 500

@app.route("/brands", methods=["GET"])
def get_brands():
    """Return list of brands the CNN can detect"""
    return jsonify({"brands": BRANDS, "count": len(BRANDS)}), 200

if __name__ == "__main__":
    print("=== PhishGuard CNN Visual Analyzer ===")
    print(f"Brands supported: {len(BRANDS)}")
    print("Loading CNN model...")
    load_model()  # pre-load model at startup
    print("Starting Flask server on http://localhost:5000")
    print("Endpoints:")
    print("  GET  /health   — health check")
    print("  POST /analyze  — analyze screenshot")
    print("  GET  /brands   — list supported brands")
    print()
    app.run(host="0.0.0.0", port=5000, debug=False)
