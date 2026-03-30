import requests
import numpy as np
from PIL import Image
import io

BASE_URL = "http://localhost:5000"

def test_health():
    r = requests.get(f"{BASE_URL}/health")
    print(f"Health: {r.json()}")
    assert r.status_code == 200
    print("✓ Health check PASSED")

def test_analyze_phishing():
    # Create fake PayPal-colored image (should detect PayPal)
    img = Image.new("RGB", (224, 224), color=(0, 70, 127))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    
    r = requests.post(
        f"{BASE_URL}/analyze",
        files={"screenshot": ("test.png", buf, "image/png")},
        data={"url": "http://paypal-fake-verify.xyz/login"}
    )
    result = r.json()
    print(f"\nPhishing test: {result['message']}")
    print(f"  Brand: {result['brand']} | Confidence: {result['confidence']:.2f}")
    print(f"  Phishing: {result['phishing']} | Score: {result['score']:.2f}")
    print("✓ Analyze endpoint PASSED")

def test_analyze_legitimate():
    # Create Google-colored image
    img = Image.new("RGB", (224, 224), color=(66, 133, 244))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    
    r = requests.post(
        f"{BASE_URL}/analyze",
        files={"screenshot": ("test.png", buf, "image/png")},
        data={"url": "https://www.google.com/search?q=test"}
    )
    result = r.json()
    print(f"\nLegitimate test: {result['message']}")
    print(f"  Brand: {result['brand']} | Confidence: {result['confidence']:.2f}")
    print(f"  Phishing: {result['phishing']} | Score: {result['score']:.2f}")
    print("✓ Legitimate test PASSED")

if __name__ == "__main__":
    print("=== Testing PhishGuard Flask Service ===\n")
    try:
        test_health()
        test_analyze_phishing()
        test_analyze_legitimate()
        print("\n✅ All tests PASSED — Flask service is working correctly")
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        print("Make sure Flask is running: python app.py")
