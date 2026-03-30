import numpy as np
import pickle
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score
from cnn_model import extract_features, MODEL_PATH
from preprocess import BRANDS, NUM_CLASSES

BRAND_COLORS = {
    "PayPal":    [(0,70,127),   (255,255,255)],
    "SBI":       [(35,97,146),  (255,255,255)],
    "HDFC":      [(0,57,130),   (220,20,60)],
    "ICICI":     [(200,40,45),  (255,165,0)],
    "Google":    [(66,133,244), (255,255,255)],
    "Microsoft": [(242,80,34),  (127,186,0)],
    "Amazon":    [(255,153,0),  (35,47,62)],
    "Apple":     [(180,180,180),(255,255,255)],
    "Netflix":   [(229,9,20),   (0,0,0)],
    "Facebook":  [(66,103,178), (255,255,255)],
    "Unknown":   [(128,128,128),(200,200,200)],
}

def generate_image(brand):
    colors = BRAND_COLORS.get(brand, BRAND_COLORS["Unknown"])
    img = np.zeros((224,224,3), dtype=np.float32)
    c1 = np.array(colors[0]) / 255.0
    c2 = np.array(colors[1]) / 255.0
    for i in range(224):
        img[i,:] = c1*(1-i/224) + c2*(i/224)
    noise = np.random.normal(0, 0.05, img.shape)
    return np.clip(img+noise, 0, 1)

def train():
    print("=== PhishGuard Visual Trainer (sklearn) ===")
    X, y = [], []
    for idx, brand in enumerate(BRANDS):
        print(f"[Trainer] Generating samples for: {brand}")
        for _ in range(100):
            img = generate_image(brand)
            features = extract_features(np.expand_dims(img, 0))
            X.append(features)
            y.append(idx)
    X, y = np.array(X), np.array(y)
    print(f"[Trainer] Dataset: {len(X)} samples, {X.shape[1]} features")
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    scores = cross_val_score(model, X, y, cv=5)
    print(f"[Trainer] CV Accuracy: {scores.mean()*100:.1f}%")
    model.fit(X, y)
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    with open(MODEL_PATH, "wb") as f:
        pickle.dump(model, f)
    print(f"[Trainer] Model saved to {MODEL_PATH}")
    print("=== Training Complete ===")
    print("Now run: python app.py")

if __name__ == "__main__":
    train()
