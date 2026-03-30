import os
import numpy as np
import pickle
from preprocess import BRANDS, NUM_CLASSES

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "brand_model.pkl")
_model = None

def load_model():
    global _model
    if _model is not None:
        return _model
    if os.path.exists(MODEL_PATH):
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        print("[CNN] Model loaded from disk")
    else:
        print("[CNN] No model found - run train_cnn.py first")
        _model = None
    return _model

def extract_features(image_array):
    img = image_array[0]
    h, w = img.shape[:2]
    features = []
    for row in [img[:h//2], img[h//2:]]:
        for col in [row[:, :w//2], row[:, w//2:]]:
            features.extend([col[:,:,0].mean(), col[:,:,1].mean(), col[:,:,2].mean()])
    for c in range(3):
        features.append(img[:,:,c].mean())
        features.append(img[:,:,c].std())
    return features

def predict(image_array):
    model = load_model()
    if model is None:
        return "Unknown", 0.0, [0.0] * NUM_CLASSES
    features = extract_features(image_array)
    probs = model.predict_proba([features])[0]
    brand_idx = int(np.argmax(probs))
    confidence = float(probs[brand_idx])
    return BRANDS[brand_idx], confidence, probs.tolist()
