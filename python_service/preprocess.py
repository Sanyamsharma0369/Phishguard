import numpy as np
from PIL import Image

TARGET_SIZE = (224, 224)
BRANDS = [
    "PayPal", "SBI", "HDFC", "ICICI", "Google",
    "Microsoft", "Amazon", "Apple", "Netflix", "Facebook",
    "Unknown"
]
NUM_CLASSES = len(BRANDS)

def preprocess_image(image_path=None, image_bytes=None):
    """
    Load image from path or bytes, resize to 224x224, normalize to [0,1]
    Returns numpy array of shape (1, 224, 224, 3)
    """
    try:
        if image_bytes:
            import io
            img = Image.open(io.BytesIO(image_bytes))
        elif image_path:
            img = Image.open(image_path)
        else:
            raise ValueError("Must provide image_path or image_bytes")
        
        img = img.convert("RGB")
        img = img.resize(TARGET_SIZE, Image.LANCZOS)
        arr = np.array(img, dtype=np.float32) / 255.0
        return np.expand_dims(arr, axis=0)  # shape: (1, 224, 224, 3)
    except Exception as e:
        print(f"[Preprocess] Error: {e}")
        # Return blank image on failure
        return np.zeros((1, 224, 224, 3), dtype=np.float32)

def get_brand_list():
    return BRANDS

def get_num_classes():
    return NUM_CLASSES
