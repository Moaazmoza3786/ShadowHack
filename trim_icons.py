import os
from PIL import Image

def trim_image(image_path):
    try:
        img = Image.open(image_path)
        img = img.convert("RGBA")
        
        # Get bounding box of non-zero alpha
        bbox = img.getbbox()
        if bbox:
            # Crop to content
            cropped = img.crop(bbox)
            # Save back overwriting
            cropped.save(image_path)
            print(f"Trimmed: {image_path}")
        else:
            print(f"Skipped (empty): {image_path}")
    except Exception as e:
        print(f"Error processing {image_path}: {e}")

icon_dir = r"c:\Users\mmoza\Desktop\Study-hub3\assets\images\3d-icons"

if not os.path.exists(icon_dir):
    print("Directory not found")
else:
    for filename in os.listdir(icon_dir):
        if filename.lower().endswith(".png"):
            full_path = os.path.join(icon_dir, filename)
            trim_image(full_path)
