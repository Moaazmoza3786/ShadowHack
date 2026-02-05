from PIL import Image
import os
import sys

def remove_black_background(image_path, threshold=50):
    try:
        img = Image.open(image_path).convert("RGBA")
        datas = img.getdata()
        
        newData = []
        for item in datas:
            # Check if pixel is close to black
            if item[0] < threshold and item[1] < threshold and item[2] < threshold:
                newData.append((0, 0, 0, 0)) # Transparent
            else:
                newData.append(item)
        
        img.putdata(newData)
        img.save(image_path, "PNG")
        print(f"Processed: {image_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        target_path = sys.argv[1]
        if os.path.exists(target_path):
            remove_black_background(target_path)
        else:
            print("File not found")
