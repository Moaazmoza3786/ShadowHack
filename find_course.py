
import os
import glob

search_terms = ["Mohamed Fathi", "محمد فتحي", "Application Security"]
csv_dir = "CSV links"

print(f"Searching for {search_terms} in {csv_dir}...")

for filename in glob.glob(os.path.join(csv_dir, "*.csv")):
    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            for term in search_terms:
                if term.lower() in content.lower():
                    print(f"MATCH FOUND in: {filename}")
                    print(f"Term: {term}")
                    # Print first few lines to confirm
                    print(f"Preview: {content[:200]}")
                    print("-" * 50)
    except Exception as e:
        pass
