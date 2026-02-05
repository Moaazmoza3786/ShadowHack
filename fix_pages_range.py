
lines_to_delete_start = 14057
lines_to_delete_end = 15146
file_path = r'c:/Users/mmoza/Desktop/Study-hub3/pages.js'

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

# Adjust for 0-indexing
start_idx = lines_to_delete_start - 1
end_idx = lines_to_delete_end

# Keep lines before start_idx and after end_idx
new_lines = lines[:start_idx] + lines[end_idx:]

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print(f"Deleted lines {lines_to_delete_start} to {lines_to_delete_end}")
