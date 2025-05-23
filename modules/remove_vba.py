import zipfile
import os
import shutil
import json

# Function to extract the contents of a zip file
import zipfile
import os
import shutil

def clean_office_macro(input_path):
    # Tách phần tên file và phần mở rộng
    base_name, ext = os.path.splitext(os.path.basename(input_path))
    temp_folder = f"{base_name}_extracted"
    output_file = f"{base_name}_clean{ext}"

    # Bước 1: Giải nén file Office như zip (không cần đổi tên)
    if os.path.exists(temp_folder):
        shutil.rmtree(temp_folder)
    os.makedirs(temp_folder)

    with zipfile.ZipFile(input_path, 'r') as zip_ref:
        zip_ref.extractall(temp_folder)

    # Bước 2: Tìm và xóa tất cả các file tên là "vbaProject.bin"
    deleted = False
    for root, dirs, files in os.walk(temp_folder):
        for file in files:
            if file.lower() == "vbaproject.bin":
                file_path = os.path.join(root, file)
                os.remove(file_path)
                print(f"[*] Đã xóa: {file_path}")
                deleted = True

    if not deleted:
        print("[!] Không tìm thấy vbaProject.bin")

    

    # Bước 3: Nén lại thành file Office mới
    with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED) as zip_out:
        for root, dirs, files in os.walk(temp_folder):
            for file in files:
                full_path = os.path.join(root, file)
                rel_path = os.path.relpath(full_path, temp_folder)
                zip_out.write(full_path, rel_path)

    # Bước 4: Xóa thư mục tạm
    shutil.rmtree(temp_folder)

    print(f"[+] Đã tạo file sạch macro: {output_file}")

# # Ví dụ sử dụng
# if _name_ == "_main_":
#     # arg to input file
#     import sys
#     if len(sys.argv) != 2:
#         print("Usage: python script.py <input_file>")
#         sys.exit(1)
#     input_file = sys.argv[1]
#     if not os.path.isfile(input_file):
#         print(f"File không tồn tại: {input_file}")
#         sys.exit(1)
#     # Gọi hàm clean_office_macro với đường dẫn file đầu vào
#     clean_office_macro(input_file)