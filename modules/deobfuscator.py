from time import sleep
import time
import json
import os
import re
import sys
from collections import Counter
from oletools.olevba import VBA_Parser
import win32com.client
import pythoncom
import subprocess

def detect(vba_code):
    results = []
    if vba_code.detect_vba_macros():
        analysis = vba_code.analyze_macros()
        macros_code = vba_code.extract_macros()
        
        for (filename, stream_path, vba_filename, macro_code) in macros_code:
            extrac = {
                "module": vba_filename,
                "code": macro_code,
                "analysis": []
            }

            # Attach all keywords to this macro block
            for kw_type, keyword, description in analysis:
                extrac["analysis"].append({
                    "type": kw_type,
                    "keyword": keyword,
                    "description": description
                })

            results.append(extrac)  
    return results
    
def extract_bas_modules(data):
    for module in data:
        module_name = module.get("module", "")
        code = module.get("code", "")
        if module_name.lower().endswith(".bas"):
            # Chuyển \r\n thành dòng thật
            code = code.replace("\\r\\n", "\n").replace("\r\n", "\n")
            return code

def extract_vba_functions(code):
    content = code 

    pattern = re.compile(
        r'((?:Private|Public)?\s*(Sub|Function)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[^\n]*\n)(.*?)(End\s+(Sub|Function))',
        re.DOTALL | re.IGNORECASE
    )
    matches = pattern.findall(content)
    funcs = []
    for header, ftype, fname, body, end, _ in matches:
        funcs.append({
            'header': header,
            'type': ftype,
            'name': fname,
            'body': body,
            'end': end,
            'full': header + body + end
        })
    return funcs

def find_most_called_function(funcs):
    func_names = [f['name'] for f in funcs]
    counter = Counter()

    for f in funcs:
        for name in func_names:
            if name != f['name']:
                counter[name] += len(re.findall(r'\b' + re.escape(name) + r'\s*\(', f['body']))

    return counter.most_common(1)[0][0] if counter else None

def find_main_decrypt_function(funcs, name):
    for f in funcs:
        if f['name'] == name:
            return f['full']
def find_balanced_call(s, start_idx, func_name):
    assert s.startswith(func_name + '(', start_idx)

    stack = []
    i = start_idx + len(func_name)

    if s[i] != '(':
        return None, None
    stack.append('(')
    i += 1

    while i < len(s) and stack:
        if s[i] == '(':
            stack.append('(')
        elif s[i] == ')':
            stack.pop()
        i += 1

    call_str = s[start_idx:i]
    return call_str, i

def extract_calls_and_replace(funcs, decrypt_name):
    replaced_funcs = []
    calls = []

    call_counter = 0  # Đếm để đặt tên result0, result1, ...

    for f in funcs:
        if f['name'] == decrypt_name:
            continue

        body = f['body']

        # Giữ dấu phân cách
        parts = re.split(r'(\s*&\s*_\s*|\r?\n)', body)

        new_body_parts = []

        for part in parts:
            if re.match(r'\s*&\s*_\s*|\r?\n', part):
                new_body_parts.append(part)
                continue

            positions = []
            start = 0
            while True:
                pos = part.find(decrypt_name + '(', start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

            if not positions:
                new_body_parts.append(part)
            else:
                last_end = 0
                replaced_part = ""
                for idx, pos in enumerate(positions):
                    if pos < last_end:
                        continue

                    call_str, call_end = find_balanced_call(part, pos, decrypt_name)
                    if call_str is None:
                        continue

                    var_name = f"result{call_counter}"
                    call_counter += 1

                    replaced_part += part[last_end:pos]
                    replaced_part += var_name

                    calls.append((var_name, call_str))
                    last_end = call_end

                replaced_part += part[last_end:]
                new_body_parts.append(replaced_part)

        new_body = ''.join(new_body_parts)
        full_new_func = f['header'] + new_body + f['end']
        replaced_funcs.append(full_new_func)

    return replaced_funcs, calls


def deofucator_code(main_decrypt,callss,file_path8,file_path6):
    pythoncom.CoInitialize()
    # Đọc hàm decrypt từ decrypt.txt (giả sử đây là code VBA có sub RunDecryptAndSaveResults
    decrypt_code = main_decrypt
    
    lines = decrypt_code.splitlines()
    output = []

    for line in lines:
        # Bỏ từ khóa Private/Public
        line = re.sub(r'^\s*(Private|Public)\s+(Function|Sub)', r'\2', line)

        # Bỏ kiểu dữ liệu trong khai báo tham số Function/Sub
        line = re.sub(r'(Function|Sub)\s+\w+\s*\((.*?)\)', lambda m:
                      m.group(1) + " " + re.search(r'(Function|Sub)\s+(\w+)', m.group(0)).group(2) + "(" +
                      re.sub(r'\b(ByVal|ByRef)?\s*(\w+)\s+As\s+\w+', r'\2', m.group(2)) + ")", line)

        # Bỏ kiểu dữ liệu trong khai báo biến Dim
        line = re.sub(r'\bDim\s+(\w+)\s+As\s+\w+', r'Dim \1', line)

        # Bỏ từ khóa Set nếu dùng cho biến không phải đối tượng
        line = re.sub(r'\bSet\s+', '', line)

        output.append(line)

        result = "\n".join(output)
    
    
    

    # Đọc các dòng gọi hàm từ call.txt
    call_content = "\n".join(f"{var} = {code}" for var, code in callss)

    

    # Tách các đoạn gọi hàm result = ...
    calls = re.findall(r"(result\d+\s*=.*?(?=result\d+\s*=|\Z))", call_content, flags=re.DOTALL)
    
    # Tạo code VBA cho module .bas, kết hợp decrypt_code và các lệnh gọi kèm in kết quả
    vba_code = result.strip() + "\n\n"
    vba_code += "Sub RunDecryptAndSaveResults()\n"
    vba_code += "    Dim fso \n"
    vba_code += "    Dim txtFile\n"
    vba_code += "    Set fso = CreateObject(\"Scripting.FileSystemObject\")\n"
    vba_code += f"    Set txtFile = fso.CreateTextFile(\"{file_path6}\", True, True) ' True để overwrite, True để UTF-8\n\n"
    for i, call in enumerate(calls):
        call = call.strip().replace("\n", " ")
        vba_code += f"    Dim result{i}\n"
        vba_code += f"    {call}\n"
        vba_code += f"    txtFile.Write \"result{i} =\"\n"
        vba_code += f"    txtFile.Write result{i}\n"
        vba_code += f"    txtFile.WriteLine \"\"\n"

    vba_code += "    txtFile.Close\n"
    vba_code += "End Sub\n"
    vba_code += "RunDecryptAndSaveResults\n"
    # Ghi file .bas (module VBA)
    bas_path = file_path8    # filepath3 ="C:\daccmd\VBA\run_decrypt.bas" 
    os.makedirs(os.path.dirname(bas_path), exist_ok=True)
    with open(bas_path, "w", encoding="utf-8") as f:
        f.write(vba_code)

    print(" run_decrypt.bas has been created")

    # # --- Tự động mở Excel, import module .bas và chạy macro ---

    # excel = win32com.client.Dispatch("Excel.Application")
    # excel.Visible = False  # ẩn Excel khi chạy

    # wb = excel.Workbooks.Add()

    # # Thêm module .bas vào Workbook VBA project
    # vbproj = wb.VBProject
    # mod = vbproj.VBComponents.Add(1)  # 1 = vbext_ct_StdModule

    # with open(bas_path, "r", encoding="utf-8") as f:
    #     mod_code = f.read()

    # mod.CodeModule.AddFromString(mod_code)

    # # Chạy macro RunDecryptAndSaveResults
    # try:
    #     excel.Application.Run("RunDecryptAndSaveResults")
    #     print("Đã chạy macro và xuất kết quả ra coderesult.txt")
    # except Exception as e:
    #     print("Lỗi khi chạy macro:", e)

    # # Đóng workbook không lưu
    # wb.Close(False)
    # excel.Quit()
    # xcel = None
    # wb = None

    # try:
    #     # Tạo instance Excel riêng biệt
    #     excel = win32com.client.DispatchEx("Excel.Application")
    #     excel.Visible = False
    #     excel.DisplayAlerts = False

    #     wb = excel.Workbooks.Open(r"C:\daccmd\Book1.xlsm")

    #     # Thêm module .bas vào Workbook VBA project
         
    #     mod = wb.VBProject.VBComponents.Add(1)  # 1 = vbext_ct_StdModule

    #     with open(file_path8, "r", encoding="utf-8") as f:
    #         mod_code = f.read()

    #     mod.CodeModule.AddFromString(mod_code)

    #     # Chạy macro RunDecryptAndSaveResults
    #     try:
    #         excel.Application.Run("RunDecryptAndSaveResults")
    #     except Exception as e:
    #         print("error in running macro :", e)
    #         # Nếu lỗi do AccessVBOM, bạn có thể check message lỗi ở đây và báo thêm

    # finally:
    #     # Đóng workbook không lưu
    #     if wb:
    #         wb.Close(False)
    #     if excel:
    #         excel.Quit()
    #     pythoncom.CoUninitialize()
    subprocess.run(['cscript', '//NoLogo', file_path8], capture_output=True, text=True)
        
def tranfer(file_path6, replaced_funcs):
    variables = {}
    with open(file_path6, "r", encoding="utf-16") as f:
        for line in f:
            match = re.match(r"(result\d+)\s*=\s*(.*)", line.strip())
            if match:
                var_name = match.group(1)
                var_value = match.group(2)
                variables[var_name] = var_value

    # Đọc nội dung file code.txt
        content = "\n".join(replaced_funcs)
     # Bỏ xuống dòng giữa hai resultX liền nhau
    content = re.sub(r"(result\d+\s*=.*)\n(?=result\d+\s*=)", r"\1", content)

    


    # Thay thế từng biến trong nội dung
    for var_name, var_value in variables.items():
        content = re.sub(
            rf"\b{re.escape(var_name)}\b",
            lambda m: var_value,
            content
        )
    # Loại bỏ tất cả " & _"
    content = re.sub(r"\s*&\s*_\s*\n\s*", "", content)
    
    return content



def deobfuscator(malicious_file_path):
    
    current_dir = os.getcwd() 
    CODEFOLDER_NAME2 = r"VBA"
    folder_path2 = os.path.join(current_dir, CODEFOLDER_NAME2)  # Đường dẫn thư mục mới
    if not os.path.isdir(CODEFOLDER_NAME2):
        os.makedirs(CODEFOLDER_NAME2)
        
    FILE_NAME6 = "coderesult.txt"
    file_path6 = os.path.join(folder_path2, FILE_NAME6)

    FILE_NAME8 = "run_decrypt.vbs"
    file_path8 = os.path.join(folder_path2, FILE_NAME8)
    
    
    

    vba = VBA_Parser(malicious_file_path)
    data = detect(vba)
    code = extract_bas_modules(data)
    func = extract_vba_functions(code)
    decrypt_name = find_most_called_function(func)
    decrypt_code = find_main_decrypt_function(func, decrypt_name)
    replaced_funcs, calls = extract_calls_and_replace(func, decrypt_name)
    deofucator_code(decrypt_code,calls,file_path8,file_path6)
    result = tranfer(file_path6, replaced_funcs)
    return result

# if __name__ == "__main__":
#     malicious_file_path = r"C:\daccmd\fileDOAN\CCMD_DA\Win10_Enc_Only.xlsm"
#     print(deobfuscator(malicious_file_path))

    
    
    