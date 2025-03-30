# TryHackMe Chrome Full Walkthrough

## Topics

- **Cryptography**  
- **Reverse Engineering**  
- **Dumping Chrome Browser Credentials**
- **Network traffic analysis** 


## PCAP analysis

We are given a pcap to analyse called traffic.pcapng. Opening it up and going to **Statistics > Protocol Hierarchy**  We can see what protocols we are dealing with.

![image](https://github.com/user-attachments/assets/87707c59-1237-4804-83ce-d8f4049bcaa6)

Looking at this we can see DNS and SMB2. We are told in the challenge "You find that a malicious actor extracted something over the network". This points to exfiltration of files most likely. Lets have a look at the exported objects

**File > Export Objects > SMB**  

![image](https://github.com/user-attachments/assets/3e70a99c-f022-477e-ac43-0e22201c555d)

From the above we can see two interesting files:

`transfer.exe`
`encrypted_files`

## Reversing transfer.exe 
The `encrypted_files` as the name suggests is encrypted. Lets take a look at `transfer.exe` with die (Detect It Easy)
![image](https://github.com/user-attachments/assets/354eed3a-d168-49a1-aaa7-31e90c88318a)

We can see that this is a .NET executable, which should mean we can decompile it to get the original code using dnspy.

![image](https://github.com/user-attachments/assets/74f5d464-d3b0-4312-a4b7-bab8234228e9)

From the `main()` function we can see that `encrypted_files` has been encrypted with AES. We are also given the key and the IV. 

Key: `PjoM95MpBdz85Kk7ewcXSLWCoAr7mRj1`
IV: `lR3soZqkaWZ9ojTX`

![image](https://github.com/user-attachments/assets/f09313e8-368b-4770-b621-8eef28cbaac5)

Using AES decrypt and saving the output, cyberchef suggests saving it as a zip which matches what we saw in the code before. As the attacker exfiltrated it as a zip file.


## Extracting Credentials from Chrome

Extracting the zip file gives us an app data folder. There is an interesting blog from Hackthebox on how to extract chrome credentials:

https://www.hackthebox.com/blog/seized-ca-ctf-2022-forensics-writeup

Following that we are interested in the following paths:

1. `C:\Users\Flare\Desktop\decrypt\AppData\Roaming\Microsoft\Protect\S-1-5-21-3854677062-280096443-3674533662-1001\8c6b6187-8eaa-48bd-be16-98212a441580`
2. `C:\Users\Flare\Desktop\decrypt\AppData\Local\Google\Chrome\User Data\Local State`

The first path contains the DPAPI (Data Protection API) Master Key, which is required to decrypt stored Chrome passwords. The second path contains the encryption key (Base64-encoded) that Chrome uses to encrypt saved credentials in the Login Data SQLite database.

First we need to extract the user hash from file path 1. We have the SID and the master key. So we can extract this using a tool called `DPAPImk2john.py`. 

```
DPAPImk2john -mk AppData/Roaming/Microsoft/Protect/S-1-5-21-3854677062-280096443-3674533662-1001/8c6b6187-8eaa-48bd-be16-98212a441580 -c local -S S-1-5-21-3854677062-280096443-3674533662-1001 > mkhash
```
Now we can crack the hash using john the ripper 

```
john --wordlist=/usr/share/wordlists/rockyou.txt mkhash
```
This should now give us the password [REDACTED].

Next we need to decode the DPAPI blob before decrypting. We can run the python script provided in the blog and it should give us a file called dec_data.

```python
import json
import base64

fh = open('AppData/Local/Google/Chrome/User Data/Local State', 'rb')
encrypted_key = json.load(fh)

encrypted_key = encrypted_key['os_crypt']['encrypted_key']

decrypted_key = base64.b64decode(encrypted_key)

open("dec_data", 'wb').write(decrypted_key[5:])
```

We now use mimikatz to decrypt the master key:

```
dpapi::masterkey /in:8c6b6187-8eaa-48bd-be16-98212a441580 /sid:S-1-5-21-3854677062-280096443-3674533662-1001 /password:[REDACTED] /protected
```
![image](https://github.com/user-attachments/assets/ed4683a4-0b39-41a1-a1b7-48b216d93c8a)

We then decrypt the DPAPI blob which is the private AES key, using the masterkey we obtained previously.

dpapi::blob /masterkey:ca4387eb0a71fc0eea23e27f54b9ae240379c9e82a05d6fca73ecee13ca2e0e4d98390844697d8ed10715415c56152653edf460a47b70ddb868a03ee6a3f9840 /in:"dec_data" /out:aes.dec

![image](https://github.com/user-attachments/assets/54018da9-4e87-43d1-a5dd-cc1164fcf7b0)

Now we can decrypt chromes passwords locally using the python script provided in the blog. 

```python
import os
import re
import sys
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil
import csv

def get_secret_key():
    secret_key = open('aes.dec', 'rb').read()
    return secret_key

def decrypt_payload(cipher, payload):
    return cipher.decrypt(payload)

def generate_cipher(aes_key, iv):
    return AES.new(aes_key, AES.MODE_GCM, iv)

def decrypt_password(ciphertext, secret_key):
    try:
        initialisation_vector = ciphertext[3:15]
        encrypted_password = ciphertext[15:-16]
        cipher = generate_cipher(secret_key, initialisation_vector)
        decrypted_pass = decrypt_payload(cipher, encrypted_password)
        decrypted_pass = decrypted_pass.decode()
        return decrypted_pass
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Unable to decrypt, Chrome version <80 not supported. Please check.")
        return ""

def get_db_connection(chrome_path_login_db):
    try:
        return sqlite3.connect(chrome_path_login_db)
    except Exception as e:
        print("%s"%str(e))
        print("[ERR] Chrome database cannot be found")
        return None

if __name__ == '__main__':
    secret_key = get_secret_key()
    chrome_path_login_db = r"AppData\AppData\Local\Google\Chrome\User Data\Default\Login Data"
    conn = get_db_connection(chrome_path_login_db)
    if(secret_key and conn):
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        for index,login in enumerate(cursor.fetchall()):
            url = login[0]
            username = login[1]
            ciphertext = login[2]
            if(url!="" and username!="" and ciphertext!=""):
                decrypted_password = decrypt_password(ciphertext, secret_key)
                print("Sequence: %d"%(index))
                print("URL: %s\nUser Name: %s\nPassword: %s\n"%(url,username,decrypted_password))
                print("*"*50)
        cursor.close()
        conn.close()
```
 Note I had to modify mine to use "from Crypto.Cipher import AES" instead as I had issues with Cryptodome. Before we run the script we also need to change action_url to origin_url in the script. The reason for this is that if we take 'Login State' and view it in an online SQLite Viewer we can see that it uses origin_url as the column

 ![image](https://github.com/user-attachments/assets/cbf98007-90c4-4bb6-a3f0-d7a4e50bbd28)

 By viewing just Local state alone in SQlite online we get 2 of ur answers as well. Now we can run the script, decrypt and get our passwords as shown below:

 ![Screenshot 2025-02-08 185113](https://github.com/user-attachments/assets/9026cf3e-6157-4af8-a4dc-841d15ec8e8e)

