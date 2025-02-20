#!/usr/bin/env python3

import os
import re
import requests
import shutil
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()

# -------------------------------
# Custom Errors
# -------------------------------
class CTFdAPIError(Exception):
    pass

class TemplateNotFoundError(Exception):
    pass

# -------------------------------
# Helper Functions for File Comparison
# -------------------------------
def file_hash(filename):
    hasher = hashlib.md5()
    with open(filename, 'rb') as f:
        buf = f.read(8192)
        while buf:
            hasher.update(buf)
            buf = f.read(8192)
    return hasher.hexdigest()

def files_differ(src, dest):
    return file_hash(src) != file_hash(dest)

# -------------------------------
# CTFd Adapter / API interactions
# -------------------------------
class CTFdAdapter:
    def __init__(self, base_url, api_key):
        self.base_url = base_url.rstrip("/")
        self.headers = {
            "Authorization": f"Token {api_key}",
            "Content-Type": "application/json"
        }

    def get_challenges(self):
        url = f"{self.base_url}/api/v1/challenges"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code != 200:
            raise CTFdAPIError(f"Error fetching challenges: {resp.status_code} {resp.text}")

        data = resp.json().get("data", [])
        challenges_details = []

        for ch in data:
            full_data = self._get_challenge_details(ch["id"])
            challenges_details.append({
                "id": full_data["id"],
                "name": full_data["name"],
                "description": full_data["description"],
                "category": full_data["category"],
                "connection_info": full_data.get("connection_info", ""),
                "files": full_data.get("files", []),
                "tags": full_data.get("tags", []),
                "hints": full_data.get("hints", []),
            })
        
        return challenges_details

    def _get_challenge_details(self, challenge_id):
        url = f"{self.base_url}/api/v1/challenges/{challenge_id}"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code != 200:
            raise CTFdAPIError(
                f"Error fetching extended challenge info for {challenge_id}: "
                f"{resp.status_code} {resp.text}"
            )
        return resp.json()["data"]
    
    def download_challenge_files(self, challenge_id):
        url = f"{self.base_url}/api/v1/challenges/{challenge_id}/files"
        resp = requests.get(url, headers=self.headers)
        if resp.status_code != 200:
            raise CTFdAPIError(
                f"Error fetching files for challenge {challenge_id}: "
                f"{resp.status_code} {resp.text}"
            )

        file_infos = resp.json().get("data", [])
        downloaded_paths = []

        for file_info in file_infos:
            if isinstance(file_info, dict) and "location" in file_info:
                file_url = file_info["location"]
            elif isinstance(file_info, str):
                file_url = file_info
            else:
                print(f"Warning: Unrecognized file info format: {file_info}")
                continue

            full_file_url = f"{self.base_url}/files/{file_url.lstrip('/')}"
            local_filename = os.path.basename(file_url.split('?')[0])

            print(f"[*] Downloading: {full_file_url}")
            file_resp = requests.get(full_file_url, headers=self.headers, stream=True)
            if file_resp.status_code == 200:
                with open(local_filename, "wb") as f:
                    shutil.copyfileobj(file_resp.raw, f)
                downloaded_paths.append(local_filename)
                print(f"    -> Saved as: {local_filename}")
            else:
                print(f"[!] Could not download file: {full_file_url} (HTTP {file_resp.status_code})")

        return downloaded_paths

# -------------------------------
# Template Handling
# -------------------------------
def ensure_default_config_structure(config_dir="config"):
    categories = ["pwn", "web", "rev", "osint", "crypto", "misc"]
    for cat in categories:
        cat_path = os.path.join(config_dir, cat)
        os.makedirs(cat_path, exist_ok=True)
        
        solve_py_path = os.path.join(cat_path, "solve.py")
        solution_md_path = os.path.join(cat_path, "solution.md")
        
        # Create default solve.py template if not exists
        if not os.path.exists(solve_py_path):
            with open(solve_py_path, "w", encoding="utf-8") as f:
                # Common header and placeholders
                f.write("#!/usr/bin/env python3\n")
                f.write("# %challname% (solve script)\n\n")
                f.write("print(\"Solving %challname% from %url%\")\n\n")
                
                # Web challenge specific template
                if cat == "web":
                    f.write("import requests\n\n")
                    f.write("url = \"http://example.com\"\n")
                    f.write("resp = requests.get(url)\n")
                    f.write("print(resp.text)\n")
                
                # PwN challenge specific template
                elif cat == "pwn":
                    f.write("from pwn import *\n\n")
                    f.write("debug = False\n")
                    f.write("if debug:\n")
                    f.write("    r = process(\"./binary\")\n")
                    f.write("    # Uncomment if using gdb\n")
                    f.write("    # gdb.attach(r, '''\n")
                    f.write("    #     b *main\n")
                    f.write("    #     c\n")
                    f.write("    # ''')\n")
                    f.write("else:\n")
                    f.write("    r = remote(\"example.com\", 1337)\n\n")
                    f.write("# Example: Basic Buffer Overflow\n")
                    f.write("offset = 72  # Adjust offset as needed\n")
                    f.write("payload = b\"A\" * offset + p64(0xdeadbeef)  # Replace with target address\n")
                    f.write("# r.sendline(payload)\n\n")
                    f.write("# Example: ROP Chain Exploitation\n")
                    f.write("# elf = ELF(\"./binary\")\n")
                    f.write("# rop = ROP(elf)\n")
                    f.write("# rop.call(elf.symbols['win'])\n")
                    f.write("# payload = flat({offset: rop.chain()})\n")
                    f.write("# r.sendline(payload)\n\n")
                    f.write("r.sendline(b\"Hello, world!\")\n")
                    f.write("print(r.recvline())\n")
                    f.write("r.interactive()\n")
                
                # Generic template for other categories
                else:
                    f.write("# Write your challenge solving code here\n")
        
        if not os.path.exists(solution_md_path):
            with open(solution_md_path, "w", encoding="utf-8") as f:
                f.write("# Solution for %challname%\n\n")
                f.write("## Description\n%description%\n\n")
                f.write("> connection info: %connection_info%\n\n") 
                f.write("## Files\n%files%\n")
                f.write("## Flag: `FLAG{FLAG_HERE}`\n\n")

def apply_template(template_content, placeholders):
    def replacer(match):
        key = match.group(1)
        return placeholders.get(key, f"%{key}%")
    return re.sub(r"%([a-zA-Z0-9_]+)%", replacer, template_content)

def create_challenge_directory(challenge, ctf_name, config_dir="config", base_url=""):
    category = challenge.get("category", "misc") or "misc"
    challenge_name = challenge["name"].replace(" ", "_")

    category_template_dir = os.path.join(config_dir, category.lower())
    if not os.path.isdir(category_template_dir):
        category_template_dir = os.path.join(config_dir, "misc")
        if not os.path.isdir(category_template_dir):
            raise TemplateNotFoundError(
                f"No template directory found for category '{category}' or 'misc'."
            )
    challenge_dir = os.path.join(".", ctf_name, category, challenge_name)
    os.makedirs(challenge_dir, exist_ok=True)
    
    placeholders = {
        "challname": challenge.get("name", ""),
        "category": category,
        "description": challenge.get("description", ""),
        "url": f"{base_url}/challenges/{challenge['id']}" if base_url else "",
        "connection_info": challenge.get("connection_info", ""),
        "files": "".join(f"{os.path.basename(f.split('?')[0])}\n" for f in challenge.get("files", [])),
    }
    
    for template_file in os.listdir(category_template_dir):
        template_path = os.path.join(category_template_dir, template_file)
        if os.path.isfile(template_path):
            with open(template_path, "r", encoding="utf-8") as tf:
                template_content = tf.read()
            
            new_content = apply_template(template_content, placeholders)
            new_file_path = os.path.join(challenge_dir, template_file)
            with open(new_file_path, "w", encoding="utf-8") as nf:
                nf.write(new_content)

    return challenge_dir

def download_and_setup_challenge(ctfd_adapter, challenge, ctf_name, base_url):
    challenge_id = challenge["id"]
    challenge_dir = create_challenge_directory(
        challenge=challenge,
        ctf_name=ctf_name,
        config_dir="config",
        base_url=base_url
    )
    
    downloaded_paths = ctfd_adapter.download_challenge_files(challenge_id)
    for file_path in downloaded_paths:
        new_location = os.path.join(challenge_dir, file_path)
        if os.path.exists(new_location):
            if files_differ(file_path, new_location):
                os.replace(file_path, new_location)
                print(f"[+] Updated file: {file_path} in {challenge_dir}")
            else:
                os.remove(file_path)
                print(f"[=] File unchanged: {file_path}")
        else:
            os.rename(file_path, new_location)
            print(f"[+] Saved new file: {file_path} in {challenge_dir}")

    print(f"[+] Finished setting up '{challenge['name']}' in {challenge_dir}")

def main():
    CTF_NAME = os.environ.get("CTF_NAME")
    BASE_URL = os.environ.get("BASE_URL")
    PERSONAL_ACCESS_TOKEN = os.environ.get("PERSONAL_ACCESS_TOKEN")

    if not (CTF_NAME and BASE_URL and PERSONAL_ACCESS_TOKEN):
        print("[!] Please set the CTF_NAME, BASE_URL, and PERSONAL_ACCESS_TOKEN environment variables.")
        if not os.path.exists(".env"):
            with open(".env", "w") as f:
                f.write(f"CTF_NAME={CTF_NAME}\n")
                f.write(f"BASE_URL={BASE_URL}\n")
                f.write(f"PERSONAL_ACCESS_TOKEN={PERSONAL_ACCESS_TOKEN}\n")
        else:
            print("[!] Check the .env file for missing values.")
        return
  
    ensure_default_config_structure()
    
    ctfd = CTFdAdapter(BASE_URL, PERSONAL_ACCESS_TOKEN)
    
    try:
        challenges = ctfd.get_challenges()
        print(f"[*] Found {len(challenges)} challenges.")
        print(f"[*] Setting up challenges in '{CTF_NAME}'...")
    except Exception as e:
        print(f"[!] Error fetching challenges: {e}")
        return

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [
            executor.submit(download_and_setup_challenge, ctfd, challenge, CTF_NAME, BASE_URL)
            for challenge in challenges
        ]
        for fut in futures:
            try:
                fut.result()
            except Exception as e:
                print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
