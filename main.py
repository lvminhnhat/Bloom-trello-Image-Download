import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import threading
import json
from trello_client import TrelloClient
from utils import Encryptor, sanitize_filename, download_file

class TrelloDownloaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Trello Image Downloader")
        self.root.geometry("600x500")
        
        self.encryptor = Encryptor()
        self.api_key = tk.StringVar()
        self.token = tk.StringVar()
        self.search_query = tk.StringVar()
        self.download_path = tk.StringVar(value=os.getcwd())
        
        self.load_credentials()
        self.load_config()
        self.create_widgets()

    def load_config(self):
        if os.path.exists("config.json"):
            try:
                with open("config.json", "r") as f:
                    config = json.load(f)
                    if "download_path" in config:
                        self.download_path.set(config["download_path"])
            except Exception as e:
                print(f"Failed to load config: {e}")

    def save_config(self):
        try:
            config = {"download_path": self.download_path.get()}
            with open("config.json", "w") as f:
                json.dump(config, f)
        except Exception as e:
            print(f"Failed to save config: {e}")
        
    def create_widgets(self):
        # API Key
        tk.Label(self.root, text="API Key:").pack(pady=5)
        self.api_key_entry = tk.Entry(self.root, textvariable=self.api_key, width=50, show="*")
        self.api_key_entry.pack(pady=5)
        
        # Token
        tk.Label(self.root, text="Token:").pack(pady=5)
        self.token_entry = tk.Entry(self.root, textvariable=self.token, width=50, show="*")
        self.token_entry.pack(pady=5)
        
        # Save Credentials Button
        tk.Button(self.root, text="Save Credentials", command=self.save_credentials).pack(pady=5)
        
        # Search Query
        tk.Label(self.root, text="Search Keyword:").pack(pady=5)
        tk.Entry(self.root, textvariable=self.search_query, width=50).pack(pady=5)
        
        # Download Path
        tk.Label(self.root, text="Download Path:").pack(pady=5)
        path_frame = tk.Frame(self.root)
        path_frame.pack(pady=5)
        tk.Entry(path_frame, textvariable=self.download_path, width=40).pack(side=tk.LEFT)
        tk.Button(path_frame, text="Browse", command=self.browse_path).pack(side=tk.LEFT, padx=5)
        
        # Start Button
        self.start_button = tk.Button(self.root, text="Start Download", command=self.start_download_thread)
        self.start_button.pack(pady=20)
        
        # Log Area
        self.log_text = tk.Text(self.root, height=10, width=70)
        self.log_text.pack(pady=5)
        
    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)
        
    def browse_path(self):
        path = filedialog.askdirectory()
        if path:
            self.download_path.set(path)
            self.save_config()
            
    def save_credentials(self):
        api_key = self.api_key.get().strip()
        token = self.token.get().strip()
        
        if not api_key or not token:
            messagebox.showerror("Error", "Please enter both API Key and Token")
            return
            
        try:
            encrypted_key = self.encryptor.encrypt(api_key)
            encrypted_token = self.encryptor.encrypt(token)
            
            with open("credentials.enc", "wb") as f:
                f.write(encrypted_key + b"\n" + encrypted_token)
            
            # Update Entry widgets to reflect stripped values
            self.api_key.set(api_key)
            self.token.set(token)
            
            messagebox.showinfo("Success", "Credentials saved securely!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save credentials: {e}")

    def load_credentials(self):
        if os.path.exists("credentials.enc"):
            try:
                with open("credentials.enc", "rb") as f:
                    lines = f.readlines()
                    if len(lines) >= 2:
                        self.api_key.set(self.encryptor.decrypt(lines[0].strip()))
                        self.token.set(self.encryptor.decrypt(lines[1].strip()))
            except Exception as e:
                print(f"Failed to load credentials: {e}")

    def start_download_thread(self):
        api_key = self.api_key.get().strip()
        token = self.token.get().strip()
        query = self.search_query.get().strip()
        base_path = self.download_path.get().strip()
        threading.Thread(target=self.run_download, args=(api_key, token, query, base_path), daemon=True).start()

    def run_download(self, api_key, token, query, base_path):
        if not api_key or not token or not query:
            self.log("Error: Missing API Key, Token, or Search Query")
            return
            
        # Save config when starting download to capture manual path edits
        self.download_path.set(base_path)
        self.save_config()
            
        self.start_button.config(state=tk.DISABLED)
        self.log(f"Starting search for '{query}'...")
        
        try:
            client = TrelloClient(api_key, token)
            cards = client.search_cards(query)
            
            if not cards:
                self.log("No cards found.")
                return
                
            self.log(f"Found {len(cards)} cards.")
            
            # Prepare OAuth header for downloads
            auth_header = {
                'Authorization': f'OAuth oauth_consumer_key="{api_key}", oauth_token="{token}"'
            }
            
            for card in cards:
                card_name = sanitize_filename(card['name'])
                self.log(f"Processing card: {card_name}")
                
                attachments = client.get_card_attachments(card['id'])
                if not attachments:
                    self.log(f"  No attachments for {card_name}")
                    continue
                    
                card_dir = os.path.join(base_path, card_name)
                os.makedirs(card_dir, exist_ok=True)
                
                for att in attachments:
                    if att['mimeType'].startswith('image/'):
                        att_name = sanitize_filename(att['name'])
                        file_name = f"{att_name}"
                        file_path = os.path.join(card_dir, file_name)
                        
                        self.log(f"  Downloading {att_name}...")
                        
                        # Try with headers first (safer for signed URLs if any)
                        success, message = download_file(att['url'], file_path, headers=auth_header)
                        
                        if not success:
                             # Fallback to params if headers fail (some S3 urls might reject auth headers but accept signed params)
                             # But usually Trello API urls work with headers.
                             # Let's log the error first.
                             self.log(f"  Failed with headers: {message}. Retrying with params...")
                             success, message = download_file(att['url'], file_path, params=client.auth_params)
                        
                        if success:
                            self.log(f"  Saved to {file_path}")
                        else:
                            self.log(f"  Failed to download {att_name}: {message}")
                            
            self.log("Download complete!")
            
        except Exception as e:
            self.log(f"An error occurred: {e}")
        finally:
            self.start_button.config(state=tk.NORMAL)

if __name__ == "__main__":
    root = tk.Tk()
    app = TrelloDownloaderApp(root)
    root.mainloop()
