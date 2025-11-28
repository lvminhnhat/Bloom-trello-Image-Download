import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import os
import threading
import json
from datetime import datetime
from trello_client import TrelloClient
from utils import Encryptor, sanitize_filename, download_file

class TrelloDownloaderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Trello Image Downloader")
        self.root.geometry("700x600")
        
        # Apply Theme
        style = ttk.Style()
        style.theme_use('clam') # Modern clean look
        
        self.encryptor = Encryptor()
        self.api_key = tk.StringVar()
        self.token = tk.StringVar()
        self.search_query = tk.StringVar()
        self.download_path = tk.StringVar(value=os.getcwd())
        self.sequential_download = tk.BooleanVar(value=False)
        
        self.load_credentials()
        self.load_config()
        self.dir_lock = threading.Lock()
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
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Credentials Section ---
        cred_frame = ttk.LabelFrame(main_frame, text="Credentials", padding="10")
        cred_frame.pack(fill=tk.X, pady=(0, 15))
        
        grid_opts = {'padx': 5, 'pady': 5, 'sticky': tk.W}
        
        ttk.Label(cred_frame, text="API Key:").grid(row=0, column=0, **grid_opts)
        self.api_key_entry = ttk.Entry(cred_frame, textvariable=self.api_key, width=50, show="*")
        self.api_key_entry.grid(row=0, column=1, **grid_opts)
        
        ttk.Label(cred_frame, text="Token:").grid(row=1, column=0, **grid_opts)
        self.token_entry = ttk.Entry(cred_frame, textvariable=self.token, width=50, show="*")
        self.token_entry.grid(row=1, column=1, **grid_opts)
        
        ttk.Button(cred_frame, text="Save Credentials", command=self.save_credentials).grid(row=2, column=1, sticky=tk.E, padx=5, pady=5)
        
        # --- Settings Section ---
        settings_frame = ttk.LabelFrame(main_frame, text="Download Settings", padding="10")
        settings_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(settings_frame, text="Search Keyword:").grid(row=0, column=0, **grid_opts)
        ttk.Entry(settings_frame, textvariable=self.search_query, width=50).grid(row=0, column=1, **grid_opts)
        
        ttk.Label(settings_frame, text="Download Path:").grid(row=1, column=0, **grid_opts)
        path_frame = ttk.Frame(settings_frame)
        path_frame.grid(row=1, column=1, sticky=tk.W, padx=5, pady=5)
        
        ttk.Entry(path_frame, textvariable=self.download_path, width=40).pack(side=tk.LEFT)
        ttk.Button(path_frame, text="Browse", command=self.browse_path).pack(side=tk.LEFT, padx=5)
        
        ttk.Checkbutton(settings_frame, text="Sequential Download (Slower but safer)", variable=self.sequential_download).grid(row=2, column=1, sticky=tk.W, padx=5, pady=5)

        # --- Action Section ---
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=(0, 15))
        
        style = ttk.Style()
        style.configure("Accent.TButton", font=("Helvetica", 10, "bold"))
        self.start_button = ttk.Button(action_frame, text="Start Download", command=self.start_download_thread, style="Accent.TButton")
        self.start_button.pack(fill=tk.X, ipady=8)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(action_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill=tk.X, pady=(10, 0))
        
        # --- Log Section ---
        log_frame = ttk.LabelFrame(main_frame, text="Logs", padding="5")
        log_frame.pack(fill=tk.BOTH, expand=True)
        
        self.log_text = tk.Text(log_frame, height=12, width=70, state=tk.DISABLED, font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure Log Tags
        self.log_text.tag_config("INFO", foreground="black")
        self.log_text.tag_config("ERROR", foreground="red")
        self.log_text.tag_config("SUCCESS", foreground="green")
        self.log_text.tag_config("WARNING", foreground="#FF8C00") # Dark Orange
        
        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
    def log(self, message, level="INFO"):
        self.root.after(0, lambda: self._log_impl(message, level))
        
    def _log_impl(self, message, level):
        timestamp = datetime.now().strftime("[%H:%M:%S]")
        full_message = f"{timestamp} {message}\n"
        
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, full_message, level)
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def update_status(self, message):
        self.root.after(0, lambda: self.status_var.set(message))

    def update_progress(self, value, maximum=None):
        def _update():
            if maximum is not None:
                self.progress_bar['maximum'] = maximum
            self.progress_var.set(value)
        self.root.after(0, _update)
        
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
        is_sequential = self.sequential_download.get()
        threading.Thread(target=self.run_download, args=(api_key, token, query, base_path, is_sequential), daemon=True).start()

    def check_permissions(self, path):
        """Check if we can create directories and write files in the given path."""
        try:
            if not os.path.exists(path):
                # Try to create the base path itself
                os.makedirs(path, exist_ok=True)
            
            # Try to create a test directory and file
            test_dir = os.path.join(path, ".perm_test_dir")
            os.makedirs(test_dir, exist_ok=True)
            
            test_file = os.path.join(test_dir, ".perm_test_file")
            with open(test_file, "w") as f:
                f.write("test")
            
            # Cleanup
            os.remove(test_file)
            os.rmdir(test_dir)
            return True, ""
        except Exception as e:
            return False, str(e)

    def run_download(self, api_key, token, query, base_path, is_sequential):
        if not api_key or not token or not query:
            self.log("Error: Missing API Key, Token, or Search Query", level="ERROR")
            return
            
        # Save config when starting download to capture manual path edits
        self.download_path.set(base_path)
        self.save_config()
            
        self.start_button.config(state=tk.DISABLED)
        self.update_status("Checking permissions...")
        
        # Pre-flight permission check
        self.log(f"Checking permissions for '{base_path}'...")
        allowed, error = self.check_permissions(base_path)
        if not allowed:
            self.log(f"ERROR: Cannot write to '{base_path}'.", level="ERROR")
            self.log(f"Details: {error}", level="ERROR")
            self.log("PLEASE CHANGE THE DOWNLOAD PATH to a folder in your User Profile (e.g., Downloads).", level="WARNING")
            self.start_button.config(state=tk.NORMAL)
            self.update_status("Error: Permission Denied")
            return

        self.log(f"Starting search for '{query}'...")
        self.update_status(f"Searching for '{query}'...")
        self.update_progress(0)
        
        try:
            client = TrelloClient(api_key, token)
            cards = client.search_cards(query)
            
            if not cards:
                self.log("No cards found.", level="WARNING")
                self.update_status("No cards found")
                self.start_button.config(state=tk.NORMAL)
                return
            
            total_cards = len(cards)
            self.update_progress(0, total_cards)
            
            # Prepare OAuth header for downloads
            auth_header = {
                'Authorization': f'OAuth oauth_consumer_key="{api_key}", oauth_token="{token}"'
            }

            if is_sequential:
                self.log(f"Found {total_cards} cards. Starting sequential download...")
                self.update_status(f"Downloading {total_cards} cards (Sequential)...")
                
                for i, card in enumerate(cards):
                    self.process_card(client, card, base_path, auth_header)
                    self.update_progress(i + 1)
            else:
                self.log(f"Found {total_cards} cards. Starting download with 5 threads...")
                self.update_status(f"Downloading {total_cards} cards (Threaded)...")
                
                # Ensure base path exists to avoid race conditions creating it
                try:
                    os.makedirs(base_path, exist_ok=True)
                except Exception as e:
                    self.log(f"Error creating base path '{base_path}': {e}", level="ERROR")
                    return

                import concurrent.futures
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
                    futures = [
                        executor.submit(self.process_card, client, card, base_path, auth_header)
                        for card in cards
                    ]
                    
                    completed_count = 0
                    for future in concurrent.futures.as_completed(futures):
                        completed_count += 1
                        self.update_progress(completed_count)
                            
            self.log("Download complete!", level="SUCCESS")
            self.update_status("Download Complete!")
            messagebox.showinfo("Success", "Download Complete!")
            
        except Exception as e:
            self.log(f"An error occurred: {e}", level="ERROR")
            self.update_status("Error occurred")
        finally:
            # Ensure button is re-enabled in the main thread
            self.root.after(0, lambda: self.start_button.config(state=tk.NORMAL))

    def process_card(self, client, card, base_path, auth_header):
        try:
            card_name = sanitize_filename(card['name'])
            self.log(f"Processing card: {card_name}")
            
            attachments = client.get_card_attachments(card['id'])
            if not attachments:
                self.log(f"  No attachments for {card_name}")
                return
                
            card_dir = os.path.join(base_path, card_name)
            
            # Check if it's a file
            if os.path.isfile(card_dir):
                self.log(f"Error: '{card_name}' exists as a file, cannot create directory.", level="ERROR")
                return

            with self.dir_lock:
                for i in range(5): # Increased retries
                    try:
                        os.makedirs(card_dir, exist_ok=True)
                        break
                    except PermissionError:
                        if i == 4: 
                            self.log(f"Failed to create directory '{card_dir}' after retries.", level="ERROR")
                            raise
                        import time
                        time.sleep(0.2) # Increased sleep
                    except Exception as e:
                        self.log(f"Unexpected error creating directory '{card_dir}': {e}", level="ERROR")
                        raise
            
            for att in attachments:
                if att['mimeType'].startswith('image/'):
                    att_name = sanitize_filename(att['name'])
                    file_name = f"{att_name}"
                    file_path = os.path.join(card_dir, file_name)
                    
                    self.log(f"  Downloading {att_name}...")
                    
                    # Try with headers first
                    success, message = download_file(att['url'], file_path, headers=auth_header)
                    
                    if not success:
                         self.log(f"  Failed with headers: {message}. Retrying with params...")
                         success, message = download_file(att['url'], file_path, params=client.auth_params)
                    
                    if success:
                        self.log(f"  Saved to {file_path}", level="SUCCESS")
                    else:
                        self.log(f"  Failed to download {att_name}: {message}", level="ERROR")
        except Exception as e:
            self.log(f"Error processing card {card.get('name', 'unknown')}: {e}", level="ERROR")

if __name__ == "__main__":
    root = tk.Tk()
    app = TrelloDownloaderApp(root)
    root.mainloop()
