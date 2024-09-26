import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import encryption

# Salt (Optional: You may want to hard-code it or ask for it)
salt = b"super_secret_salt"  # You can replace this with dynamic salt generation or input if needed

# Function to handle file selection and encryption of multiple files
def encrypt_files(file_paths, password, salt):
    for file_path in file_paths:
        try:
            encryption.encrypt_data(file_path=file_path, password=password, salt=salt)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while encrypting {file_path}: {e}")
            return
    messagebox.showinfo("Success", "All files encrypted successfully!")

# Function to handle file selection and decryption of multiple files
def decrypt_files(file_paths, password, salt):
    for file_path in file_paths:
        try:
            encryption.decrypt_data(file_path=file_path, password=password, salt=salt)
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while decrypting {file_path}: {e}")
            return
    messagebox.showinfo("Success", "All files decrypted successfully!")

# Build the GUI
def build_gui():
    root = tk.Tk()
    root.title("File Encryption/Decryption")

    # Frame for the buttons and inputs
    frame = ttk.Frame(root, padding="10 10 10 10")
    frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

    # Label for file selection
    ttk.Label(frame, text="Choose files:").grid(row=0, column=0, sticky=tk.W)
    
    # Listbox to show selected files
    file_listbox = tk.Listbox(frame, height=6, selectmode=tk.EXTENDED)
    file_listbox.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)

    # Button to select multiple files
    file_paths = []

    def select_files():
        selected_files = filedialog.askopenfilenames(title="Select Files")
        if selected_files:
            file_paths.clear()
            file_paths.extend(selected_files)
            file_listbox.delete(0, tk.END)  # Clear the listbox
            for file in file_paths:
                file_listbox.insert(tk.END, file)  # Show selected files in the listbox

    file_button = ttk.Button(frame, text="Browse Files", command=select_files)
    file_button.grid(row=0, column=2, padx=5, pady=5, sticky=tk.W)

    # Password label and entry box
    ttk.Label(frame, text="Enter Password:").grid(row=1, column=0, sticky=tk.W)
    password_entry = ttk.Entry(frame, show="*")  # `show="*"` masks the password input
    password_entry.grid(row=1, column=1, padx=5, pady=5, sticky=tk.W)

    # Encrypt button
    encrypt_button = ttk.Button(
        frame, 
        text="Encrypt Files", 
        command=lambda: encrypt_files(file_paths, password_entry.get(), salt)
    )
    encrypt_button.grid(row=2, column=0, padx=5, pady=5, sticky=tk.W)

    # Decrypt button
    decrypt_button = ttk.Button(
        frame, 
        text="Decrypt Files", 
        command=lambda: decrypt_files(file_paths, password_entry.get(), salt)
    )
    decrypt_button.grid(row=2, column=1, padx=5, pady=5, sticky=tk.W)

    root.mainloop()

if __name__ == "__main__":
    build_gui()
