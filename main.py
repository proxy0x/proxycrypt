from tkinter import filedialog, messagebox, ttk
from tkinter import Tk, Label, Button, Entry, SE, END
from Crypto.Cipher import AES
from zipfile import ZipFile
from PIL import Image, ImageTk 
import hashlib
import os
import shutil
import io
import zxcvbn
import secrets
import string
import tkinter as tk

# main window
window = tk.Tk()
window.title("proxycrypt")

window.iconbitmap(default="key.ico")

# Set the window size to a fixed value
window.geometry("900x300")  # Set your preferred width and height

# Disable window resizing
window.resizable(False, False)

# password label and entry
label_password = tk.Label(window, text="Enter Password:")
label_password.grid(row=1, column=0, pady=10, padx=10, sticky=tk.W)
entry_password = tk.Entry(window, show="*")
entry_password.grid(row=1, column=1, pady=10, padx=10, sticky=tk.E)

def toggle_password_visibility():
    current_show_state = show_password.get()
    show_password.set(not current_show_state)
    
    if current_show_state:
        entry_password.config(show="")
    else:
        entry_password.config(show="*")

show_password = tk.BooleanVar()
show_password.set(False)

# eyeball button
eyeball_button = tk.Button(window, text="👁", command=toggle_password_visibility)
eyeball_button.grid(row=1, column=2, pady=10, padx=10, sticky=tk.E)

# Function to toggle between light and dark mode
def toggle_mode():
    dark_mode.set(not dark_mode.get())
    update_colors()

# Function to update colors based on the selected mode
def update_colors():
    bg_color = "#333333" if dark_mode.get() else "#FFFFFF"
    fg_color = "#FFFFFF" if dark_mode.get() else "#000000"
    cursor_color = "white" if dark_mode.get() else "black"
    checkbutton_fg_color = "#FFFFFF" if dark_mode.get() else "#000000"  # Adjust the color to your preference
    checkbutton_select_color = "#00FF00"  # Adjust the color to your preference

    window.configure(bg=bg_color)
    line_canvas.configure(bg="white" if dark_mode.get() else "black")  # Update canvas background color

    for widget in window.winfo_children():
        try:
            widget.configure(bg=bg_color, fg=fg_color)

            # Set cursor color for Entry widgets
            if isinstance(widget, tk.Entry):
                widget.configure(insertbackground=cursor_color)

            # Set foreground color and selectcolor for Checkbutton widgets
            if isinstance(widget, tk.Checkbutton):
                widget.configure(fg=checkbutton_fg_color, selectcolor=checkbutton_select_color)

        except tk.TclError:
            
            pass

# password dialog
def create_password_dialog():
    top = tk.Toplevel()
    top.title("Create Password")
    top.geometry("300x100")

    password_label = tk.Label(top, text="Enter a new password:")
    password_label.pack()

    password_entry = tk.Entry(top, show="*")
    password_entry.pack()

    def submit():
        global user_password
        user_password = password_entry.get()
        if not user_password:
            messagebox.showerror("Error", "Please provide a password.")
        else:
            top.destroy()

    submit_button = tk.Button(top, text="Submit", command=submit)
    submit_button.pack()

# update password strength label
def update_password_strength_label(password):
    strength, suggestions = check_password_strength(password)

    # Display password strength with color-coded label
    if strength == 0:
        strength_color = "red"
        strength_text = "Weak"
    elif strength == 1:
        strength_color = "orange"
        strength_text = "Medium"
    elif strength == 2:
        strength_color = "yellow"
        strength_text = "Reasonable"
    elif strength == 3:
        strength_color = "lightgreen"
        strength_text = "Strong"
    else:
        strength_color = "green"
        strength_text = "Very Strong"

    password_strength_label.config(text=f"Password Strength: {strength_text}", fg=strength_color)
    
# password strength label
password_strength_label = tk.Label(window, text="Password Strength: N/A", font=("Arial", 10, "italic"))
password_strength_label.grid(row=5, column=0, columnspan=2, pady=5, padx=10)

# label for encryption type
label_encryption_type = tk.Label(window, text="Encryption Type: AES-256-GCM", font=("Arial", 10, "italic"))
label_encryption_type.grid(row=6, column=0, columnspan=2, pady=5, padx=10)

entry_password.bind("<KeyRelease>", lambda event: update_password_strength_label(entry_password.get()))

def on_password_key_release(event, password):
    
    if ' ' in password:
        password = password.replace(' ', '') 
        entry_password.delete(0, tk.END)
        entry_password.insert(0, password)
    
    # Update password strength label
    update_password_strength_label(password)
 
# Function to derive a key from a password using SHA-256
def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

# Check password strength
def check_password_strength(password):
    try:
        result = zxcvbn.zxcvbn(password)
        return result['score'], result['feedback']['suggestions']
    except Exception as e:
        print(f"Error in check_password_strength: {e}")
        return 0, []  # Return a default value for strength and an empty list for suggestions

line_canvas = tk.Canvas(window, height=300, width=1, bg="black", highlightthickness=0)
line_canvas.grid(row=0, column=4, rowspan=8, pady=5, padx=10, sticky="ns")

def update_colors():
    bg_color = "#333333" if dark_mode.get() else "#FFFFFF"
    fg_color = "#FFFFFF" if dark_mode.get() else "#000000"
    cursor_color = "white" if dark_mode.get() else "black"
    checkbutton_fg_color = "#000000" if dark_mode.get() else "#000000"  # Adjust the color for better visibility
    checkbutton_select_color = "#00ffff"  # Adjust the color to your preference

    window.configure(bg=bg_color)
    line_canvas.configure(bg="white" if dark_mode.get() else "black")  # Update canvas background color

    for widget in window.winfo_children():
        try:
            widget.configure(bg=bg_color, fg=fg_color)

            if isinstance(widget, tk.Entry):
                widget.configure(insertbackground=cursor_color)

            # Set foreground color and selectcolor for Checkbutton widgets
            if isinstance(widget, tk.Checkbutton):
                widget.configure(fg=checkbutton_fg_color, selectcolor=checkbutton_select_color)

        except tk.TclError:
            
            pass

show_password = tk.BooleanVar()
show_password.set(False)

# Function to toggle password visibility
def toggle_password_visibility():
    current_show_state = show_password.get()
    show_password.set(not current_show_state)
    
    if current_show_state:
        generated_password_entry.config(show="*")
    else:
        generated_password_entry.config(show="")

# eyeball button
eyeball_button = tk.Button(window, text="👁", command=toggle_password_visibility)
eyeball_button.grid(row=1, column=10, pady=10, padx=(0, 10), sticky=tk.W)

# generates and displays a password
def generate_password():
    length = password_length_var.get()  # Get the selected password length
    alphabet = update_alphabet()

    if not alphabet:
        messagebox.showerror("Error", "Please select at least one character type.")
        return

    generated_password = ''.join(secrets.choice(alphabet) for _ in range(length))
    generated_password_entry.delete(0, tk.END)
    generated_password_entry.insert(0, generated_password)
    
def copy_to_clipboard():
    generated_password = generated_password_entry.get()
    window.clipboard_clear()
    window.clipboard_append(generated_password)
    window.update()

label_title = tk.Label(window, text="Proxy's Password Generator", font=("Arial", 14, "bold"))
label_title.place(x=500, y=10)  # Adjust x and y coordinates

# Generates a Password button
button_generate_password = tk.Button(window, text="Generate Password", command=generate_password)
button_generate_password.grid(row=1, column=5, pady=10, padx=10, sticky=tk.W)  # Use sticky to anchor to the west (left)

# entry to show the generated password
generated_password_entry = tk.Entry(window, show="*", width=20)  # Adjust width as needed
generated_password_entry.grid(row=1, column=6, pady=10, padx=(0, 10), sticky=tk.E)  # Adjust column and sticky

# Scale widget for adjusting the password length
password_length_var = tk.IntVar()
password_length_scale = tk.Scale(window, from_=12, to=50, orient=tk.HORIZONTAL, label="Password Length",
                                  length=150, variable=password_length_var)
password_length_scale.set(20)  # Set an initial value
password_length_scale.place(x=670, y=117)  # Adjust x and y coordinates

# Copy button
button_copy = Button(window, text="Copy", command=copy_to_clipboard)
button_copy.grid(row=1, column=9, pady=10, padx=(0, 10), sticky=tk.W)  # Adjust column and sticky

# Checkbuttons for Uppercase, Lowercase, Numbers, and Symbols
uppercase_var = tk.BooleanVar()
lowercase_var = tk.BooleanVar()
numbers_var = tk.BooleanVar()
symbols_var = tk.BooleanVar()

uppercase_checkbox = tk.Checkbutton(window, text="Uppercase", variable=uppercase_var, onvalue=True, offvalue=False)
lowercase_checkbox = tk.Checkbutton(window, text="Lowercase", variable=lowercase_var, onvalue=True, offvalue=False)
numbers_checkbox = tk.Checkbutton(window, text="Numbers", variable=numbers_var, onvalue=True, offvalue=False)
symbols_checkbox = tk.Checkbutton(window, text="Symbols", variable=symbols_var, onvalue=True, offvalue=False)

uppercase_checkbox.grid(row=2, column=5, pady=5, padx=(0, 10), sticky=tk.W)
lowercase_checkbox.grid(row=2, column=6, pady=5, padx=(0, 10), sticky=tk.W)
numbers_checkbox.grid(row=3, column=5, pady=5, padx=(0, 10), sticky=tk.W)
symbols_checkbox.grid(row=3, column=6, pady=5, padx=(0, 10), sticky=tk.W)

recommendation_label = tk.Label(window, text="Recommendation: Check all boxes for a more secure password", font=("Arial", 10, "italic"))
recommendation_label.place(x=430, y=210)  # Adjust x and y coordinates

# Update the alphabet based on checkbox states
def update_alphabet():
    alphabet = ""
    if uppercase_var.get():
        alphabet += string.ascii_uppercase
    if lowercase_var.get():
        alphabet += string.ascii_lowercase
    if numbers_var.get():
        alphabet += string.digits
    if symbols_var.get():
        alphabet += string.punctuation

    return alphabet

# Function to encrypt a file using AES-256-GCM
def encrypt_file_gcm(file_path, password):
    try:
        key = derive_key(password)
        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce

        with open(file_path, "rb") as file:
            plaintext = file.read()

        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        with open(file_path + ".enc", "wb") as file:
            file.write(nonce + ciphertext + tag)

        messagebox.showinfo("Encryption Successful", "File has been successfully encrypted.")
        entry_password.delete(0, END)  # Clear the password entry

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# Function to decrypt a file using AES-256-GCM
def decrypt_file_gcm(file_path, password):
    try:
        key = derive_key(password)

        with open(file_path, "rb") as file:
            data = file.read()

        nonce = data[:16]
        ciphertext = data[16:-16]
        tag = data[-16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_text = cipher.decrypt_and_verify(ciphertext, tag)

        base_path, original_extension = os.path.splitext(os.path.basename(file_path))

        extension = original_extension.replace('.enc', '')

        decrypted_file_path = os.path.join(os.path.dirname(file_path), f"{base_path}_decrypted{extension}")

        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_text)

        print("Decryption Successful") 
        messagebox.showinfo("Decryption Successful", f"File has been successfully decrypted and saved as '{decrypted_file_path}'")
        entry_password.delete(0, END)  

    except ValueError as ve:
        print(f"Decryption Error: {ve}") 
        messagebox.showerror("Decryption Error", str(ve))
    except Exception as e:
        print(f"Error during decryption: {e}")
        messagebox.showerror("Decryption Error", str(e))
        
# Function to encrypt a folder and its contents using AES-256-GCM
def encrypt_folder_gcm(folder_path, password):
    try:
        key = derive_key(password)

        temp_folder_path = os.path.join(os.path.dirname(folder_path), "temp_folder")
        shutil.copytree(folder_path, temp_folder_path)

        zip_file_path = os.path.join(os.path.dirname(folder_path), "temp_folder.zip")
        with ZipFile(zip_file_path, "w") as zip_file:
            for root, _, files in os.walk(temp_folder_path):
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    arcname = os.path.relpath(file_path, temp_folder_path)
                    zip_file.write(file_path, arcname=arcname)

        # Encrypt the zip file
        with open(zip_file_path, "rb") as file:
            plaintext = file.read()

        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        encrypted_zip_file_path = folder_path + "_encrypted.zip.enc"
        with open(encrypted_zip_file_path, "wb") as file:
            file.write(nonce + ciphertext + tag)

        shutil.rmtree(temp_folder_path)
        os.remove(zip_file_path)

        messagebox.showinfo("Encryption Successful", "Folder has been successfully encrypted.")
        entry_password.delete(0, END) 

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# Function to decrypt a folder and its contents using AES-256-GCM
def decrypt_folder_gcm(encrypted_folder_path, password):
    try:
        key = derive_key(password)

        # Decrypt the encrypted zip file
        encrypted_zip_file_path = encrypted_folder_path
        with open(encrypted_zip_file_path, "rb") as file:
            data = file.read()

        nonce = data[:16]
        ciphertext = data[16:-16]
        tag = data[-16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        base_path, _ = os.path.splitext(os.path.basename(encrypted_zip_file_path))

        decrypted_zip_file_path = os.path.join(os.path.dirname(encrypted_zip_file_path), base_path + "_decrypted.zip")
        os.rename(encrypted_zip_file_path, decrypted_zip_file_path)

        with ZipFile(decrypted_zip_file_path, "w") as zip_file:
            zip_file.writestr(base_path, decrypted_data)

        messagebox.showinfo("Decryption Successful", f"Folder has been successfully decrypted and saved.")
        entry_password.delete(0, END) 

    except ValueError as ve:
        messagebox.showerror("Decryption Error", str(ve))
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Function to encrypt an image file using AES-256-GCM
def encrypt_image_gcm(image_path, password):
    try:
        key = derive_key(password)

        with open(image_path, "rb") as file:
            plaintext = file.read()

        cipher = AES.new(key, AES.MODE_GCM)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)

        encrypted_image_path = image_path + "_encrypted.enc"
        with open(encrypted_image_path, "wb") as file:
            file.write(nonce + ciphertext + tag)

        messagebox.showinfo("Encryption Successful", "Image has been successfully encrypted.")
        entry_password.delete(0, END) 

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# Function to decrypt an image file using AES-256-GCM
def decrypt_image_gcm(file_path, password):
    try:
        key = derive_key(password)

        with open(file_path, "rb") as file:
            data = file.read()

        nonce = data[:16]
        ciphertext = data[16:-16]
        tag = data[-16:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        base_path, original_extension = os.path.splitext(os.path.basename(file_path))

        extension = original_extension.replace('.enc', '')

        decrypted_file_path = os.path.join(os.path.dirname(file_path), base_path + "_decrypted" + extension)
        with open(decrypted_file_path, "wb") as decrypted_file:
            decrypted_file.write(decrypted_data)

        messagebox.showinfo("Decryption Successful", f"Image has been successfully decrypted and saved as '{decrypted_file_path}'")
        entry_password.delete(0, END) 

    except ValueError as ve:
        messagebox.showerror("Decryption Error", str(ve))
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))

# Function to handle the Encrypt Image button click
def on_encrypt_image_button_click():
    file_path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.gif")])
    password = entry_password.get()

    if not password:
        messagebox.showerror("Error", "Please provide a password.")
        return

    encrypt_image_gcm(file_path, password)

# Function to handle the Decrypt Image button click
def on_decrypt_image_button_click():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted image files", "*.enc")])
    password = entry_password.get()
    decrypt_image_gcm(file_path, password)

# Function to handle the Encrypt button click
def on_encrypt_button_click():
    file_path = filedialog.askopenfilename()
    password = entry_password.get()

    if not password:
        messagebox.showerror("Error", "Please provide a password.")
        return

    encrypt_file_gcm(file_path, password)

# Function to handle the Decrypt button click
def on_decrypt_button_click():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    password = entry_password.get()
    decrypt_file_gcm(file_path, password)

# Function to handle the Encrypt Folder button click
def on_encrypt_folder_button_click():
    folder_path = filedialog.askdirectory()
    password = entry_password.get()

    if not password:
        messagebox.showerror("Error", "Please provide a password.")
        return

    encrypt_folder_gcm(folder_path, password)

# Function to handle the Decrypt Folder button click
def on_decrypt_folder_button_click():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted folder files", "*.enc")])
    password = entry_password.get()
    decrypt_folder_gcm(file_path, password)

# Toggle variable for light and dark mode
dark_mode = tk.BooleanVar()
dark_mode.set(False) 

# Create a mode label
label_mode = tk.Label(window, text="Encryption Mode: AES-256-GCM")
label_mode.grid(row=0, column=0, pady=10, padx=10, sticky=tk.W)

# Create a toggle button for light and dark mode
toggle_button = tk.Button(window, text="Toggle Theme", command=toggle_mode)
toggle_button.grid(row=0, column=1, pady=10, padx=10, sticky=tk.E)

# Create an Encrypt button
button_encrypt = tk.Button(window, text="Encrypt File", command=on_encrypt_button_click)
button_encrypt.grid(row=2, column=0, pady=5, padx=10, sticky=tk.W)

# Create a Decrypt button
button_decrypt = tk.Button(window, text="Decrypt File", command=on_decrypt_button_click)
button_decrypt.grid(row=2, column=1, pady=10, padx=10, sticky=tk.E)

# Function to handle the "How to Use ⬅ Recommend Reading" button click
def on_how_to_use_click():
    display_instructions()
    
# menu-like frame at the top
menu_frame = tk.Frame(window, bg="#222222", height=30)
menu_frame.grid(row=0, column=0, columnspan=1, sticky="nsew")

# Create a "How to Use" button in the menu-like frame
button_how_to_use = tk.Button(menu_frame, text="How to Use ⬅ Recommend Reading", command=on_how_to_use_click, bg="#222222", fg="#FFFFFF", bd=0)
button_how_to_use.pack(side="left", padx=10)

# Create an Encrypt Image button
button_encrypt_image = tk.Button(window, text="Encrypt Image", command=on_encrypt_image_button_click)
button_encrypt_image.grid(row=3, column=0, pady=5, padx=10, sticky=tk.W)

# Create a Decrypt Image button
button_decrypt_image = tk.Button(window, text="Decrypt Image", command=on_decrypt_image_button_click)
button_decrypt_image.grid(row=3, column=1, pady=10, padx=10, sticky=tk.E)

# Create an Encrypt Folder button
button_encrypt_folder = tk.Button(window, text="Encrypt Folder", command=on_encrypt_folder_button_click)
button_encrypt_folder.grid(row=4, column=0, pady=5, padx=10, sticky=tk.W)

# Create a Decrypt Folder button
button_decrypt_folder = tk.Button(window, text="Decrypt Folder", command=on_decrypt_folder_button_click)
button_decrypt_folder.grid(row=4, column=1, pady=10, padx=10, sticky=tk.E)

# Load the image
encryption_image_path = "images/key.png"
encryption_image = Image.open(encryption_image_path)
encryption_image = ImageTk.PhotoImage(encryption_image)

# Create a Canvas widget to display the image
canvas = tk.Canvas(window, width=100, height=100)  # Adjust width and height as needed
canvas.place(x=130, y=110)  # Manually adjust x and y coordinates

# Manually adjust the position of the image by specifying the x and y coordinates
canvas.create_image(50, 50, anchor=tk.CENTER, image=encryption_image)  # Adjust x and y as needed

# Function to handle the "How to Use ⬅ Recommend Reading " button click
def on_how_to_use_click():
    display_instructions()

# Function to display usage instructions
def display_instructions():
    instructions = """Encrypt/Decrypt:
1. Set Encryption/Decryption Password:

- Enter a strong and secure password in the "Enter Password" field.

2. Toggle Password Visibility:

- Use the 👁 button to toggle visibility for reviewing your entered password.

3. Select Operation:

- Choose between "Encrypt File," "Decrypt File," "Encrypt Image," "Decrypt Image," "Encrypt Folder," and "Decrypt Folder."

4. Select File, image, or Folder:

- Click the respective buttons to choose the file or folder you want to encrypt or decrypt.

5. Execute Operation:

- Click "Encrypt" or "Decrypt" to perform the chosen operation.

6. Review Results:

- Follow on-screen prompts to review successful encryption/decryption messages.

Password Generator:
1. Set Your Secure Password:

- Enter a strong and memorable password in the "Enter Password" field.

2. Toggle Password Visibility:

- Use the 👁 button to toggle visibility for reviewing your entered password.

3. Choose Character Types:

- Select the character types you want in your password: Uppercase, Lowercase, Numbers, and Symbols.

4. Adjust Password Length:

- Use the slider to set the desired password length between 12 and 50 characters.

5. Generate Password:

- Click "Generate Password" to create a secure password based on your preferences.

6. Copy to Clipboard:

- Click "Copy" to copy the generated password to your clipboard for easy use.

Notes:
- For AES-256-GCM mode, a password is required for encryption and decryption.

- Ensure to keep your password secure to maintain the confidentiality of your data. I recommend utilizing KeepassXC for secure password management.

-After decryption, it is essential to remove the '_decrypted' suffix and appropriately adjust the file name. Failure to do so may result in issues opening the file. For instance, if the original file was named 'Test.txt_decrypted,' change it to 'Test_decrypted.txt' or any desired format.

-An efficient approach to handle encryption and decryption is by encrypting an entire folder. This method eliminates the need to manually adjust file names for the process to function seamlessly.
"""
    messagebox.showinfo("How to Use", instructions)
    
# Start the Tkinter event loop
update_colors()  # Set initial colors
window.mainloop()
