# proxycrypt
ProxyCrypt is a Python-based graphical user interface (GUI) application that provides functionality for secure file encryption, decryption, and password generation. The application is built using the Tkinter library for the GUI and includes encryption support using the AES-256-GCM mode.

Table of Contents
Features
Getting Started

## File Encryption/Decryption: 
Securely encrypt and decrypt files using the AES-256-GCM encryption mode.

## Folder Encryption/Decryption: 
Encrypt and decrypt entire folders and their contents for easy and efficient data protection.

## Image Encryption/Decryption: 
Apply encryption to image files while maintaining their integrity during decryption.

## Password Generation: 
Generate strong and secure passwords with customizable options.

## Getting Started
Prerequisites
Ensure you have the following installed on your machine:

Python (3.6 or above)
Tkinter library
Pillow library (pip install Pillow)
PyCryptodome library (pip install pycryptodome)
zxcvbn library (pip install zxcvbn)

Clone the repository:

git clone https://github.com/proxy0x/proxycrypt.git

Navigate to the project directory:

cd proxycrypt

Run the application:

python proxycrypt.py

## How to Use:

## Encryption/Decryption

- Set Encryption/Decryption Password

- Enter a strong and secure password in the "Enter Password" field.
  
- Use the 👁 button to toggle visibility for reviewing your entered password.
- 
-Choose between "Encrypt File," "Decrypt File," "Encrypt Image," "Decrypt Image," "Encrypt Folder," and "Decrypt Folder."

- Select File, Image, or Folder

- Click the respective buttons to choose the file or folder you want to encrypt or decrypt.

- Click "Encrypt" or "Decrypt" to perform the chosen operation.
  
Review Results:

- Follow on-screen prompts to review successful encryption/decryption messages.

## Password Generator
Set Your Secure Password:

- Enter a strong and memorable password in the "Enter Password" field.

Toggle Password Visibility:

- Use the 👁 button to toggle visibility for reviewing your entered password.
  
Choose Character Types:

- Select the character types you want in your password: Uppercase, Lowercase, Numbers, and Symbols.
  
Adjust Password Length:

- Use the slider to set the desired password length between 12 and 50 characters.
  
Generate Password:

- Click "Generate Password" to create a secure password based on your preferences.
  
Copy to Clipboard:

- Click "Copy" to copy the generated password to your clipboard for easy use.
  
## Notes: 

- For AES-256-GCM mode, a password is required for encryption and decryption.

- Ensure to keep your password secure to maintain the confidentiality of your data. I recommend utilizing KeepassXC for secure password management.

- After decryption, it is essential to remove the '_decrypted' suffix and appropriately adjust the file name. Failure to do so may result in issues opening the file. For instance, if the original file was named 'Test.txt_decrypted,' change it to 'Test_decrypted.txt' or any desired format.

- An efficient approach to handle encryption and decryption is by encrypting an entire folder. This method eliminates the need to manually adjust file names for the process to function seamlessly.

## Contributing
Feel free to contribute to the project by opening issues or submitting pull requests. Your contributions are welcome!

## License
This project is licensed under the MIT License - see the LICENSE file for details.
