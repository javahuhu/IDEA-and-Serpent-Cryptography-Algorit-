from CryptoPlus.Cipher import python_Serpent as SERPENT
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import os
from tkinter import *
from PIL import ImageTk, Image

# Define global variables for input file entry, output file entry, and key entry
input_file_entry = ""
output_file_entry = ""
key_entry = ""

def encrypt_file(input_file, output_file, key):
    cipher = SERPENT.new(key, SERPENT.MODE_ECB)
    with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
        while True:
            chunk = file_in.read(1024)
            if len(chunk) == 0:
                break
            elif len(chunk) % 16 != 0:
                chunk += b' ' * (16 - len(chunk) % 16)
            file_out.write(cipher.encrypt(chunk))


def decrypt_file(input_file, output_file, key):
    cipher = SERPENT.new(key, SERPENT.MODE_ECB)
    with open(input_file, 'rb') as file_in, open(output_file, 'wb') as file_out:
        while True:
            chunk = file_in.read(1024)
            if len(chunk) == 0:
                break
            file_out.write(cipher.decrypt(chunk))  


def browse_file(entry_widget):
    filename = filedialog.askopenfilename()
    if valid(filename):
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
    else:
         messagebox.showerror("Error", "Invalid Selected file type. Please select a valid file. Thank You!")


def browse_folder(entry_widget):
    initialdir = os.path.join(os.path.expanduser('~'), 'Desktop')
    foldername = filedialog.askdirectory(initialdir=initialdir)
    entry_widget.delete(0, tk.END)
    entry_widget.insert(0, foldername)


def encrypt():
    global input_file_entry, output_file_entry, key_entry
    
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    key = key_entry.get().encode('utf-8')
    
    if input_file == "" or output_file == "" or key == "":
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    
    if len(key) != 16 :
        messagebox.showerror("Error", "The Key must be 16 Characters.")
        return encrypt
        
  
    if os.path.isfile(input_file):
        encrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", "File Encrypted successfully.")
    else:
        messagebox.showerror("Error", "Input file does not exist.")

def decrypt():
    global input_file_entry, output_file_entry, key_entry
    
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    key = key_entry.get().encode('utf-8')

    if input_file == "" or output_file == "" or key == "":
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    
    if len(key) != 16:
        messagebox.showerror("Error", "The Key must be 16 Characters.")
        return
    
    if os.path.isfile(input_file):
        # Attempt to open the key file
        try:
            with open("key.txt", 'r') as key_file:
                original_key = key_file.read().strip()
        except FileNotFoundError:
            messagebox.showerror("Error", "The key file is not found.")
            return
        
        if key != original_key.encode('utf-8'):
            messagebox.showerror("Error", "Wrong Input Key Provided.")
            return
        
        decrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", "File Decrypted successfully.")
    else:
        messagebox.showerror("Error", "Input file does not exist.")



    
def valid(filename):
    valid_file = ['.csv', '.xls', '.xlsx', '.txt']
    ext = os.path.splitext(filename)[1].lower()
    return ext in valid_file

def serpent():
    global input_file_entry, output_file_entry, key_entry
    
    #Destroy the main window when the serpent encryption is being clicked!
    window.destroy()

    #Main Window for Serpent Cryptography Algorithm 
    root = tk.Tk()
    root.title("Serpent Encryption Tool")
    root.geometry("315x370")
    
    # Input File
    input_file_label = tk.Label(root, text="Input File")
    input_file_label.grid(row=0, column=0, columnspan=7, sticky='w')

    input_img = tk.Label(root, text="img")
    input_img.grid(row=0, column=0, columnspan=7)

    input_file_entry = tk.Entry(root, width=50)
    input_file_entry.grid(row=1, column=1, padx=5, pady=5)

    input_file_button = tk.Button(root, text="Browse", command=lambda: browse_file(input_file_entry))
    input_file_button.grid(row=2, column=0, columnspan=7, padx=5, pady=5)

    # Load the image
    Input_original_image = Image.open("D:\Information Assurance and Security\input.png")

    # Resize the image
    Input_resized_image = Input_original_image.resize((30, 30), resample=Image.LANCZOS)

    # Convert the resized image to PhotoImage
    Input_resized_img = ImageTk.PhotoImage(Input_resized_image)

    # Set the resized image to the label
    input_img.config(image=Input_resized_img)

    # Separator
    seperator = ttk.Separator(root, orient='horizontal')
    seperator.grid(row=3, column=0, columnspan=7, sticky="ew", padx=0, pady=5)

    # Output File
    output_file_label = tk.Label(root, text="Output File")
    output_file_label.grid(row=4, column=0, columnspan=7, sticky='w')

    output_img = tk.Label(root, text="outputimg")
    output_img.grid(row=4, column=0, columnspan=7)

    output_file_entry = tk.Entry(root, width=50)
    output_file_entry.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

    output_file_button = tk.Button(root, text="Browse", command=lambda: browse_file(output_file_entry))
    output_file_button.grid(row=6, column=0, columnspan=7, padx=5, pady=5)

    # Load the image
    output_original_image = Image.open("D:\Information Assurance and Security\output.png")
    
    # Resize the image
    output_resized_image = output_original_image.resize((30, 30), resample=Image.LANCZOS)

    # Convert the resized image to PhotoImage
    output_resized_img = ImageTk.PhotoImage(output_resized_image)

    # Set the resized image to the label
    output_img.config(image=output_resized_img)

    key_Label = tk.Label(root, text="Key")
    key_Label.grid(row=8, column=0, columnspan=2, sticky='w')

    keykey = tk.Label(root, text="image")
    keykey.grid(row=8, column=0, columnspan=7)

    key_entry = tk.Entry(root, width=50)
    key_entry.grid(row=9, column=1, padx=5, pady=5)

    seperator = ttk.Separator(root, orient='horizontal')
    seperator.grid(row=10, column=0, columnspan=7, sticky="ew", padx=0, pady=5)

    # Load the image
    original_image = Image.open("D:\Information Assurance and Security\keychain.png")

    # Resize the image
    resized_image = original_image.resize((30, 30), resample=Image.LANCZOS)

    # Convert the resized image to PhotoImage
    resized_img = ImageTk.PhotoImage(resized_image)

    # Set the resized image to the label
    keykey.config(image=resized_img)

    # Buttons
    encrypt_button = tk.Button(root, text="Encrypt", command=encrypt, bg='white', activebackground='green')
    encrypt_button.grid(row=11, column=0, columnspan=100, padx=60, pady=25, sticky='w')

    decrypt_button = tk.Button(root, text="Decrypt", command=decrypt, bg='white', activebackground='red')
    decrypt_button.grid(row=11, column=1, columnspan=100, padx=200, pady=25, sticky='w')

    root.mainloop()

    








window = tk.Tk()
window.geometry("300x300")
label = tk.Label(window, text="IDEA and SERPENT CRYPTOGRAPHY ALGORITHM")
label.grid(row=2, column=0, columnspan=10, padx=20, pady=50)

idea_button = tk.Button(window,
                     text='IDEA',
                     command="",
                     width=15,
                     height=3)
idea_button.grid(row=3, column=0, columnspan=5, padx=20, pady=0)

serpent_button = tk.Button(window,
                        text='Serpent',
                        command=serpent,
                        width=15,
                        height=3,)
serpent_button.grid(row=3, column=6, padx=5, pady=50)




window.mainloop()
