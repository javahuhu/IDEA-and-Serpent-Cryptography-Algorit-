from library import *
import random
import tkinter as tk
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
import sys, os
import numpy as np
from PIL import Image
import io
import codecs
from CryptoPlus.Cipher import python_Serpent as SERPENT
import tkinter as tk
from tkinter import ttk
from tkinter import filedialog
from tkinter import messagebox
import os
from PIL import ImageTk, Image
import binascii

def clear_entries():
    response = messagebox.askyesno("Confirmation", "Are you sure you want to clear?")
    if response:
        input_file_entry.delete(0, tk.END)
        output_file_entry.delete(0, tk.END)
        key_entry.delete(0, tk.END)

        messagebox.showinfo("Success", "Successfully Cleared")
    else:
        # Do nothing
        pass

def Back():
    global window
    window = tk.Tk()
    window.geometry("405x280")
    title = key_entry
    window.title("IDEA and Serpent Cryptography Algorithm")
    window.config(bg='#8FD7C7')

    input_img_window = tk.Label(window, text="img", bg='#8FD7C7')
    input_img_window.grid(row=1, column=0, columnspan=7, padx=123, pady=20, sticky = 'w')

    # Load the image
    Input_original_image_window = Image.open("D:\Information Assurance and Security\security.png")
   
    Input_resized_image_window = Input_original_image_window.resize((150, 150), resample=Image.LANCZOS)
  
    Input_resized_img_w = ImageTk.PhotoImage(Input_resized_image_window)
   
    input_img_window.config(image=Input_resized_img_w)

    

    input_img1_window1 = tk.Label(window, text="img1", bg='#8FD7C7')
    input_img1_window1.grid(row=1, column=0, columnspan=7, padx=40, pady=20, sticky = 'w')

    
   
    Input_original_image_window1 = Image.open("D:\Information Assurance and Security\secured-lock.png")

    Input_resized_image_window1 = Input_original_image_window1.resize((50, 50), resample=Image.LANCZOS)
 
    Input_resized_img_w1 = ImageTk.PhotoImage(Input_resized_image_window1)
 
    input_img1_window1.config(image=Input_resized_img_w1)



    input_img1_window2 = tk.Label(window, text="img2", bg='#8FD7C7')
    input_img1_window2.grid(row=1, column=0, columnspan=320, padx=303, pady=20, sticky = 'w')

    

    Input_original_image_window2 = Image.open(r"D:\Information Assurance and Security\unlock.png")
  
    Input_resized_image_window2 = Input_original_image_window2.resize((50, 50), resample=Image.LANCZOS)
  
    Input_resized_img_w2 = ImageTk.PhotoImage(Input_resized_image_window2)
  
    input_img1_window2.config(image=Input_resized_img_w2)

    button_font = ("Tahoma", 10, "bold")
    idea_button = tk.Button(window,
                         text='IDEA',
                         command=idea,
                         width=15,
                         height=3, 
                         bg='#B8DAFF',  
                         activebackground='white',
                         font=button_font)
    idea_button.grid(row=2, column=0, columnspan=5, padx=37, pady=0, sticky = 'w')

    serpent_button = tk.Button(window,
                            text='Serpent',
                            command=serpents,
                            width=15,
                            height=3,
                            bg='#B8DAFF',  
                            activebackground='white',font=button_font)
    serpent_button.grid(row=2, column=6, padx=0, pady=0, sticky = 'w')

    window.mainloop()




def read_image(image_path):
    image = Image.open(image_path)
    height, width = image.size

    return height, width
def image_to_binary(image_path):
   with open(image_path, 'rb') as file:
    image_data = file.read()
    data = binascii.hexlify(image_data)

    binary = bin(int(data, 16))
    binary = binary[2:].zfill(32)
    return binary

def binary_to_image(binary_data, height, width):
   
    # Assuming 'binary_data' is your binary pixel data
    # 'width' and 'height' are the dimensions of the image
    # 'mode' is the mode of the image (e.g., 'RGB' for color images
    # Convert binary data to numpy array
    binary_data = np.frombuffer(binary_data, dtype=np.uint8)
    # Reshape numpy array to match image dimensions
    image_array = binary_data.reshape((height, width, len(mode)))

    # Create PIL image from numpy array
    image = Image.fromarray(image_array, mode)

    # Save PIL image to PNG file
    image.save("output.png")

def idea_algo(block, key, mode):
    block_length = len(block)
    remainder = block_length % 64
    if block_length % 64 != 0:
        block += '0' * (64 - remainder)  # Fill with '0's to make the total length a multiple of 64

    chunks = [block[i:i+64] for i in range(0, len(block), 64)]
    
    result = ""
    for binaryData in chunks:
        X = split_into_x_parts_of_y(binaryData, 4, 16)

        Z = generate_subkeys(key)
        if mode == 1:
            Z = generate_decrypt_keys(Z) 

        #  8 Rounds
        for i in range(8):
            multiplier = i * 6

            one = m_mul(X[0], Z[multiplier + 0])
            two = m_sum(X[1], Z[multiplier + 1])
            three = m_sum(X[2], Z[multiplier + 2])
            four = m_mul(X[3], Z[multiplier + 3])

            five = XOR(one, three)
            six = XOR(two, four)
            seven = m_mul(five, Z[multiplier + 4])
            eight = m_sum(six, seven)
            nine = m_mul(eight, Z[multiplier + 5])
            ten = m_sum(seven, nine)
            eleven = XOR(one, nine)
            twelve = XOR(three, nine)
            thirteen = XOR(two, ten)
            fourteen = XOR(four, ten)
            if i == 7:
                X = [eleven, thirteen, twelve, fourteen]
            else:
                X = [eleven, twelve, thirteen, fourteen]

        # Output pre-processing (half-round)    
        X[0] = m_mul(X[0], Z[48])
        X[1] = m_sum(X[1], Z[49])
        X[2] = m_sum(X[2], Z[50])
        X[3] = m_mul(X[3], Z[51])
        
        # Append the result of this chunk to the overall result
        result += ''.join(X)
    print("Key:\t" + key)
    return result
#Allow a file that only consist of png and jpg
def valid1(filename1):
    valid_file1 = ['.png', '.jpg']
    ext1 = os.path.splitext(filename1)[1].lower()
    return ext1 in valid_file1

def browse_idea_file(entry_widget):
    filename = filedialog.askopenfilename()
    if valid1(filename):
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
    else:
        messagebox.showerror("Error", "Invalid Selected file type for IDEA. Please select a valid image file (JPG or PNG).")


def display_private_key(private_key):
    private_key_window = tk.Toplevel()
    private_key_window.title("Generated Random Private Key")
    private_key_window.geometry("1000x200")
    private_key_window.config(bg='black')
    
    private_key_label = tk.Label(private_key_window, text=f"Private Key: {private_key}", fg='#8FD7C7', bg='black')
    private_key_label.pack(pady=20)
    
    ok_button = tk.Button(private_key_window, text="OK", command=private_key_window.destroy)
    ok_button.pack()


def encrypt_and_display_private_key():
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
        private_key = int2bits(random.randint(1, pow(2, 128)))
        encrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", "Successfully Encrypted")
        
        # Display the private key in a new window
     

    else:
        messagebox.showerror("Error", "Input file does not exist.")

    private_key = int2bits(random.randint(1, pow(2, 128)))
    display_private_key(private_key)








def decrypt():
    global input_file_entry, output_file_entry, key_entry
    
    input_file = input_file_entry.get()
    output_file = output_file_entry.get()
    key = key_entry.get().encode('utf-8')
    new_key = key.decode('utf-8')

    if input_file == "" or output_file == "" or key_entry == "":
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    
    if os.path.isfile(input_file):
        binary_series,= image_to_binary(input_file)
        height, width = read_image(input_file)
        result = idea_algo(binary_series, new_key, 1)
        hexData = binary_to_image(result, height, width)
        print(hexData)
        with open(output_file, 'wb') as file_out:
            file_out.write(hexData)
        
        messagebox.showinfo("Success", "File Decrypted successfully.")
    else:
        messagebox.showerror("Error", "Input file does not exist.")


    

def idea():

    #Destroy the main window when the serpent encryption is being click!
    window.destroy()
    global input_file_entry, output_file_entry, key_entry, private_key_label
    #Main Window for Serpent Cryptography Algorithm 
    IDEA = Tk()
    IDEA.geometry("315x470")
    IDEA.config(bg='#8FD7C7')
    IDEA.title("IDEA Encryption Tool")

    

  
    button_font = ("Tahoma", 10, "bold")
    # Input File
    input_file_label = tk.Label(IDEA, text="Input File", bg='#8FD7C7', font=button_font, fg='#253226' )
    input_file_label.grid(row=0, column=0, columnspan=7, sticky='w')

    input_img = tk.Label(IDEA, text="img", bg='#8FD7C7')
    input_img.grid(row=0, column=0, columnspan=7, pady=5)

    style = ttk.Style()
    style.configure("TSeparator", background='black') 
  
    Input_original_image = Image.open("D:\Information Assurance and Security\input.png")

  
    Input_resized_image = Input_original_image.resize((60, 60), resample=Image.LANCZOS)

 
    Input_resized_imgage = ImageTk.PhotoImage(Input_resized_image)

    input_img.config(image=Input_resized_imgage)


    input_file_entry = tk.Entry(IDEA, width=50)
    input_file_entry.grid(row=1, column=1, padx=5, pady=5)

    input_file_button = tk.Button(IDEA, text="Browse", command=lambda: browse_idea_file(input_file_entry))
    input_file_button.grid(row=2, column=0, columnspan=7, padx=5, pady=5)

  
    Input_original_image_browse = Image.open(r"D:\Information Assurance and Security\upload.png")

    
    Input_resized_image_browse = Input_original_image_browse.resize((20, 20), resample=Image.LANCZOS)

  
    Input_resized_image_browse = ImageTk.PhotoImage(Input_resized_image_browse)


    input_file_button.config(image=Input_resized_image_browse)

 
    seperator = ttk.Separator(IDEA, orient='horizontal')
    seperator.grid(row=3, column=0, columnspan=7, sticky="ew", padx=0, pady=5)

   
    output_file_label = tk.Label(IDEA, text="Output File", bg='#8FD7C7', font=button_font,  fg='#253226')
    output_file_label.grid(row=4, column=0, columnspan=7, sticky='w')

    output_img = tk.Label(IDEA, text="outputimg", bg='#8FD7C7')
    output_img.grid(row=4, column=0, columnspan=7)

    output_original_image = Image.open("D:\Information Assurance and Security\output.png")
    
  
    output_resized_image = output_original_image.resize((60, 60), resample=Image.LANCZOS)


    output_resized_img = ImageTk.PhotoImage(output_resized_image)

   
    output_img.config(image=output_resized_img)

    output_file_entry = tk.Entry(IDEA, width=50)
    output_file_entry.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

    output_file_button = tk.Button(IDEA, text="Browse", command=lambda: browse_idea_file(output_file_entry))
    output_file_button.grid(row=6, column=0, columnspan=7, padx=5, pady=5)

    output_original_image_browse = Image.open(r"D:\Information Assurance and Security\upload.png")
    
   
    output_resized_image_browse = output_original_image_browse.resize((20, 20), resample=Image.LANCZOS)

   
    output_resized_image_browse = ImageTk.PhotoImage(output_resized_image_browse)

 
    output_file_button.config(image=output_resized_image_browse)

  
    seperator = ttk.Separator(IDEA, orient='horizontal')
    seperator.grid(row=7, column=0, columnspan=7, sticky="ew", padx=0, pady=5)


    key_Label = tk.Label(IDEA, text="Name", bg='#8FD7C7', font=button_font, fg='#253226')
    key_Label.grid(row=8, column=0, columnspan=2, sticky='w')

    keykey = tk.Label(IDEA, text="image", bg='#8FD7C7')
    keykey.grid(row=8, column=0, columnspan=7)

    key_entry = tk.Entry(IDEA, width=50)
    key_entry.grid(row=9, column=1, padx=5, pady=5)

    private_key_label = tk.Label(IDEA, text="", bg='#8FD7C7')
    private_key_label.grid(row=12, column=0, columnspan=7, padx=5, pady=5)


    
    seperator = ttk.Separator(IDEA, orient='horizontal')
    seperator.grid(row=10, column=0, columnspan=7, sticky="ew", padx=0, pady=5)

   
    original_image = Image.open("D:\Information Assurance and Security\keychain.png")

   
    resized_image = original_image.resize((60, 60), resample=Image.LANCZOS)

   
    resized_img = ImageTk.PhotoImage(resized_image)


    keykey.config(image=resized_img)

    


    encrypt_button = tk.Button(IDEA, text="Encrypt", command=lambda: encrypt_and_display_private_key(),  bg='#B8DAFF',  activebackground='white',)
    encrypt_button.grid(row=11, column=0, columnspan=100, padx=40, pady=25, sticky='w')
    
    Back_button = tk.Button(IDEA, text="Back", command=lambda: [IDEA.destroy(), Back()],  bg='#B8DAFF', activebackground='white',)
    Back_button.grid(row=11, column=1, columnspan=100, padx=150, pady=27, sticky='w')

    clear_button = tk.Button(IDEA, text='Clear', command=clear_entries, bg='#D0494A', activebackground='white')
    clear_button.grid(row=11, column=1, columnspan=300, padx=250, pady=0, sticky='w')

    #private_button = tk.Button(IDEA, text="Private Key", command=display_private_key,  bg='#B8DAFF', activebackground='white',)
    #private_button.grid(row=11, column=1, columnspan=100, padx=10, pady=27, sticky='w')



    IDEA.mainloop()

    

    


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
            decrypted_chunk = cipher.decrypt(chunk)
            file_out.write(decrypted_chunk.rstrip(b' '))  # Remove padding if added during encryption


def browse_file(entry_widget):
    filename = filedialog.askopenfilename()
    if valid2(filename):
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
    else:
         messagebox.showerror("Error", "Invalid Selected file type for Serpent. Please select a valid file ('.csv', '.xls', '.xlsx', '.txt')")


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
    
    if len(key) != 16 :
        messagebox.showerror("Error", "The Key must be 16 Characters.")
        return decrypt
        
    
    
    if os.path.isfile(input_file):
        original_key = key
        if key != original_key:
             messagebox.showinfo("Success", "Wrong Input Key Provided.")
        decrypt_file(input_file, output_file, key)
        messagebox.showinfo("Success", "File Decrypted successfully.")
        
    else:
        messagebox.showerror("Error", "input file does not exist.")

#Check if the file is only consist of csv, xls, xlsx, txt
def valid2(filename):
    valid_file2 = ['.csv', '.xls', '.xlsx', '.txt']
    ext2 = os.path.splitext(filename)[1].lower()
    return ext2 in valid_file2


def serpents():
    global input_file_entry, output_file_entry, key_entry
    
    #Destroy the main window when the serpent encryption is being clicked!
    window.destroy()

    #Main Window for Serpent Cryptography Algorithm 
    serpent = tk.Tk()
    serpent.title("Serpent Encryption Tool")
    serpent.geometry("315x470")
    serpent.config(bg='#8FD7C7')
    
    button_font = ("Tahoma", 10, "bold")
    # Input File
    input_file_label = tk.Label(serpent, text="Input File", bg='#8FD7C7', font=button_font, fg='#253226' )
    input_file_label.grid(row=0, column=0, columnspan=7, sticky='w')

    input_img = tk.Label(serpent, text="img", bg='#8FD7C7')
    input_img.grid(row=0, column=0, columnspan=7, pady=5)

    style = ttk.Style()
    style.configure("TSeparator", background='black') 
    # Load the image
    Input_original_image = Image.open("D:\Information Assurance and Security\input.png")

    # Resize the image
    Input_resized_image = Input_original_image.resize((60, 60), resample=Image.LANCZOS)

    # Convert the resized image to PhotoImage
    Input_resized_imgage = ImageTk.PhotoImage(Input_resized_image)

    # Set the resized image to the label
    input_img.config(image=Input_resized_imgage)


    input_file_entry = tk.Entry(serpent, width=50)
    input_file_entry.grid(row=1, column=1, padx=5, pady=5)

    input_file_button = tk.Button(serpent, text="Browse", command=lambda: browse_file(input_file_entry))
    input_file_button.grid(row=2, column=0, columnspan=7, padx=5, pady=5)

    #for browse button
    Input_original_image_browse = Image.open(r"D:\Information Assurance and Security\upload.png")

    # Resize the image
    Input_resized_image_browse = Input_original_image_browse.resize((20, 20), resample=Image.LANCZOS)

    # Convert the resized image to PhotoImage
    Input_resized_image_browse = ImageTk.PhotoImage(Input_resized_image_browse)

    # Set the resized image to the label
    input_file_button.config(image=Input_resized_image_browse)

    # Separator
    seperator = ttk.Separator(serpent, orient='horizontal')
    seperator.grid(row=3, column=0, columnspan=7, sticky="ew", padx=0, pady=5)

    # Output File
    output_file_label = tk.Label(serpent, text="Output File", bg='#8FD7C7', font=button_font,  fg='#253226')
    output_file_label.grid(row=4, column=0, columnspan=7, sticky='w')

    output_img = tk.Label(serpent, text="outputimg", bg='#8FD7C7')
    output_img.grid(row=4, column=0, columnspan=7)

    output_original_image = Image.open("D:\Information Assurance and Security\output.png")
    
    output_resized_image = output_original_image.resize((60, 60), resample=Image.LANCZOS)


    output_resized_img = ImageTk.PhotoImage(output_resized_image)

    
    output_img.config(image=output_resized_img)

    output_file_entry = tk.Entry(serpent, width=50)
    output_file_entry.grid(row=5, column=0, columnspan=3, padx=5, pady=5)

    output_file_button = tk.Button(serpent, text="Browse", command=lambda: browse_file(output_file_entry))
    output_file_button.grid(row=6, column=0, columnspan=7, padx=5, pady=5)

    output_original_image_browse = Image.open(r"D:\Information Assurance and Security\upload.png")
    
   
    output_resized_image_browse = output_original_image_browse.resize((20, 20), resample=Image.LANCZOS)

  
    output_resized_image_browse = ImageTk.PhotoImage(output_resized_image_browse)

  
    output_file_button.config(image=output_resized_image_browse)

 
    seperator = ttk.Separator(serpent, orient='horizontal')
    seperator.grid(row=7, column=0, columnspan=7, sticky="ew", padx=0, pady=5)


    key_Label = tk.Label(serpent, text="Key", bg='#8FD7C7', font=button_font, fg='#253226')
    key_Label.grid(row=8, column=0, columnspan=2, sticky='w')

    keykey = tk.Label(serpent, text="image", bg='#8FD7C7')
    keykey.grid(row=8, column=0, columnspan=7)

    key_entry = tk.Entry(serpent, width=50)
    key_entry.grid(row=9, column=1, padx=5, pady=5)

    seperator = ttk.Separator(serpent, orient='horizontal')
    seperator.grid(row=10, column=0, columnspan=7, sticky="ew", padx=0, pady=5)

   
    original_image = Image.open("D:\Information Assurance and Security\keychain.png")

    
    resized_image = original_image.resize((60, 60), resample=Image.LANCZOS)

    resized_img = ImageTk.PhotoImage(resized_image)

   
    keykey.config(image=resized_img)


    encrypt_button = tk.Button(serpent, text="Encrypt", command=encrypt,  bg='#B8DAFF',  activebackground='white',)
    encrypt_button.grid(row=11, column=0, columnspan=60, padx=23, pady=25, sticky='w')

    decrypt_button = tk.Button(serpent, text="Decrypt", command=decrypt,  bg='#B8DAFF',   activebackground='white',)
    decrypt_button.grid(row=11, column=1, columnspan=60, padx=100, pady=25, sticky='w')

    Exit_button = tk.Button(serpent, text="Back", command=lambda: [serpent.destroy(), Back()],  bg='#B8DAFF',  activebackground='white',)
    Exit_button.grid(row=11, column=1, columnspan=100, padx=185, pady=27, sticky='w')

    clear_button = tk.Button(serpent, text='Clear', command=clear_entries, bg='#D0494A', activebackground='white')
    clear_button.grid(row=11, column=1, columnspan=300, padx=250, pady=0, sticky='w')

    serpent.mainloop()





def main():
    global window
    window = tk.Tk()
    window.geometry("405x280")
    window.title("IDEA and Serpent Cryptography Algorithm")
    Font_tuple = ("Comic Sans MS", 12, "bold") 
    window.config(bg='#8FD7C7')

    input_img_window = tk.Label(window, text="img", bg='#8FD7C7')
    input_img_window.grid(row=1, column=0, columnspan=7, padx=122, pady=20, sticky = 'w')

    
    
    Input_original_image_window = Image.open("D:\Information Assurance and Security\security.png")
  
    Input_resized_image_window = Input_original_image_window.resize((150, 150), resample=Image.LANCZOS)
   
    Input_resized_img_w = ImageTk.PhotoImage(Input_resized_image_window)
  
    input_img_window.config(image=Input_resized_img_w)




    input_img1_window1 = tk.Label(window, text="img1", bg='#8FD7C7')
    input_img1_window1.grid(row=1, column=0, columnspan=7, padx=40, pady=20, sticky = 'w')

    
    
    Input_original_image_window1 = Image.open("D:\Information Assurance and Security\secured-lock.png")
 
    Input_resized_image_window1 = Input_original_image_window1.resize((50, 50), resample=Image.LANCZOS)
    
    Input_resized_img_w1 = ImageTk.PhotoImage(Input_resized_image_window1)
  
    input_img1_window1.config(image=Input_resized_img_w1)



    input_img1_window2 = tk.Label(window, text="img2", bg='#8FD7C7')
    input_img1_window2.grid(row=1, column=0, columnspan=320, padx=303, pady=20, sticky = 'w')

    
  
    Input_original_image_window2 = Image.open(r"D:\Information Assurance and Security\unlock.png")
  
    Input_resized_image_window2 = Input_original_image_window2.resize((50, 50), resample=Image.LANCZOS)
    
    Input_resized_img_w2 = ImageTk.PhotoImage(Input_resized_image_window2)
 
    input_img1_window2.config(image=Input_resized_img_w2)
    button_font = ("Tahoma", 10, "bold")
    idea_button = tk.Button(window,
                         text='IDEA',
                         command=idea,
                         width=15,
                         height=3, 
                         bg='#B8DAFF',  
                         activebackground='white',
                         font=button_font,
                        )
    idea_button.grid(row=2, column=0, columnspan=5, padx=37, pady=0, sticky = 'w')

    serpent_button = tk.Button(window,
                            text='Serpent',
                            command=serpents,
                            width=15,
                            height=3,
                            bg='#B8DAFF',  
                            activebackground='white',font=button_font)
    serpent_button.grid(row=2, column=6, padx=0, pady=0, sticky = 'w')

    window.mainloop()

if __name__ == "__main__":
    main()