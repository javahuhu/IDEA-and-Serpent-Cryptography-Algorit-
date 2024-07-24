from library import *
import random
import tkinter as tk
from tkinter import Tk, Label, Entry, Button, filedialog, messagebox
import sys, os
import numpy as np
from PIL import Image
import io
import codecs
import binascii


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

def browse_img(entry_widget):
    filename = filedialog.askopenfilename()
    if valid(filename):
        entry_widget.delete(0, tk.END)
        entry_widget.insert(0, filename)
    else:
         messagebox.showerror("Error", "Invalid Selected file type. Please select a valid file. Thank You!")

def valid(filename):
    valid_file = ['.jpg', '.png']
    ext = os.path.splitext(filename)[1].lower()
    return ext in valid_file

def encrypt():
    global input_img_entry, output_img_entry, key_img
    
    input_file = input_img_entry.get()
    output_file = output_img_entry.get()


    if input_file == "" or output_file == "":
        messagebox.showerror("Error", "Please fill in all fields.")
        return
    
    if os.path.isfile(input_file):
        binary_series= image_to_binary(input_file)
        height, width = read_image(input_file)
        private_key = int2bits(random.randint(1, pow(2, 128)))
        result = idea_algo(binary_series, private_key, 0)
        var = binary_to_image(result, height, width)
        with open(output_file, 'wb') as file_out:
            file_out.write(var)
        

        messagebox.showinfo("Success", "File Encrypted successfully.")
    else:
        messagebox.showerror("Error", "Input file does not exist.")

def decrypt():
    global input_img_entry, output_img_entry, key_img
    
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
    global input_img_entry, output_img_entry, key_img
    #Main Window for Serpent Cryptography Algorithm 
    root = Tk()
    root.title("File Encryption Tool")

    # Input File
    input_file_label = Label(root, text="Input File:")
    input_file_label.grid(row=0, column=0, sticky="e")

    input_file_entry = Entry(root, width=50)
    input_file_entry.grid(row=0, column=1, padx=5, pady=5)

    input_file_button = Button(root, text="Browse", command= lambda: browse_img(input_img_entry))
    input_file_button.grid(row=0, column=2, padx=5, pady=5)

    # Output File
    output_file_label = Label(root, text="Output File:")
    output_file_label.grid(row=1, column=0, sticky="e")

    output_file_entry = Entry(root, width=50)
    output_file_entry.grid(row=1, column=1, padx=5, pady=5)

    output_file_button = Button(root, text="Browse", command= lambda: browse_img(output_img_entry))
    output_file_button.grid(row=1, column=2, padx=5, pady=5)

    # Encryption Key
    key_label = Label(root, text="Encryption Key:")
    key_label.grid(row=2, column=0, sticky="e")

    key_entry = Entry(root, width=50)
    key_entry.grid(row=2, column=1, padx=5, pady=5)

    # Buttons
    encrypt_button = Button(root, text="Encrypt", command= encrypt)
    encrypt_button.grid(row=3, column=0, columnspan=2, padx=5, pady=10)

    decrypt_button = Button(root, text="Decrypt", command= decrypt)
    decrypt_button.grid(row=3, column=1, columnspan=3, padx=5, pady=10)
    
    root.mainloop()



if __name__ == '__main__':
    # Prompt the user for mode (e/d) and data
    mode = input("Enter mode (e for encryption, d for decryption): ")
    data = input("Enter data (message for encryption or private key for decryption): ")

    if mode == "e":
        data = str_to_bits(data)
        private_key = int2bits(random.randint(1, pow(2, 128)))
    elif mode == "d":
        private_key = input("Enter private key: ")
    else:
        raise Exception("Incorrect parameter")

    # IDEA encryption/decryption
    result = idea_algo(data, private_key, mode)

    # Display the result
    if mode == "e":
        print("Key:\t" + private_key)
    else:
        result = decode_binary_string(result)
    
    print("Output:\t" + result)