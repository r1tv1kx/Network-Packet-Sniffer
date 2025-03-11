import tkinter as tk
from tkinter import messagebox, ttk
import os

# Suppress Tkinter deprecation warning on macOS
os.environ["TK_SILENCE_DEPRECATION"] = "1"

# Caesar cipher logic
letters = 'abcdefghijklmnopqrstuvwxyz'

def encrypt(text, key):
    return ''.join(
        letters[(letters.index(letter.lower()) + key) % 26] if letter.lower() in letters else letter for letter in text
    )

def decrypt(ciphertext, key):
    return ''.join(
        letters[(letters.index(letter.lower()) - key) % 26] if letter.lower() in letters else letter for letter in ciphertext
    )

def perform_action():
    action = action_var.get()
    text = text_entry.get("1.0", tk.END).strip()
    key = key_entry.get().strip()

    if not key.isdigit() or not (1 <= int(key) <= 26):
        messagebox.showerror("Invalid Key", "Key must be an integer between 1 and 26.")
        return

    key = int(key)
    result = encrypt(text, key) if action == "Encrypt" else decrypt(text, key)

    result_text.delete("1.0", tk.END)
    result_text.insert(tk.END, result)

# Create the main window
root = tk.Tk()
root.title("Caesar Cipher")

# Main frame
main_frame = ttk.Frame(root, padding=20)
main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Action frame
action_frame = ttk.Labelframe(main_frame, text="Action", padding=10)
action_frame.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)

action_var = tk.StringVar(value="Encrypt")
encrypt_radio = ttk.Radiobutton(action_frame, text="Encrypt", variable=action_var, value="Encrypt")
decrypt_radio = ttk.Radiobutton(action_frame, text="Decrypt", variable=action_var, value="Decrypt")
encrypt_radio.grid(row=0, column=0, padx=10)
decrypt_radio.grid(row=0, column=1, padx=10)

# Key frame
key_frame = ttk.Frame(main_frame, padding=10)
key_frame.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)

ttk.Label(key_frame, text="Key (1-26):").grid(row=0, column=0, padx=10)
key_entry = ttk.Entry(key_frame, width=5)
key_entry.grid(row=0, column=1, padx=10)

# Text and result frames in landscape view
text_result_frame = ttk.Frame(main_frame, padding=10)
text_result_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=10, sticky=(tk.W, tk.E))

ttk.Label(text_result_frame, text="Enter text:").grid(row=0, column=0, padx=10)
text_entry = tk.Text(text_result_frame, height=10, width=40)
text_entry.grid(row=1, column=0, padx=10, pady=5)

ttk.Label(text_result_frame, text="Result:").grid(row=0, column=1, padx=10)
result_text = tk.Text(text_result_frame, height=10, width=40)
result_text.grid(row=1, column=1, padx=10, pady=5)

# Perform Action button
action_button = ttk.Button(main_frame, text="Perform Action", command=perform_action)
action_button.grid(row=2, column=0, columnspan=2, pady=10)

# Start the main loop
root.mainloop()
