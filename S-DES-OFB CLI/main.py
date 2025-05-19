import os
import secrets
import argparse
from colorama import init, Fore, Style, Back
from utils.constants import P10, P8, IP, IP_INV
from utils.helpers import draw_table,log_full_details, permute, shift_left, fk, switch

# Initialize colorama (styled console library)
init()

def generate_subkeys(key):
    if len(key) != 10 or not set(key) <= {'0','1'}:
        raise ValueError("Key must be 10-bit binary string")

    p10_key = permute(key, P10)

    left_key = shift_left(p10_key[:5], 1)
    right_key = shift_left(p10_key[5:], 1)

    subkey_k1 = permute(left_key + right_key, P8)

    left_key = shift_left(left_key, 2)
    right_key = shift_left(right_key, 2)

    return subkey_k1, permute(left_key + right_key, P8)

def sdes_encrypt(plaintext_8bit, key_10bit):
    if len(plaintext_8bit) != 8 or any(c not in '01' for c in plaintext_8bit):
        raise ValueError("Plaintext must be 8-bit binary string")
    k1, k2 = generate_subkeys(key_10bit)
    ip_bits = permute(plaintext_8bit, IP)
    first_fk = fk(ip_bits, k1)
    switched = switch(first_fk)
    second_fk = fk(switched, k2)
    ciphertext = permute(second_fk, IP_INV)
    return ciphertext

def ofb_encrypt(plaintext_bytes, key_10bit, iv_8bit):
    if len(iv_8bit) != 8 or any(c not in '01' for c in iv_8bit):
        raise ValueError("IV must be 8-bit binary string")
    ciphertext = bytearray()
    feedback = iv_8bit
    for byte in plaintext_bytes:
        keystream_bits = sdes_encrypt(feedback, key_10bit)
        keystream_byte = int(keystream_bits, 2)
        ciphertext.append(byte ^ keystream_byte)
        feedback = keystream_bits
    return bytes(ciphertext)

def ofb_decrypt(ciphertext_bytes, key_10bit, iv_8bit):
    if len(iv_8bit) != 8 or any(c not in '01' for c in iv_8bit):
        raise ValueError("IV must be 8-bit binary string")
    plaintext = bytearray()
    feedback = iv_8bit
    for byte in ciphertext_bytes:
        keystream_bits = sdes_encrypt(feedback, key_10bit)
        keystream_byte = int(keystream_bits, 2)
        plaintext.append(byte ^ keystream_byte)
        feedback = keystream_bits
    return bytes(plaintext)

def brute_force_attack(known_plaintext_bytes, known_ciphertext_bytes, iv_8bit):
    print("Starting brute force attack...")
    for key_int in range(1024):
        key = format(key_int, '010b')
        try:
            encrypted = ofb_encrypt(known_plaintext_bytes, key, iv_8bit)
            if encrypted == known_ciphertext_bytes:
                print(f"Key found: {key}")
                return key
        except Exception:
            continue
    print("Key not found in keyspace.")
    return None

def cryptanalysis_attack(plaintext_ciphertext_pairs, iv_8bit):
    print("Starting cryptanalysis attack with known plaintext-ciphertext pairs...")
    for key_int in range(1024):
        key = format(key_int, '010b')
        try:
            if all(ofb_encrypt(pt, key, iv_8bit) == ct for pt, ct in plaintext_ciphertext_pairs):
                print(f"Key found: {key}")
                return key
        except Exception:
            continue
    print("Key not found using provided pairs.")
    return None

def interactive_menu():
    show_menu = True

    while True:
        if show_menu:
            print(f"\n{Fore.CYAN}S-DES OFB CLI Menu{Style.RESET_ALL}")
            print(f"1. Generate random 10-bit key")
            print(f"2. S-DES-OFB Encryption")
            print(f"3. S-DES-OFB Decryption")
            print(f"4. Brute Force Attack")
            print(f"5. Cryptanalysis Attack")
            print(f"6. Exit")

        try:
            choice = input(f"\n{Fore.CYAN}Select operation (1-6): {Style.RESET_ALL}").strip()

            if choice == '1':
                key = bin(secrets.randbits(10))[2:].zfill(10)
                k1, k2 = generate_subkeys(key)
                draw_table(key, k1, k2)

                input(f"\n{Fore.CYAN}Press Enter to return to main menu...{Style.RESET_ALL}")
                show_menu = True

            elif choice == '2':
                print(f"\n{Fore.GREEN}Encryption input form: {Style.RESET_ALL}");
                print(f"1.Text (hex ciphertext)")
                print(f"2.File/image/video")
                mode = input(f"\n{Fore.CYAN}Choose (1 or 2): {Style.RESET_ALL}")
                key = input("Enter 10-bit key (e.g. 1010101010): ").strip()
                iv = input("Enter 8-bit IV (e.g. 01010101): ").strip()

                if len(key) != 10 or any(c not in '01' for c in key):
                    print("Invalid key. Must be 10-bit binary string.")
                    continue
                if len(iv) != 8 or any(c not in '01' for c in iv):
                    print("Invalid IV. Must be 8-bit binary string.")
                    continue

                if mode == '1':
                    message = input("Enter plaintext message: ")
                    plaintext_bytes = message.encode('utf-8')
                    ciphertext = ofb_encrypt(plaintext_bytes, key, iv)
                    ciphertext_hex = ciphertext.hex();
                    print(f"Ciphertext (hex): {ciphertext_hex}")
                    log_full_details(
                        operation="Encryption - Message",
                        key=key,
                        iv=iv,
                        input_data=message,
                        output_data=ciphertext_hex
                    )
                elif mode == '2':
                    input_path = input("Enter plaintext file path: ").strip()
                    output_path = input("Enter output ciphertext file path: ").strip()

                    try:
                        with open(input_path, 'rb') as f:
                            file_bytes = f.read()

                        ciphertext = ofb_encrypt(file_bytes, key, iv)

                        with open(output_path, 'wb') as f:
                            f.write(ciphertext)

                        print(f"File encrypted successfully. Output saved to '{output_path}'.")
                        log_full_details(
                            operation="Encryption - File",
                            key=key,
                            iv=iv,
                            input_data=f"{input_path} ({len(file_bytes)} bytes)",
                            output_data=f"{output_path} ({len(ciphertext)} bytes)"
                        )
                    except FileNotFoundError:
                        print("File not found. Please check the file path.")
                    except Exception as e:
                        print(f"Error during encryption: {e}")

            elif choice == '3':
                print(f"\n{Fore.GREEN}Decrypt from: {Style.RESET_ALL}")
                print("1.Text (hex ciphertext)")
                print(f"2.File/image/video")
                mode = input(f"\n{Fore.CYAN}Choose (1 or 2): {Style.RESET_ALL}")
                key = input("Enter 10-bit key (e.g. 1010101010): ").strip()
                iv = input("Enter 8-bit IV (e.g. 01010101): ").strip()

                if len(key) != 10 or any(c not in '01' for c in key):
                    print("Invalid key. Must be 10-bit binary string.")
                    continue
                if len(iv) != 8 or any(c not in '01' for c in iv):
                    print("Invalid IV. Must be 8-bit binary string.")
                    continue

                if mode == '1':
                    hex_ciphertext = input("Enter ciphertext (hex): ").strip()
                    try:
                        ciphertext_bytes = bytes.fromhex(hex_ciphertext)
                        plaintext_bytes = ofb_decrypt(ciphertext_bytes, key, iv)
                        try:
                            plaintext = plaintext_bytes.decode('utf-8')
                            print(f"Decrypted plaintext message:\n{plaintext}")
                            log_full_details(
                                operation="Decryption - Message",
                                key=key,
                                iv=iv,
                                input_data=hex_ciphertext,
                                output_data=plaintext
                            )
                        except UnicodeDecodeError:
                            print("Decrypted bytes (non-text data):", plaintext_bytes)
                            log_full_details(
                                operation="Decryption - Message (non-text)",
                                key=key,
                                iv=iv,
                                input_data=hex_ciphertext,
                                output_data=plaintext_bytes
                            )
                    except ValueError:
                        print("Invalid hex input.")

                elif mode == '2':
                    input_path = input("Enter ciphertext file path: ").strip()
                    output_path = input("Enter output plaintext file path: ").strip()
                    try:
                        with open(input_path, 'rb') as f:
                            ciphertext_bytes = f.read()
                        plaintext_bytes = ofb_decrypt(ciphertext_bytes, key, iv)
                        with open(output_path, 'wb') as f:
                            f.write(plaintext_bytes)
                        print(f"Decryption complete. Plaintext saved to '{output_path}'.")
                        log_full_details(
                            operation="Decryption - File",
                            key=key,
                            iv=iv,
                            input_data=f"{input_path} ({len(ciphertext_bytes)} bytes)",
                            output_data=f"{output_path} ({len(plaintext_bytes)} bytes)"
                        )
                    except FileNotFoundError:
                        print("File not found. Please check the file path.")
                    except Exception as e:
                        print(f"Error during decryption: {e}")

            elif choice == '4':
                plaintext = input("Enter known plaintext (text): ").encode('utf-8')
                ciphertext_hex = input("Enter corresponding ciphertext (hex): ").strip()
                iv = input("Enter 8-bit IV (e.g. 01010101): ").strip()

                try:
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    if len(iv) != 8 or any(c not in '01' for c in iv):
                        print("Invalid IV. Must be 8-bit binary string.")
                        continue

                    key = brute_force_attack(plaintext, ciphertext, iv)
                    if key:
                        print(f"Brute force succeeded! Key: {key}")
                        log_full_details(
                            operation="Brute Force Attack - Success",
                            key=key,
                            iv=iv,
                            input_data=plaintext.decode('utf-8', errors='replace'),
                            output_data=f"key found {key}"
                        )
                    else:
                        print("Brute force failed to find the key.")
                        log_full_details(
                            operation="Brute Force Attack - Success",
                            key=key,
                            iv=iv,
                            input_data=plaintext.decode('utf-8', errors='replace'),
                            output_data="key not found"
                        )
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == '5':
                n = int(input("Enter number of plaintext-ciphertext pairs: "))
                pairs = []
                iv = input("Enter 8-bit IV (e.g. 01010101): ").strip()
                if len(iv) != 8 or any(c not in '01' for c in iv):
                    print("Invalid IV. Must be 8-bit binary string.")
                    continue

                try:
                    for i in range(n):
                        pt = input(f"Enter plaintext #{i+1} (text): ").encode('utf-8')
                        ct_hex = input(f"Enter ciphertext #{i+1} (hex): ").strip()
                        ct = bytes.fromhex(ct_hex)
                        pairs.append((pt, ct))

                    key = cryptanalysis_attack(pairs, iv)
                    if key:
                        print(f"Cryptanalysis succeeded! Key: {key}")
                        log_full_details(
                            operation="Cryptanalysis Attack - Success",
                            key=key,
                            iv=iv,
                            input_data=f"{n} plaintext-ciphertext pairs",
                            output_data=f"Key found {key}"
                        )
                    else:
                        print("Cryptanalysis failed to find the key.")
                        log_full_details(
                            operation="Cryptanalysis Attack - Failure",
                            key="N/A",
                            iv=iv,
                            input_data=f"{n} plaintext-ciphertext pairs",
                            output_data="Key not found"
                        )
                except Exception as e:
                    print(f"Error: {e}")

            elif choice == '6':
                print(f"{Fore.RED}Exiting...{Style.RESET_ALL}")
                break

            else:
                print(f"{Fore.RED}Invalid choice, try again{Style.RESET_ALL}")
                show_menu = True

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Operation cancelled{Style.RESET_ALL}")
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='S-DES OFB CLI Tool')
    args = parser.parse_args()

    print(f"""{Fore.CYAN}
  ____        ____  _____ ____         ___  _____ ____         ____ _     ___
 / ___|      |  _ \| ____/ ___|       / _ \|  ___| __ )       / ___| |   |_ _|
 \___ \ _____| | | |  _| \___ \ _____| | | | |_  |  _ \      | |   | |    | |
  ___) |_____| |_| | |___ ___) |_____| |_| |  _| | |_) |     | |___| |___ | |
 |____/      |____/|_____|____/       \___/|_|   |____/       \____|_____|___|

──────────────────────────────────────────────────────────────────────────────
       Welcome to the S-DES OFB CLI Tool - Encryption Made Simple
──────────────────────────────────────────────────────────────────────────────
{Style.RESET_ALL}""")
    interactive_menu()
