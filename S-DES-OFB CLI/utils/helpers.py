from colorama import init, Fore, Style, Back
from .constants import EP, S0, S1, P4
import datetime

LOG_FILE = "logs.txt"

def permute(bits, permutation_table):
    return ''.join(bits[i-1] for i in permutation_table)

def shift_left(bits, n):
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    return ''.join('0' if b1 == b2 else '1' for b1, b2 in zip(bits1, bits2))

def sbox_lookup(bits, sbox):
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    val = sbox[row][col]
    return format(val, '02b')

def fk(bits, subkey):
    left, right = bits[:4], bits[4:]
    expanded_right = permute(right, EP)
    xor_result = xor(expanded_right, subkey)
    left_half, right_half = xor_result[:4], xor_result[4:]
    s0_bits = sbox_lookup(left_half, S0)
    s1_bits = sbox_lookup(right_half, S1)
    p4_bits = permute(s0_bits + s1_bits, P4)
    left_result = xor(left, p4_bits)
    return left_result + right

def switch(bits):
    return bits[4:] + bits[:4]

def draw_table(key, k1, k2):
    """Draw a bordered table with box-drawing characters, showing keys in 3 columns"""
    tl, tr = '╭', '╮'
    bl, br = '╰', '╯'
    h, v = '─', '│'
    lt, rt = '├', '┤'
    tt, bt = '┬', '┴'
    cross = '┼'

    # Calculate column widths
    col_width = 16  # Width for each column
    total_width = col_width * 3 + 4  # 3 columns + 4 separators

    # Draw top border
    top_border = f"{tl}{h * col_width}{tt}{h * col_width}{tt}{h * col_width}{tr}"
    middle_border = f"{lt}{h * col_width}{cross}{h * col_width}{cross}{h * col_width}{rt}"
    bottom_border = f"{bl}{h * col_width}{bt}{h * col_width}{bt}{h * col_width}{br}"

    # Table header and content
    print(f"\n{Fore.GREEN}{top_border}")
    print(f"{v}{Fore.CYAN}{'S-DES Key Information':^{total_width-2}}{Fore.GREEN}{v}")
    print(f"{middle_border}")

    # Key titles row
    print(f"{v}{Fore.WHITE}{'10-bit Key':^{col_width}}{Fore.GREEN}{v}", end='')
    print(f"{Fore.WHITE}{'Subkey K1':^{col_width}}{Fore.GREEN}{v}", end='')
    print(f"{Fore.WHITE}{'Subkey K2':^{col_width}}{Fore.GREEN}{v}")

    # Key values row
    print(f"{v}{Fore.YELLOW}{key:^{col_width}}{Fore.GREEN}{v}", end='')
    print(f"{Fore.YELLOW}{k1:^{col_width}}{Fore.GREEN}{v}", end='')
    print(f"{Fore.YELLOW}{k2:^{col_width}}{Fore.GREEN}{v}")

    # Bottom border
    print(f"{bottom_border}{Style.RESET_ALL}")

def log_full_details(operation, key, iv, input_data, output_data):
    timestamp = datetime.datetime.now().isoformat()
    with open(LOG_FILE, 'a') as logf:
        logf.write(f"[{timestamp}]")
        logf.write(f"{operation} | Key: {key} | IV: {iv}\n")
        logf.write(f"Input: {repr(input_data)} => Output: {repr(output_data)}\n")
        logf.write("-" * 40 + "\n")