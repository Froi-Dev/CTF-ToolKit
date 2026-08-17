import string
import math
from typing import Generator

def _is_mostly_text(data: bytes) -> bool:
    if not data:
        return False
    printable = sum(byte in (9, 10, 13) or 32 <= byte <= 126 for byte in data)
    return printable / len(data) > 0.8

def affine_brute_force(data: bytes) -> Generator[tuple[bytes, str], None, None]:
    """Brute forces all 312 combinations of the Affine cipher for A-Z."""
    if not _is_mostly_text(data):
        return
        
    text = data.decode('ascii', errors='ignore')
    valid_a = [a for a in range(1, 26) if math.gcd(a, 26) == 1]
    
    for a in valid_a:
        # modular inverse of a mod 26
        a_inv = pow(a, -1, 26)
        for b in range(26):
            output = bytearray()
            for char in text:
                if char.isupper():
                    y = ord(char) - 65
                    x = (a_inv * (y - b)) % 26
                    output.append(x + 65)
                elif char.islower():
                    y = ord(char) - 97
                    x = (a_inv * (y - b)) % 26
                    output.append(x + 97)
                else:
                    output.append(ord(char))
            
            yield bytes(output), f"a={a}, b={b}"

def rail_fence_decode(data: bytes, rails: int) -> bytes:
    if not data or rails < 2:
        return data
    
    length = len(data)
    fence = [['\n'] * length for _ in range(rails)]
    
    direction_down = None
    row, col = 0, 0
    
    for i in range(length):
        if row == 0:
            direction_down = True
        if row == rails - 1:
            direction_down = False
            
        fence[row][col] = '*'
        col += 1
        
        if direction_down:
            row += 1
        else:
            row -= 1
            
    index = 0
    for i in range(rails):
        for j in range(length):
            if fence[i][j] == '*' and index < length:
                fence[i][j] = data[index]
                index += 1
                
    result = bytearray()
    row, col = 0, 0
    for i in range(length):
        if row == 0:
            direction_down = True
        if row == rails - 1:
            direction_down = False
            
        if isinstance(fence[row][col], int):
            result.append(fence[row][col])
        else:
            # fallback
            result.append(0)
        col += 1
        
        if direction_down:
            row += 1
        else:
            row -= 1
            
    return bytes(result)

def rail_fence_brute_force(data: bytes) -> Generator[tuple[bytes, str], None, None]:
    if not _is_mostly_text(data) or len(data) < 4:
        return
    for rails in range(2, min(10, len(data) // 2)):
        yield rail_fence_decode(data, rails), f"rails={rails}"

def reverse_string(data: bytes) -> bytes:
    return data[::-1]

def alternate_chunks(data: bytes) -> Generator[tuple[bytes, str], None, None]:
    """Tries simple transposition like taking every 2nd character"""
    if len(data) > 4:
        yield data[::2] + data[1::2], "deinterleave-2"
        if len(data) % 2 == 0:
            half = len(data) // 2
            yield bytes(a for pair in zip(data[:half], data[half:]) for a in pair), "interleave-2"

