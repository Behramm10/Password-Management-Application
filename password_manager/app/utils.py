import random
import string

def generate_password(length: int = 10, use_special: bool = True) -> str:
    chars = string.ascii_letters + string.digits
    if use_special:
        chars += string.punctuation
    return ''.join(random.choice(chars) for _ in range(length))
