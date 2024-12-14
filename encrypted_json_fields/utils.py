

def pad(data: bytes, block_size: int) -> bytes:
    """
    Pad the given data using PKCS#7 padding.
    """
    padding_length = block_size - len(data) % block_size
    return data + bytes([padding_length] * padding_length)


def unpad(data: bytes, block_size: int) -> bytes:
    """
    Remove PKCS#7 padding from the given data.
    """
    padding_length = data[-1]
    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length")
    return data[:-padding_length]
