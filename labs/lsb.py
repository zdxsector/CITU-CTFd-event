from PIL import Image
import numpy as np

def embed_flag_lsb(image_path, output_path, message):
    img = Image.open(image_path).convert("RGB")
    data = np.array(img)
    flat = data.flatten()

    # Convert message to bits
    bits = ''.join([format(ord(c), '08b') for c in message])
    if len(bits) > len(flat):
        raise ValueError("Message too long")

    # Embed in LSB of Blue channel
    for i in range(len(bits)):
        flat[i] = (flat[i] & 0xFE) | int(bits[i])

    new_data = flat.reshape(data.shape)
    Image.fromarray(new_data.astype(np.uint8)).save(output_path)

embed_flag_lsb("cover.png", "output.png", "CITU{LSBEmbedOnBlue_Channel}")
