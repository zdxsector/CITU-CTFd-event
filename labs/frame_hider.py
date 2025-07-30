from PIL import Image
import numpy as np

def embed_flag_in_alpha_only(base_image_path, flag_bw_path, output_path):
    base = Image.open(base_image_path).convert("RGBA")
    flag = Image.open(flag_bw_path).convert("L")  # Ensure grayscale

    # Resize flag to match base
    flag = flag.resize(base.size)

    # Convert to array
    base_np = np.array(base)
    flag_np = np.array(flag)

    # Make RGB fully opaque (255), visual decoy only
    base_np[..., :3] = base_np[..., :3]  # RGB unchanged
    base_np[..., 3] = flag_np            # A (alpha) = FLAG

    Image.fromarray(base_np).save(output_path, format="PNG")

def embed_flag_in_green_lsb(cover_path, hidden_flag_path, output_path):
    """
    Embed the flag in the green channel's least significant bits
    so it's only visible in steganography tools like StegSolve
    """
    # Load images
    cover = Image.open(cover_path).convert("RGB")
    hidden_flag = Image.open(hidden_flag_path).convert("L")  # Convert to grayscale
    
    # Resize hidden_flag to match cover
    hidden_flag = hidden_flag.resize(cover.size)
    
    # Convert to arrays
    cover_np = np.array(cover)
    flag_np = np.array(hidden_flag)
    
    # Clear the least significant bits of the green channel
    # We'll use only 2 LSB to make it less visible in normal view
    cover_np[..., 1] = (cover_np[..., 1] >> 2) << 2
    
    # Embed flag in the 2 LSB of green channel
    # This will be visible in StegSolve but barely noticeable in normal view
    flag_bits = (flag_np >> 6) & 3  # Get bits 6-7 of flag (0-3)
    cover_np[..., 1] |= flag_bits
    
    # Save result
    Image.fromarray(cover_np).save(output_path, format="PNG")

# Usage
# embed_flag_in_alpha_only("cover.png", "hidden_flag.png", "chal2_frames.png")

# Embed flag in green channel LSB - only visible in steganography tools
embed_flag_in_green_lsb("cover.png", "hidden_flag.png", "chal2_plane.png")
