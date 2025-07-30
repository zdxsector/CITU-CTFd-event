#!/usr/bin/env python3
import struct
import time

# HID Usage IDs & modifier bits per HID Usage Tables 1.12 (§10)
hid_map = {
    'a': (0x00, 0x04), 'b': (0x00, 0x05), 'c': (0x00, 0x06), 'd': (0x00, 0x07),
    'e': (0x00, 0x08), 'f': (0x00, 0x09), 'g': (0x00, 0x0A), 'h': (0x00, 0x0B),
    'i': (0x00, 0x0C), 'j': (0x00, 0x0D), 'k': (0x00, 0x0E), 'l': (0x00, 0x0F),
    'm': (0x00, 0x10), 'n': (0x00, 0x11), 'o': (0x00, 0x12), 'p': (0x00, 0x13),
    'q': (0x00, 0x14), 'r': (0x00, 0x15), 's': (0x00, 0x16), 't': (0x00, 0x17),
    'u': (0x00, 0x18), 'v': (0x00, 0x19), 'w': (0x00, 0x1A), 'x': (0x00, 0x1B),
    'y': (0x00, 0x1C), 'z': (0x00, 0x1D),
    'A': (0x02, 0x04), 'B': (0x02, 0x05), 'C': (0x02, 0x06), 'D': (0x02, 0x07),
    'E': (0x02, 0x08), 'F': (0x02, 0x09), 'G': (0x02, 0x0A), 'H': (0x02, 0x0B),
    'I': (0x02, 0x0C), 'J': (0x02, 0x0D), 'K': (0x02, 0x0E), 'L': (0x02, 0x0F),
    'M': (0x02, 0x10), 'N': (0x02, 0x11), 'O': (0x02, 0x12), 'P': (0x02, 0x13),
    'Q': (0x02, 0x14), 'R': (0x02, 0x15), 'S': (0x02, 0x16), 'T': (0x02, 0x17),
    'U': (0x02, 0x18), 'V': (0x02, 0x19), 'W': (0x02, 0x1A), 'X': (0x02, 0x1B),
    'Y': (0x02, 0x1C), 'Z': (0x02, 0x1D),
    '0': (0x00, 0x27), '1': (0x00, 0x1E), '2': (0x00, 0x1F), '3': (0x00, 0x20),
    '4': (0x00, 0x21), '5': (0x00, 0x22), '6': (0x00, 0x23), '7': (0x00, 0x24),
    '8': (0x00, 0x25), '9': (0x00, 0x26),
    '{': (0x02, 0x2F), '}': (0x02, 0x30), '_': (0x02, 0x2D),
}

target_string = "CITU{FlagSample}"

# 1) PCAP global header for LINKTYPE_USB_LINUX (DLT=189)
pcap_global = struct.pack(
    "=IHHIIII",
    0xa1b2c3d4,  # magic
    2, 4,        # version major, minor
    0, 0,        # thiszone, sigfigs
    65535,       # snaplen
    189          # network: LINKTYPE_USB_LINUX
)

packets = []
ts = time.time()
packet_id = 1

def build_usbmon_packet(modifier, keycode, timestamp, pid):
    """
    Construct exactly the first 48 bytes of struct usbmon_packet:
      - 8B id, 1B type, 1B xfer_type, 1B epnum, 1B devnum,
      - 2B busnum, 1B flag_setup,1B flag_data,
      - 8B ts_sec, 4B ts_usec, 4B status,
      - 4B length, 4B len_cap, 8B data (HID report).
    """
    ts_sec = int(timestamp)
    ts_usec = int((timestamp - ts_sec) * 1_000_000)

    # Pack header + HID report into exactly 48 bytes:
    hdr = struct.pack(
        "<Q"      # u64 id
        "BBBB"    # u8 type, xfer_type, epnum, devnum
        "H"       # u16 busnum
        "bb"      # char flag_setup, flag_data
        "q"       # s64 ts_sec
        "i"       # s32 ts_usec
        "i"       # int status
        "I"       # u32 length
        "I"       # u32 len_cap
        "8s",     # u8[8] data (HID report)
        pid,               # id
        0x01,              # type = URB_SUBMIT
        0x01,              # xfer_type = INTERRUPT
        0x81,              # epnum = endpoint 1 IN
        2,                 # devnum = device addr 2
        1,                 # busnum = USB bus 1
        0,                 # flag_setup
        1,                 # flag_data
        ts_sec,            # timestamp seconds
        ts_usec,           # timestamp microseconds
        0,                 # status
        8,                 # length (requested)
        8,                 # len_cap (delivered)
        bytes([modifier, 0x00, keycode, 0, 0, 0, 0, 0])
    )
    # Prepend PCAP per-packet header
    pkt_hdr = struct.pack(
        "=IIII",
        ts_sec,      # ts_sec
        ts_usec,     # ts_usec
        len(hdr),    # incl_len
        len(hdr)     # orig_len
    )
    return pkt_hdr + hdr

# Start simulating the keyboard
for ch in target_string:
    if ch not in hid_map:
        continue

    mod, code = hid_map[ch]

    # Key press
    packets.append(build_usbmon_packet(mod, code, ts, packet_id))
    packet_id += 1
    ts += 0.05

    # Key release (all-zero report)
    packets.append(build_usbmon_packet(0x00, 0x00, ts, packet_id))
    packet_id += 1
    ts += 0.05

# Write out the combined PCAP
with open("usb_keyboard_fixed.pcap", "wb") as f:
    f.write(pcap_global)
    f.write(b"".join(packets))

print("PCAP written: usb_keyboard_fixed.pcap")
