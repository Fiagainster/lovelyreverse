import struct, re

path = None
import glob, os
for p in glob.glob(r"D:\临时取证\ch10\*"):
    if os.path.isfile(p) and os.path.basename(p) == "KeygenMe":
        path = p
data = open(path, "rb").read()
print("size:", len(data))
print("head16:", data[:16].hex())
cls, endian, ver, osabi = data[4], data[5], data[6], data[7]
entry, = struct.unpack_from("<Q" if cls == 2 else "<I", data, 24)
machine, = struct.unpack_from("<H", data, 18)
print(f"ELF class={cls} endian={endian} osabi={osabi} machine={hex(machine)} entry={hex(entry)}")

# program headers -> interp
phoff = struct.unpack_from("<Q" if cls == 2 else "<I", data, 32 if cls == 2 else 28)[0]
phnum = struct.unpack_from("<H", data, 56 if cls == 2 else 44)[0]
for i in range(phnum):
    off = phoff + i * 56  # 64-bit layout
    ptype = struct.unpack_from("<I", data, off)[0]
    if ptype == 3:  # PT_INTERP
        isz, = struct.unpack_from("<Q", data, off + 32)
        ioff, = struct.unpack_from("<Q", data, off + 8)
        print("interp:", data[ioff:ioff+isz-1].decode())

strs = re.findall(rb"[\x20-\x7e]{4,}", data)
print("--- strings (%d total, showing all meaningful) ---" % len(strs))
seen = set()
for s in strs:
    t = s.decode()
    if t not in seen:
        seen.add(t)
        print(t)
