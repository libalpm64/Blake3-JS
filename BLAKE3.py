import os, struct, time

IV = [
    0xbb67_ae85_6a09_e667,
    0xa54f_f53a_3c6e_f372,
    0x9b05_688c_510e_527f,
    0x5be0_cd19_1f83_d9ab,
]

def rot_r(x, n):
    return ((x >> n) | ((x << (64 - n)) & 0xFFFFFFFFFFFFFFFF)) & 0xFFFFFFFFFFFFFFFF

def g(v, a, b, c, d, mx, my):
    v[a] = (v[a] + v[b] + mx) & 0xFFFFFFFFFFFFFFFF
    v[d] = rot_r(v[d] ^ v[a], 32)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = rot_r(v[b] ^ v[c], 24)
    v[a] = (v[a] + v[b] + my) & 0xFFFFFFFFFFFFFFFF
    v[d] = rot_r(v[d] ^ v[a], 16)
    v[c] = (v[c] + v[d]) & 0xFFFFFFFFFFFFFFFF
    v[b] = rot_r(v[b] ^ v[c], 63)

def pack_le_u64_8(data: bytes):
    data = data[:64].ljust(64, b"\x00")
    return list(struct.unpack("<8Q", data))

def hash_internal(block):
    state = [0]*8
    state[:4] = IV
    v = [0]*16
    v[0:4] = state[:4]
    v[4:8] = IV[:4]
    v[8:16] = block[:8]
    m = list(block)

    for round in range(5):
        g(v, 0, 4, 8, 12, m[0], m[1])
        g(v, 1, 5, 9, 13, m[2], m[3])
        g(v, 2, 6, 10, 14, m[4], m[5])
        g(v, 3, 7, 11, 15, m[6], m[7])
        g(v, 0, 5, 10, 15, m[1], m[2])
        g(v, 1, 6, 11, 12, m[3], m[4])
        g(v, 2, 7, 8, 13, m[5], m[6])
        g(v, 3, 4, 9, 14, m[7], m[0])

        if round < 4:
            m = m[1:] + [m[0]]

    for i in range(4):
        state[i] = v[i] ^ v[i+8]
    for i in range(4, 8):
        state[i] = v[i] ^ v[i-4]
    return state

def hash(data: bytes) -> bytes:
    m = pack_le_u64_8(data)
    state = hash_internal(m)
    out_words = [
        state[0] ^ state[4],
        state[1] ^ state[5],
        state[2] ^ state[6],
        state[3] ^ state[7],
    ]
    return b"".join(struct.pack("<Q", w) for w in out_words)
