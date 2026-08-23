"""OpenBSD bcrypt_pbkdf, including SHA-512 and EksBlowfish."""

from std.bit import byte_swap
from std.collections import Array
from std.sys.info import simd_width_of as simdwidthof

from constants import initial_blowfish_state

comptime BPtr = UnsafePointer[UInt8, AnyOrigin[mut=True]]
comptime W = simdwidthof[DType.float64]()
comptime REGISTER_BYTES = W * 8
comptime U64_WIDTH = W
comptime U32_WIDTH = W * 2


@always_inline
def bptr(address: Int) -> BPtr:
    return BPtr(unsafe_from_address=address)


@always_inline
def rotr64(value: UInt64, amount: UInt64) -> UInt64:
    return (value >> amount) | (value << (UInt64(64) - amount))


@always_inline
def load64_be(source: UnsafePointer[UInt8, _], offset: Int) -> UInt64:
    return (
        (UInt64(source[offset]) << 56)
        | (UInt64(source[offset + 1]) << 48)
        | (UInt64(source[offset + 2]) << 40)
        | (UInt64(source[offset + 3]) << 32)
        | (UInt64(source[offset + 4]) << 24)
        | (UInt64(source[offset + 5]) << 16)
        | (UInt64(source[offset + 6]) << 8)
        | UInt64(source[offset + 7])
    )


@always_inline
def store64_be[
    destination_origin: MutOrigin
](
    destination: UnsafePointer[UInt8, destination_origin],
    offset: Int,
    value: UInt64,
):
    destination[offset] = UInt8(value >> 56)
    destination[offset + 1] = UInt8(value >> 48)
    destination[offset + 2] = UInt8(value >> 40)
    destination[offset + 3] = UInt8(value >> 32)
    destination[offset + 4] = UInt8(value >> 24)
    destination[offset + 5] = UInt8(value >> 16)
    destination[offset + 6] = UInt8(value >> 8)
    destination[offset + 7] = UInt8(value)


def sha512_compress[
    state_origin: MutOrigin
](
    state_bytes: UnsafePointer[UInt8, state_origin],
    block: UnsafePointer[UInt8, _],
):
    var words = state_bytes.bitcast[UInt64]()
    var schedule = Array[UInt64, 80](fill=0)
    for i in range(16):
        schedule[i] = load64_be(block, i * 8)
    for i in range(16, 80):
        var x = schedule[i - 15]
        var y = schedule[i - 2]
        var s0 = rotr64(x, 1) ^ rotr64(x, 8) ^ (x >> 7)
        var s1 = rotr64(y, 19) ^ rotr64(y, 61) ^ (y >> 6)
        schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1
    var constants: Array[UInt64, 80] = [
        0x428A2F98D728AE22,
        0x7137449123EF65CD,
        0xB5C0FBCFEC4D3B2F,
        0xE9B5DBA58189DBBC,
        0x3956C25BF348B538,
        0x59F111F1B605D019,
        0x923F82A4AF194F9B,
        0xAB1C5ED5DA6D8118,
        0xD807AA98A3030242,
        0x12835B0145706FBE,
        0x243185BE4EE4B28C,
        0x550C7DC3D5FFB4E2,
        0x72BE5D74F27B896F,
        0x80DEB1FE3B1696B1,
        0x9BDC06A725C71235,
        0xC19BF174CF692694,
        0xE49B69C19EF14AD2,
        0xEFBE4786384F25E3,
        0x0FC19DC68B8CD5B5,
        0x240CA1CC77AC9C65,
        0x2DE92C6F592B0275,
        0x4A7484AA6EA6E483,
        0x5CB0A9DCBD41FBD4,
        0x76F988DA831153B5,
        0x983E5152EE66DFAB,
        0xA831C66D2DB43210,
        0xB00327C898FB213F,
        0xBF597FC7BEEF0EE4,
        0xC6E00BF33DA88FC2,
        0xD5A79147930AA725,
        0x06CA6351E003826F,
        0x142929670A0E6E70,
        0x27B70A8546D22FFC,
        0x2E1B21385C26C926,
        0x4D2C6DFC5AC42AED,
        0x53380D139D95B3DF,
        0x650A73548BAF63DE,
        0x766A0ABB3C77B2A8,
        0x81C2C92E47EDAEE6,
        0x92722C851482353B,
        0xA2BFE8A14CF10364,
        0xA81A664BBC423001,
        0xC24B8B70D0F89791,
        0xC76C51A30654BE30,
        0xD192E819D6EF5218,
        0xD69906245565A910,
        0xF40E35855771202A,
        0x106AA07032BBD1B8,
        0x19A4C116B8D2D0C8,
        0x1E376C085141AB53,
        0x2748774CDF8EEB99,
        0x34B0BCB5E19B48A8,
        0x391C0CB3C5C95A63,
        0x4ED8AA4AE3418ACB,
        0x5B9CCA4F7763E373,
        0x682E6FF3D6B2B8A3,
        0x748F82EE5DEFB2FC,
        0x78A5636F43172F60,
        0x84C87814A1F0AB72,
        0x8CC702081A6439EC,
        0x90BEFFFA23631E28,
        0xA4506CEBDE82BDE9,
        0xBEF9A3F7B2C67915,
        0xC67178F2E372532B,
        0xCA273ECEEA26619C,
        0xD186B8C721C0C207,
        0xEADA7DD6CDE0EB1E,
        0xF57D4F7FEE6ED178,
        0x06F067AA72176FBA,
        0x0A637DC5A2C898A6,
        0x113F9804BEF90DAE,
        0x1B710B35131C471B,
        0x28DB77F523047D84,
        0x32CAAB7B40C72493,
        0x3C9EBE0A15C9BEBC,
        0x431D67C49C100D4C,
        0x4CC5D4BECB3E42B6,
        0x597F299CFC657E2A,
        0x5FCB6FAB3AD6FAEC,
        0x6C44198C4A475817,
    ]
    var a = words[0]
    var b = words[1]
    var c = words[2]
    var d = words[3]
    var e = words[4]
    var f = words[5]
    var g = words[6]
    var h = words[7]
    for i in range(80):
        var sum1 = rotr64(e, 14) ^ rotr64(e, 18) ^ rotr64(e, 41)
        var choice = (e & f) ^ ((~e) & g)
        var t1 = h + sum1 + choice + constants[i] + schedule[i]
        var sum0 = rotr64(a, 28) ^ rotr64(a, 34) ^ rotr64(a, 39)
        var majority = (a & b) ^ (a & c) ^ (b & c)
        var t2 = sum0 + majority
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
    words[0] += a
    words[1] += b
    words[2] += c
    words[3] += d
    words[4] += e
    words[5] += f
    words[6] += g
    words[7] += h


def sha512_init() -> Array[UInt64, 8]:
    return [
        0x6A09E667F3BCC908,
        0xBB67AE8584CAA73B,
        0x3C6EF372FE94F82B,
        0xA54FF53A5F1D36F1,
        0x510E527FADE682D1,
        0x9B05688C2B3E6C1F,
        0x1F83D9ABFB41BD6B,
        0x5BE0CD19137E2179,
    ]


def sha512[
    destination_origin: MutOrigin
](
    source: UnsafePointer[UInt8, _],
    size: Int,
    destination: UnsafePointer[UInt8, destination_origin],
):
    var state = sha512_init()
    var state_ptr = UnsafePointer(to=state[0]).bitcast[UInt8]()
    var offset = 0
    while offset + 128 <= size:
        sha512_compress(state_ptr, source + offset)
        offset += 128
    var final_blocks = Array[UInt8, 256](fill=0)
    var final_ptr = UnsafePointer(to=final_blocks[0])
    var remainder = size - offset
    for i in range(remainder):
        final_blocks[i] = source[offset + i]
    final_blocks[remainder] = 0x80
    var final_size = 128 if remainder < 112 else 256
    store64_be(final_ptr, final_size - 16, 0)
    store64_be(final_ptr, final_size - 8, UInt64(size) * 8)
    sha512_compress(state_ptr, final_ptr)
    if final_size == 256:
        sha512_compress(state_ptr, final_ptr + 128)
    for i in range(8):
        store64_be(destination, i * 8, state[i])


def sha512_salt_count[
    destination_origin: MutOrigin
](
    salt: UnsafePointer[UInt8, _],
    salt_size: Int,
    count: UInt32,
    destination: UnsafePointer[UInt8, destination_origin],
):
    var state = sha512_init()
    var state_ptr = UnsafePointer(to=state[0]).bitcast[UInt8]()
    var offset = 0
    while offset + 128 <= salt_size:
        sha512_compress(state_ptr, salt + offset)
        offset += 128
    var final_blocks = Array[UInt8, 256](fill=0)
    var final_ptr = UnsafePointer(to=final_blocks[0])
    var remainder = salt_size - offset
    for i in range(remainder):
        final_blocks[i] = salt[offset + i]
    final_blocks[remainder] = UInt8(count >> 24)
    final_blocks[remainder + 1] = UInt8(count >> 16)
    final_blocks[remainder + 2] = UInt8(count >> 8)
    final_blocks[remainder + 3] = UInt8(count)
    final_blocks[remainder + 4] = 0x80
    var final_size = 128 if remainder + 4 < 112 else 256
    store64_be(final_ptr, final_size - 16, 0)
    store64_be(final_ptr, final_size - 8, UInt64(salt_size + 4) * 8)
    sha512_compress(state_ptr, final_ptr)
    if final_size == 256:
        sha512_compress(state_ptr, final_ptr + 128)
    for i in range(8):
        store64_be(destination, i * 8, state[i])


@always_inline
def word64(data: UnsafePointer[UInt8, _], position: Int) -> UInt32:
    return (
        (UInt32(data[position]) << 24)
        | (UInt32(data[position + 1]) << 16)
        | (UInt32(data[position + 2]) << 8)
        | UInt32(data[position + 3])
    )


@always_inline
def xor_key64[
    state_origin: MutOrigin
](state: UnsafePointer[UInt32, state_origin], key: UnsafePointer[UInt8, _],):
    var key_words = key.bitcast[UInt32]()
    var i = 0
    while i + U32_WIDTH <= 16:
        var state_values = state.load[width=U32_WIDTH](i)
        var key_values = key_words.load[width=U32_WIDTH, alignment=1](i)
        state.store(i, state_values ^ byte_swap(key_values))
        i += U32_WIDTH
    while i < 18:
        state[i] ^= word64(key, (i * 4) & 63)
        i += 1


@always_inline
def copy32[
    destination_origin: MutOrigin
](
    destination: UnsafePointer[UInt8, destination_origin],
    source: UnsafePointer[UInt8, _],
):
    var destination_words = destination.bitcast[UInt64]()
    var source_words = source.bitcast[UInt64]()
    var byte_offset = 0
    while byte_offset + REGISTER_BYTES <= 32:
        var word_offset = byte_offset // 8
        var values = source_words.load[width=U64_WIDTH, alignment=1](
            word_offset
        )
        destination_words.store[alignment=1](word_offset, values)
        byte_offset += REGISTER_BYTES
    while byte_offset < 32:
        destination[byte_offset] = source[byte_offset]
        byte_offset += 1


@always_inline
def xor32[
    destination_origin: MutOrigin
](
    destination: UnsafePointer[UInt8, destination_origin],
    source: UnsafePointer[UInt8, _],
):
    var destination_words = destination.bitcast[UInt64]()
    var source_words = source.bitcast[UInt64]()
    var byte_offset = 0
    while byte_offset + REGISTER_BYTES <= 32:
        var word_offset = byte_offset // 8
        var destination_values = destination_words.load[
            width=U64_WIDTH, alignment=1
        ](word_offset)
        var source_values = source_words.load[width=U64_WIDTH, alignment=1](
            word_offset
        )
        destination_words.store[alignment=1](
            word_offset, destination_values ^ source_values
        )
        byte_offset += REGISTER_BYTES
    while byte_offset < 32:
        destination[byte_offset] ^= source[byte_offset]
        byte_offset += 1


@always_inline
def blowfish_f(state: UnsafePointer[UInt32, _], value: UInt32) -> UInt32:
    var result = state[18 + Int(UInt8(value >> 24))]
    result += state[18 + 256 + Int(UInt8(value >> 16))]
    result ^= state[18 + 512 + Int(UInt8(value >> 8))]
    result += state[18 + 768 + Int(UInt8(value))]
    return result


@always_inline
def encipher(
    state: UnsafePointer[UInt32, _],
    left_input: UInt32,
    right_input: UInt32,
) -> Tuple[UInt32, UInt32]:
    var left = left_input ^ state[0]
    var right = right_input
    for i in range(1, 17, 2):
        right ^= blowfish_f(state, left) ^ state[i]
        left ^= blowfish_f(state, right) ^ state[i + 1]
    return (right ^ state[17], left)


def expand0[
    state_origin: MutOrigin
](state: UnsafePointer[UInt32, state_origin], key: UnsafePointer[UInt8, _],):
    xor_key64(state, key)
    var left = UInt32(0)
    var right = UInt32(0)
    for i in range(0, 18, 2):
        left, right = encipher(state, left, right)
        state[i] = left
        state[i + 1] = right
    for i in range(18, 1042, 2):
        left, right = encipher(state, left, right)
        state[i] = left
        state[i + 1] = right


def expand[
    state_origin: MutOrigin
](
    state: UnsafePointer[UInt32, state_origin],
    data: UnsafePointer[UInt8, _],
    key: UnsafePointer[UInt8, _],
):
    xor_key64(state, key)
    var left = UInt32(0)
    var right = UInt32(0)
    var data_position = 0
    for i in range(0, 18, 2):
        left ^= word64(data, data_position)
        data_position = (data_position + 4) & 63
        right ^= word64(data, data_position)
        data_position = (data_position + 4) & 63
        left, right = encipher(state, left, right)
        state[i] = left
        state[i + 1] = right
    for i in range(18, 1042, 2):
        left ^= word64(data, data_position)
        data_position = (data_position + 4) & 63
        right ^= word64(data, data_position)
        data_position = (data_position + 4) & 63
        left, right = encipher(state, left, right)
        state[i] = left
        state[i + 1] = right


def bcrypt_hash[
    destination_origin: MutOrigin
](
    sha2pass: UnsafePointer[UInt8, _],
    sha2salt: UnsafePointer[UInt8, _],
    destination: UnsafePointer[UInt8, destination_origin],
):
    var state = initial_blowfish_state()
    var state_ptr = UnsafePointer(to=state[0])
    expand(state_ptr, sha2salt, sha2pass)
    for _ in range(64):
        expand0(state_ptr, sha2salt)
        expand0(state_ptr, sha2pass)
    var ciphertext: Array[UInt32, 8] = [
        0x4F787963,
        0x68726F6D,
        0x61746963,
        0x426C6F77,
        0x66697368,
        0x53776174,
        0x44796E61,
        0x6D697465,
    ]
    for _ in range(64):
        for j in range(0, 8, 2):
            ciphertext[j], ciphertext[j + 1] = encipher(
                state_ptr, ciphertext[j], ciphertext[j + 1]
            )
    for i in range(8):
        var value = ciphertext[i]
        destination[i * 4] = UInt8(value)
        destination[i * 4 + 1] = UInt8(value >> 8)
        destination[i * 4 + 2] = UInt8(value >> 16)
        destination[i * 4 + 3] = UInt8(value >> 24)
    for i in range(1042):
        state[i] = 0


def bcrypt_pbkdf_block[
    destination_origin: MutOrigin
](
    sha2pass: UnsafePointer[UInt8, _],
    salt: UnsafePointer[UInt8, _],
    salt_size: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_size: Int,
    rounds: Int,
    stride: Int,
    amount: Int,
    count: UInt32,
):
    var sha2salt = Array[UInt8, 64](fill=0)
    var tmp = Array[UInt8, 32](fill=0)
    var block = Array[UInt8, 32](fill=0)
    var salt_hash_ptr = UnsafePointer(to=sha2salt[0])
    var tmp_ptr = UnsafePointer(to=tmp[0])
    var block_ptr = UnsafePointer(to=block[0])
    sha512_salt_count(salt, salt_size, count, salt_hash_ptr)
    bcrypt_hash(sha2pass, salt_hash_ptr, block_ptr)
    copy32(tmp_ptr, block_ptr)
    for _ in range(1, rounds):
        sha512(block_ptr, 32, salt_hash_ptr)
        bcrypt_hash(sha2pass, salt_hash_ptr, block_ptr)
        xor32(tmp_ptr, block_ptr)
    for i in range(amount):
        var index = i * stride + Int(count) - 1
        if index >= destination_size:
            break
        destination[index] = tmp[i]
    for i in range(64):
        sha2salt[i] = 0
    for i in range(32):
        tmp[i] = 0
        block[i] = 0


def bcrypt_pbkdf[
    destination_origin: MutOrigin
](
    password: UnsafePointer[UInt8, _],
    password_size: Int,
    salt: UnsafePointer[UInt8, _],
    salt_size: Int,
    destination: UnsafePointer[UInt8, destination_origin],
    destination_size: Int,
    rounds: Int,
):
    var sha2pass = Array[UInt8, 64](fill=0)
    var pass_ptr = UnsafePointer(to=sha2pass[0])
    sha512(password, password_size, pass_ptr)
    var stride = (destination_size + 31) // 32
    var amount = (destination_size + stride - 1) // stride

    @parameter
    def derive_block(block_index: Int):
        bcrypt_pbkdf_block(
            pass_ptr,
            salt,
            salt_size,
            destination,
            destination_size,
            rounds,
            stride,
            amount,
            UInt32(block_index + 1),
        )

    for block_index in range(stride):
        derive_block(block_index)

    for i in range(64):
        sha2pass[i] = 0


@export("mbc_kdf")
def mbc_kdf(
    password_address: Int,
    password_size: Int,
    salt_address: Int,
    salt_size: Int,
    destination_address: Int,
    destination_size: Int,
    rounds: Int,
) abi("C") -> Int:
    if (
        password_address == 0
        or salt_address == 0
        or destination_address == 0
        or password_size <= 0
        or salt_size <= 0
        or destination_size <= 0
        or destination_size > 512
        or rounds < 1
        or rounds > 0xFFFFFFFF
    ):
        return -1
    bcrypt_pbkdf(
        bptr(password_address),
        password_size,
        bptr(salt_address),
        salt_size,
        bptr(destination_address),
        destination_size,
        rounds,
    )
    return 0
