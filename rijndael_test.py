import ctypes
import os
from aes.aes import (
    AES,
    add_round_key,
    bytes2matrix,
    inv_mix_columns,
    inv_shift_rows,
    matrix2bytes,
    mix_columns,
    sub_bytes,
    inv_sub_bytes,
    shift_rows,
)

rijndael = ctypes.CDLL("./rijndael.so")


def gen_buffers():
    buffer = os.urandom(16)
    py_buffer = bytes2matrix(buffer)
    c_buffer = ctypes.create_string_buffer(buffer)
    ref_buffer = ctypes.create_string_buffer(buffer)
    return (c_buffer, py_buffer, ref_buffer)


def gen_keys():
    c_key, py_key, _ = gen_buffers()
    return (c_key, py_key)


def buffers_match(c_buffer, py_buffer):
    print(list(c_buffer))
    print([c for a in py_buffer for c in a])
    return [c for a in py_buffer for c in a] == list(c_buffer)


def c_buffers_match(old, new):
    print(list(old[:-1]))
    print(list(new[:-1]))
    return list(new) == list(old)


def test_sub_bytes():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.sub_bytes(c_buffer)
        sub_bytes(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_inv_sub_bytes():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.sub_bytes(c_buffer)
        sub_bytes(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
        rijndael.invert_sub_bytes(c_buffer)
        inv_sub_bytes(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert c_buffers_match(original_c_buffer, c_buffer)


def test_shift_rows():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.shift_rows(c_buffer)
        shift_rows(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_inv_shift_rows():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.shift_rows(c_buffer)
        shift_rows(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
        rijndael.invert_shift_rows(c_buffer)
        inv_shift_rows(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert c_buffers_match(original_c_buffer, c_buffer)


def test_mix_columns():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.mix_columns(c_buffer)
        mix_columns(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_inv_mix_columns():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.mix_columns(c_buffer)
        mix_columns(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
        rijndael.invert_mix_columns(c_buffer)
        inv_mix_columns(py_buffer)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert c_buffers_match(original_c_buffer, c_buffer)


def test_add_round_key():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        c_key, py_key = gen_keys()
        rijndael.add_round_key(c_buffer, c_key)
        add_round_key(py_buffer, py_key)
        assert buffers_match(c_buffer[:-1], py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_expand_key():
    for _ in range(3):
        c_key, py_key = gen_keys()
        py_aes = AES(matrix2bytes(py_key))
        rijndael.expand_key.restype = ctypes.c_void_p
        pointer = rijndael.expand_key(c_key)
        expanded_c_key = ctypes.string_at(pointer, 176)
        expanded_py_key = []
        key_matrices = py_aes._key_matrices
        for mat in key_matrices:
            for x in mat:
                expanded_py_key.append([y for y in x])
        assert buffers_match(expanded_c_key, expanded_py_key)


def test_encrypt_block():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        c_key, py_key = gen_keys()
        py_aes = AES(matrix2bytes(py_key))
        rijndael.aes_encrypt_block.restype = ctypes.c_void_p
        pointer = rijndael.aes_encrypt_block(c_buffer, c_key)
        py_encrypted = py_aes.encrypt_block(matrix2bytes(py_buffer))
        c_encrypted = ctypes.string_at(pointer, 16)
        assert buffers_match(c_encrypted, bytes2matrix(py_encrypted))
        # ensure the encrypted data is different from the original data
        assert not c_buffers_match(c_encrypted, original_c_buffer)


def test_decrypt_block():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        c_key, py_key = gen_keys()
        py_aes = AES(matrix2bytes(py_key))
        rijndael.aes_encrypt_block.restype = ctypes.c_void_p
        pointer = rijndael.aes_encrypt_block(c_buffer, c_key)
        py_encrypted = py_aes.encrypt_block(matrix2bytes(py_buffer))
        c_encrypted = ctypes.string_at(pointer, 16)
        assert buffers_match(c_encrypted, bytes2matrix(py_encrypted))

        rijndael.aes_decrypt_block.restype = ctypes.c_void_p
        pointer = rijndael.aes_decrypt_block(c_encrypted, c_key)
        py_decrypted = py_aes.decrypt_block(py_encrypted)
        c_decrypted = ctypes.string_at(pointer, 16)
        assert buffers_match(c_decrypted, bytes2matrix(py_decrypted))
        # make sure the original data is present after decryption
        assert c_buffers_match(c_decrypted, original_c_buffer[:-1])

        wrong_key, _ = (
            gen_keys()
        )  # make sure that the payload cannot be encrypted with the wrong key
        pointer = rijndael.aes_decrypt_block(c_encrypted, wrong_key)
        c_decrypted_wrong = ctypes.string_at(pointer, 16)
        assert not c_buffers_match(c_decrypted, c_decrypted_wrong)
