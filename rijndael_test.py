import ctypes
import os
from aes.aes import (
    add_round_key,
    bytes2matrix,
    inv_mix_columns,
    inv_shift_rows,
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
    print([c for a in py_buffer for c in a])
    print(list(c_buffer[:-1]))
    return [c for a in py_buffer for c in a] == list(c_buffer[:-1])


def c_buffers_match(old, new):
    print(list(old[:-1]))
    print(list(new[:-1]))
    return list(new) == list(old)


def test_sub_bytes():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.sub_bytes(c_buffer)
        sub_bytes(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_inv_sub_bytes():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.sub_bytes(c_buffer)
        sub_bytes(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
        rijndael.invert_sub_bytes(c_buffer)
        inv_sub_bytes(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert c_buffers_match(original_c_buffer, c_buffer)


def test_shift_rows():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.shift_rows(c_buffer)
        shift_rows(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_inv_shift_rows():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.shift_rows(c_buffer)
        shift_rows(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
        rijndael.invert_shift_rows(c_buffer)
        inv_shift_rows(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert c_buffers_match(original_c_buffer, c_buffer)


def test_mix_columns():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.mix_columns(c_buffer)
        mix_columns(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)


def test_inv_mix_columns():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        rijndael.mix_columns(c_buffer)
        mix_columns(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
        rijndael.invert_mix_columns(c_buffer)
        inv_mix_columns(py_buffer)
        assert buffers_match(c_buffer, py_buffer)
        assert c_buffers_match(original_c_buffer, c_buffer)


def test_add_round_key():
    for _ in range(3):
        c_buffer, py_buffer, original_c_buffer = gen_buffers()
        c_key, py_key = gen_keys()
        rijndael.add_round_key(c_buffer, c_key)
        add_round_key(py_buffer, py_key)
        assert buffers_match(c_buffer, py_buffer)
        assert not c_buffers_match(original_c_buffer, c_buffer)
