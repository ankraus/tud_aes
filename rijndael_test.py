import ctypes
from aes.aes import inv_shift_rows, sub_bytes, inv_sub_bytes, shift_rows

rijndael = ctypes.CDLL("./rijndael.so")


def gen_py_buffer():
    return [
        [0x00, 0x01, 0x02, 0x03],
        [0x04, 0x05, 0x06, 0x07],
        [0x08, 0x09, 0x0A, 0x0B],
        [0x0C, 0x0D, 0x0E, 0x0F],
    ]


def gen_c_buffer():
    buffer = b"\x00\x01\x02\x03\x04\x05\x06\x07"
    buffer += b"\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    return ctypes.create_string_buffer(buffer)


def buffers_match(py_buffer, c_buffer):
    print([c for a in py_buffer for c in a])
    print(list(c_buffer[:-1]))
    return [c for a in py_buffer for c in a] == list(c_buffer[:-1])


def buffer_matches_original(c_buffer):
    print(list(gen_c_buffer()[:-1]))
    print(list(c_buffer[:-1]))
    return list(c_buffer) == list(gen_c_buffer())


def test_sub_bytes():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    rijndael.sub_bytes(c_buffer)
    sub_bytes(py_buffer)
    assert buffers_match(py_buffer, c_buffer)
    assert not buffer_matches_original(c_buffer)


def test_inv_sub_bytes():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    rijndael.sub_bytes(c_buffer)
    sub_bytes(py_buffer)
    assert buffers_match(py_buffer, c_buffer)
    assert not buffer_matches_original(c_buffer)
    rijndael.invert_sub_bytes(c_buffer)
    inv_sub_bytes(py_buffer)
    assert buffers_match(py_buffer, c_buffer)
    assert buffer_matches_original(c_buffer)


def test_shift_rows():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    rijndael.shift_rows(c_buffer)
    shift_rows(py_buffer)
    assert buffers_match(py_buffer, c_buffer)
    assert not buffer_matches_original(c_buffer)


def test_inv_shift_rows():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    rijndael.shift_rows(c_buffer)
    shift_rows(py_buffer)
    assert buffers_match(py_buffer, c_buffer)
    assert not buffer_matches_original(c_buffer)
    rijndael.invert_shift_rows(c_buffer)
    inv_shift_rows(py_buffer)
    assert buffers_match(py_buffer, c_buffer)
    assert buffer_matches_original(c_buffer)
