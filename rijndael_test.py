import ctypes
from aes.aes import sub_bytes, inv_sub_bytes, shift_rows

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


def test_sub_bytes():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    rijndael.sub_bytes(c_buffer)
    sub_bytes(py_buffer)
    assert [c for a in py_buffer for c in a] == list(c_buffer[:-1])


def test_inv_sub_bytes():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    rijndael.sub_bytes(c_buffer)
    sub_bytes(py_buffer)
    assert [c for a in py_buffer for c in a] == list(c_buffer[:-1])
    assert list(c_buffer) != list(gen_c_buffer())
    rijndael.invert_sub_bytes(c_buffer)
    inv_sub_bytes(py_buffer)
    assert [c for a in py_buffer for c in a] == list(c_buffer[:-1])
    assert list(c_buffer) == list(gen_c_buffer())


def test_shift_rows():
    c_buffer = gen_c_buffer()
    py_buffer = gen_py_buffer()
    print(list(c_buffer[:-1]))
    rijndael.shift_rows(c_buffer)
    print(list(c_buffer[:-1]))
    print("\n")
    print(list([c for a in py_buffer for c in a]))
    shift_rows(py_buffer)
    print(list([c for a in py_buffer for c in a]))
    assert [c for a in py_buffer for c in a] == list(c_buffer[:-1])
    assert list(c_buffer[:-1]) != list(gen_c_buffer()[:-1])
