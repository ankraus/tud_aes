/*
 *           Name: Andreas Kraus
 * Student Number: D23125112
 *
 */

#include "rijndael.h"

#include <stdlib.h>
#include <string.h>

/*
 * Bytes for sub_bytes function
 */
static const unsigned char s_box[16][16] = {
    {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76},
    {0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0},
    {0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15},
    {0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75},
    {0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84},
    {0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF},
    {0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8},
    {0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2},
    {0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73},
    {0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB},
    {0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79},
    {0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08},
    {0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A},
    {0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E},
    {0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF},
    {0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16},
};

/*
 * Bytes for invert_sub_bytes function
 */
static const unsigned char inv_s_box[16][16] = {
    {0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB},
    {0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB},
    {0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E},
    {0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25},
    {0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92},
    {0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84},
    {0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06},
    {0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B},
    {0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73},
    {0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E},
    {0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B},
    {0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4},
    {0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F},
    {0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF},
    {0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61},
    {0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D},
};

/*
 * Round constant for key expansion
 */
unsigned char rcon[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
};

/*
 * Operations used when encrypting a block
 */

/*
 * This function subsitutes bytes in the block with those in the s_box
 * Each unsigned char of the block is split, with the first four bits denoting
 * the x position in the s_box and the last four bits denoting the y position
 */
void sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    unsigned char c = block[i];
    unsigned char x = c >> 4;   // access first four bits
    unsigned char y = c & 0xF;  // access last four bits
    unsigned char sub = s_box[x][y];
    block[i] = sub;  // subsitute value in block with value from s_box
  }
}

/*
 * This function executes the shift_rows step of the encryption. It takes a
 * reference to the block, the row index and how much that row should be
 * shifted.
 */
void shift_row(unsigned char *block, int row, int shift) {
  // allocate memory to store shifted row
  unsigned char *shifted_row = (unsigned char *)malloc(ROW_WIDTH * sizeof(unsigned char));
  // iterate over the row and store each value in the new position
  for (int i = 0; i < ROW_WIDTH; i++) {
    int j = i - shift;
    // wrap around incase i < shift
    if (j < 0) {
      j += ROW_WIDTH;
    }
    // wrap around if j > row height, make sure shifting works in both directions
    j %= ROW_WIDTH;
    shifted_row[j] = block[row + i * ROW_WIDTH];
  }
  // store shifted rows in the original buffer
  for (int i = 0; i < ROW_WIDTH; i++) {
    block[row + i * ROW_WIDTH] = shifted_row[i];
  }
}

/*
 * Utilise shift_row function to perform the shift_rows step of the encryption
 */
void shift_rows(unsigned char *block) {
  // row with index zero is not shifted
  for (int i = 1; i < COLUMN_HEIGHT; i++) {
    shift_row(block, i, i);
  }
}

/*
 * This function performs the xor operation used in the mix_columns step.
 * This is a direct translation from the Python implementation
 */
unsigned char xtime(unsigned char x) {
  if (x & 0x80) {
    return ((x << 1) ^ 0x1B) & 0xFF;
  } else {
    return (x << 1) & 0xFF;
  }
}

/*
 * Performs the mix_columns step for a single column during encryption
 * This is a direct translation from the Python implementation
 */
void mix_single_column(unsigned char *column) {
  unsigned char t = column[0] ^ column[1] ^ column[2] ^ column[3];
  unsigned char u = column[0];
  column[0] ^= t ^ xtime(column[0] ^ column[1]);
  column[1] ^= t ^ xtime(column[1] ^ column[2]);
  column[2] ^= t ^ xtime(column[2] ^ column[3]);
  column[3] ^= t ^ xtime(column[3] ^ u);
}

/*
 * Iterate over all columns, extract each and pass them to the mix_single_column
 * function. The result is then copied back onto the block.
 */
void mix_columns(unsigned char *block) {
  for (int i = 0; i < ROW_WIDTH; i++) {
    unsigned char *col = &block[i * COLUMN_HEIGHT];
    mix_single_column(col);
    memcpy(&block[i * COLUMN_HEIGHT], col, COLUMN_HEIGHT);
  }
}

/*
 * Operations used when decrypting a block
 */

/*
 * Uses the inv_s_box data to invert the byte subsitution when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    unsigned char c = block[i];
    unsigned char x = c >> 4;
    unsigned char y = c & 0xF;
    unsigned char inv = inv_s_box[x][y];
    block[i] = inv;
  }
}

/*
 * Use the shift_row function to invert the shift when decrypting a block
 */
void invert_shift_rows(unsigned char *block) {
  for (int i = 1; i < COLUMN_HEIGHT; i++) {
    shift_row(block, i, -i);
  }
}

/*
 * Invert the mix_column step for decryption
 */
void invert_mix_columns(unsigned char *block) {
  for (int i = 0; i < COLUMN_HEIGHT; i++) {
    unsigned char *column = &block[i * COLUMN_HEIGHT];
    unsigned char u = xtime(xtime(column[0] ^ column[2]));
    unsigned char v = xtime(xtime(column[1] ^ column[3]));
    column[0] ^= u;
    column[1] ^= v;
    column[2] ^= u;
    column[3] ^= v;
    memcpy(&block[i * COLUMN_HEIGHT], column, COLUMN_HEIGHT);
  }
  mix_columns(block);
}

/*
 * Adds the given round key to the given block by XORing each byte
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  for (int i = 0; i < BLOCK_SIZE; i++) {
    block[i] ^= round_key[i];
  }
}

/*
 * Performs the word rotation during key expansion
 */
unsigned char *rot_word(unsigned char *word) {
  unsigned char *rotated_word = (unsigned char *)malloc(COLUMN_HEIGHT * sizeof(unsigned char));
  for (int i = 0; i < COLUMN_HEIGHT; i++) {
    rotated_word[i] = word[(i + 1) % COLUMN_HEIGHT];
  }
  return rotated_word;
}

/*
 * XORs the bytes of two unsigned char buffers one by one and returns a resulting buffer
 */
unsigned char *xor_bytes(const unsigned char *a, const unsigned char *b, int length) {
  unsigned char *result = malloc(length);
  for (int i = 0; i < length; i++) {
    result[i] = a[i] ^ b[i];
  }
  return result;
}

/*
 * This function expands all round keys. Given a 128-bit key, it returns a
 * 176-byte block, containing the original key and the 10 round keys one after
 * the other.
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  unsigned char *round_keys = (unsigned char *)malloc(BLOCK_SIZE * (ROUNDS + 1) * sizeof(unsigned char));
  memcpy(round_keys, cipher_key, BLOCK_SIZE);
  for (int i = BLOCK_SIZE; i < (ROUNDS * BLOCK_SIZE) + BLOCK_SIZE; i += COLUMN_HEIGHT) {
    unsigned char *word = (unsigned char *)malloc(COLUMN_HEIGHT * sizeof(unsigned char));
    unsigned char *w1 = &round_keys[i - COLUMN_HEIGHT];  // column at w - 1
    unsigned char *w4 = &round_keys[i - BLOCK_SIZE];     // column at w - 4
    memcpy(word, w1, COLUMN_HEIGHT);  // copy the value of the previous column into the current column
    // if the column is at the start of a block, rotate the word
    // subsitute bytes and xor it with the correct round constant
    if (i % BLOCK_SIZE == 0) {
      unsigned char *rot_w1 = rot_word(w1);
      for (int j = 0; j < COLUMN_HEIGHT; j++) {
        unsigned char c = rot_w1[j];
        unsigned char x = c >> 4;
        unsigned char y = c & 0xF;
        unsigned char sub = s_box[x][y];
        rot_w1[j] = sub;
      }
      rot_w1[0] ^= rcon[i / BLOCK_SIZE];
      word = rot_w1;  // replace the original word with the modified one for further processing
    }
    unsigned char *xored_word =
        xor_bytes(word, w4, COLUMN_HEIGHT);  // xor the column with the same column of the previous block
    memcpy(&round_keys[i], xored_word,
           COLUMN_HEIGHT);  // copy the processed word to the current column of the key block
  }
  return round_keys;
}

/*
 * This function encrypts one block (16 bytes) of data with a given, 16 byte key
 * using the AES (Rijndael) algorithm. The output is 16 bytes of encrypted data.
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // allocate memory for output and round keys
  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned char *round_keys = expand_key(key);

  // store the plaintext in the output buffer where it will be encrypted
  memcpy(output, plaintext, BLOCK_SIZE);

  // perform the encryption steps with a total of 10 rounds
  add_round_key(output, round_keys);
  for (int i = 1; i < ROUNDS; i++) {
    sub_bytes(output);
    shift_rows(output);
    mix_columns(output);
    add_round_key(output, &round_keys[i * BLOCK_SIZE]);  // each round has a different key
  }
  sub_bytes(output);
  shift_rows(output);
  add_round_key(output, &round_keys[BLOCK_SIZE * ROUNDS]);
  return output;
}

/*
 * This function decrypts one block (16 bytes) of cyphertext with a given, 16 byte key
 * using the AES (Rijndael) algorithm. The output is 16 bytes of decrypted data.
 */
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key) {
  // allocate memory for output and round keys
  unsigned char *output = (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  unsigned char *round_keys = expand_key(key);

  // store the cyphertext in the output buffer where it will be decrypted
  memcpy(output, ciphertext, BLOCK_SIZE);

  // perform the decryption steps using the inverted functions
  // the round keys are added in reverse order
  add_round_key(output, &round_keys[BLOCK_SIZE * ROUNDS]);
  invert_shift_rows(output);
  invert_sub_bytes(output);
  for (int i = ROUNDS - 1; i > 0; i--) {
    add_round_key(output, &round_keys[i * BLOCK_SIZE]);
    invert_mix_columns(output);
    invert_shift_rows(output);
    invert_sub_bytes(output);
  }
  add_round_key(output, round_keys);
  return output;
}
