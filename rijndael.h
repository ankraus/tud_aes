/*
 *           Name: Andreas Kraus
 * Student Number: D23125112
 *
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_SIZE 16
#define COLUMN_HEIGHT 4
#define ROW_WIDTH 4
#define ROUNDS 10
#define BLOCK_ACCESS(block, row, col) (block[(row * ROW_WIDTH) + col])

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
