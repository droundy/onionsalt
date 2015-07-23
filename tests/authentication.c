#include "tweetnacl.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void randombytes(unsigned char * ptr,unsigned int length);

int main() {
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	unsigned char sk2[crypto_box_SECRETKEYBYTES];
	unsigned char pk2[crypto_box_PUBLICKEYBYTES];
	unsigned char nonce[crypto_box_NONCEBYTES];

  const int message_len = 137;
  unsigned char *message = malloc(message_len);
  randombytes(message, message_len);

	randombytes(nonce, crypto_box_NONCEBYTES);

	assert(!crypto_box_keypair(pk, sk));
	assert(!crypto_box_keypair(pk2, sk2));

  unsigned char *plaintext = calloc(1, message_len + crypto_box_ZEROBYTES);
  memcpy(plaintext + crypto_box_ZEROBYTES, message, message_len);

  unsigned char *ciphertext = malloc(message_len + crypto_box_ZEROBYTES);

  assert(!crypto_box(ciphertext, plaintext, message_len + crypto_box_ZEROBYTES,
                     nonce, pk2, sk));

  /* crypto_box leaves some blank padding at the beginning of the
     ciphertext, which we will want to strip when transimitting. */
  for (int i=0; i<crypto_box_BOXZEROBYTES; i++) assert(!ciphertext[i]);

  unsigned char *broken_ciphertext = malloc(message_len + crypto_box_ZEROBYTES);
  memcpy(broken_ciphertext, ciphertext, message_len + crypto_box_ZEROBYTES);
  unsigned char *newplaintext = malloc(message_len + crypto_box_ZEROBYTES);

  for (int i=crypto_box_BOXZEROBYTES;i<message_len + crypto_box_ZEROBYTES; i++) {
    printf("Modifying byte %d of broken_ciphertext...\n", i);
    while (broken_ciphertext[i] == ciphertext[i]) {
      randombytes(&broken_ciphertext[i], 1);
    }
    /* Verify that decryption fails. */
    assert(crypto_box_open(newplaintext, broken_ciphertext,
                           message_len + crypto_box_ZEROBYTES,
                           nonce, pk, sk2));
    /* Put that byte back again. */
    broken_ciphertext[i] = ciphertext[i];
  }
  return 0;
}
