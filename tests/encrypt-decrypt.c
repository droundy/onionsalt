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

	crypto_box_keypair(pk, sk);
	crypto_box_keypair(pk2, sk2);

  unsigned char *plaintext = calloc(1, message_len + crypto_box_ZEROBYTES);
  memcpy(plaintext + crypto_box_ZEROBYTES, message, message_len);

  unsigned char *ciphertext = malloc(message_len + crypto_box_ZEROBYTES);

  crypto_box(ciphertext, plaintext, message_len + crypto_box_ZEROBYTES,
             nonce, pk2, sk);

  /* crypto_box leaves some blank padding at the beginning of the
     ciphertext, which we will want to strip when transimitting. */
  for (int i=0; i<crypto_box_BOXZEROBYTES; i++) assert(!ciphertext[i]);

  unsigned char *newplaintext = malloc(message_len + crypto_box_ZEROBYTES);
  crypto_box_open(newplaintext,ciphertext, message_len + crypto_box_ZEROBYTES,
                  nonce, pk, sk2);

  /* Verify that crypto_box_open gives us back our padded plaintext. */
  for (int i=0; i<message_len + crypto_box_ZEROBYTES; i++) {
    assert(newplaintext[i] == plaintext[i]);
  }
  /* Just for completeness, verify that the padded plaintext actually
     contains the original message.  Really, this just checks that we
     didn't manage to screw up our memcpy above. */
  for (int i=0; i<message_len; i++) {
    assert(newplaintext[i + crypto_box_ZEROBYTES] == message[i]);
  }
  return 0;
}
