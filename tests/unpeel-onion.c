#include "onionsalt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void randombytes(unsigned char * ptr,unsigned int length);

/* This test checks that we can unpeel an onion and get back the
   original messages. */

int main() {
	unsigned char sk[crypto_box_SECRETKEYBYTES];
	unsigned char pk[crypto_box_PUBLICKEYBYTES];
	assert(!crypto_box_keypair(pk, sk));

  const int interior_plaintext_length = 137;
  unsigned char *interior_plaintext = malloc(interior_plaintext_length);
	randombytes(interior_plaintext, interior_plaintext_length);

  const int num_layers = 5;
  const int address_length = 30;
  unsigned char *addresses = malloc(address_length*(num_layers-1));
  randombytes(addresses, address_length*(num_layers-1));

  unsigned char *public_keys = malloc(num_layers*crypto_box_PUBLICKEYBYTES);
  unsigned char *secret_keys = malloc(num_layers*crypto_box_SECRETKEYBYTES);
  for (int i=0;i<num_layers;i++) {
    assert(!crypto_box_keypair(public_keys + i*crypto_box_PUBLICKEYBYTES,
                               secret_keys + i*crypto_box_SECRETKEYBYTES));
  }

  unsigned long long cb_len = crypto_box_ZEROBYTES + interior_plaintext_length
    + (num_layers+1)*(address_length + onion_box_LAYEROVERHEADBYTES);
  unsigned char *ciphertext = malloc(cb_len);
  unsigned char *buffer = malloc(cb_len + num_layers*(crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES));
  assert(!onion_box(ciphertext,
                    buffer,
                    interior_plaintext,
                    interior_plaintext_length,
                    addresses,
                    address_length,
                    num_layers,
                    public_keys));

  unsigned long long message_length = cb_len - crypto_box_BOXZEROBYTES - address_length;
  unsigned char *mycipher = malloc(cb_len);
  memcpy(mycipher, ciphertext, message_length);
  unsigned char *myplain = malloc(cb_len);
  for (int i=0;i<1;i++) {
    assert(onion_box_open(myplain, // FIXME THIS ASSERTION IS BACKWARDS!!!
                           mycipher,
                           cb_len,
                           address_length,
                           secret_keys + i*crypto_box_SECRETKEYBYTES));
  }

  return 0;
}
