#include "onionsalt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

void randombytes(unsigned char * ptr,unsigned int length);

/* This test only verifies that we can call onion_box without causing
   a segfault or crash. */

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

  return 0;
}
