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

  const int secret_length = 137;
  unsigned char *secret = malloc(secret_length);
	randombytes(secret, secret_length);

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

  unsigned long long layer_overhead = address_length + onion_box_LAYEROVERHEADBYTES;
  unsigned long long cb_len = crypto_box_ZEROBYTES + secret_length + num_layers*layer_overhead;
  unsigned char *ciphertext = malloc(cb_len);
  unsigned char *buffer = malloc(cb_len + num_layers*onion_box_PERLAYERBUFFERBYTES);
  assert(!onion_box(ciphertext,
                    buffer,
                    secret,
                    secret_length,
                    addresses,
                    address_length,
                    num_layers,
                    public_keys));

  return 0;
}
