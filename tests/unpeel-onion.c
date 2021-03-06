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

  const int secret_length = 17;
  unsigned char *secret = malloc(secret_length);
	randombytes(secret, secret_length);

  const int num_layers = 5;
  const int address_length = 51;
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

  //unsigned long long transmitted_length = cb_len - layer_overhead - crypto_box_BOXZEROBYTES + crypto_box_PUBLICKEYBYTES;
  unsigned char *mycipher = malloc(cb_len);
  memcpy(mycipher, ciphertext, cb_len);
  unsigned char *myplain = malloc(cb_len);
  for (int i=0;i<num_layers;i++) {
    printf("Attempting to unpeel layer %d\n", i);
    assert(!onion_box_open(myplain,
                           mycipher,
                           cb_len,
                           address_length,
                           secret_keys + i*crypto_box_SECRETKEYBYTES));
    if (i < num_layers-1) {
      assert(!memcmp(addresses + i*address_length, myplain, address_length));
      memset(mycipher, 0, cb_len);
      memcpy(mycipher, myplain + address_length, cb_len - layer_overhead+16);
    } else {
      assert(!memcmp(secret, myplain, secret_length));
    }
    printf("Unpeel worked!!!\n");
  }

  return 0;
}
