#include "onionsalt.h"

#include <assert.h>
#include <string.h>

extern int onion_box(unsigned char *ciphertext,
                     unsigned char *buffer,
                     const unsigned char *secret,
                     unsigned long long secret_length,
                     const unsigned char *addresses,
                     unsigned long long address_length,
                     int num_layers,
                     const unsigned char *their_public_keys) {
  /* We always use a zero nonce. */
  const unsigned char nonce[crypto_box_NONCEBYTES] = {0};

  /* layer_overhead is the amount of space needed for each additional
     layer.  This ends up being equal to the amount of zero padding
     that we have to add to the end. */
  const long long layer_overhead =
    address_length + onion_box_LAYEROVERHEADBYTES;
  /* message_length is the length of the transmitted message. */
  const long long encrypted_length =
    secret_length + onion_box_AUTHENTICATIONBYTES
                  + (num_layers-1)*layer_overhead;
  /* cb_length is the length that we always pass to crypto_box.  It
     corresponds to encrypted_length plus one layer_overhead (filled
     with zeros at the end) plus crypto_box_BOXZEROBYTES. */
  const long long cb_length =
    crypto_box_BOXZEROBYTES + encrypted_length + layer_overhead;

  /* Here we split up the buffer into three sections: my_public_keys,
     my_private_keys, and plaintext. */
  unsigned char *my_public_keys = buffer;
  unsigned char *my_secret_keys =
    my_public_keys + num_layers*crypto_box_PUBLICKEYBYTES;
  for (int i=0;i<num_layers;i++) {
    crypto_box_keypair(my_public_keys + i*crypto_box_PUBLICKEYBYTES,
                       my_secret_keys + i*crypto_box_SECRETKEYBYTES);
  }
  unsigned char *plaintext = buffer
    + num_layers*(crypto_box_PUBLICKEYBYTES+crypto_box_SECRETKEYBYTES);

  memset(ciphertext, 0, cb_length);
  memset(plaintext, 0, cb_length);

  for (int i=0;i<num_layers;i++) {
    assert(!crypto_box(ciphertext, plaintext, cb_length, nonce,
                       their_public_keys + i*crypto_box_PUBLICKEYBYTES,
                       my_secret_keys + i*crypto_box_SECRETKEYBYTES));
    if (i == num_layers - 1) break;
    memcpy(plaintext + crypto_box_ZEROBYTES,
           ciphertext + crypto_box_ZEROBYTES + layer_overhead,
           cb_length - crypto_box_ZEROBYTES - layer_overhead);
  }
  memcpy(plaintext + crypto_box_ZEROBYTES,
         ciphertext + crypto_box_ZEROBYTES,
         cb_length - crypto_box_ZEROBYTES);
  /* At this stage, plaintext should be set up for the innermost layer
     of the onion, with everything but the actual plaintext that we
     want. */
  for (int i=num_layers-1;i>=0;i--) {
    /* Now we add the true message! */
    if (i == num_layers-1) {
      memcpy(plaintext + crypto_box_ZEROBYTES, secret, secret_length);
    } else {
      memcpy(plaintext + crypto_box_ZEROBYTES, addresses + i*address_length,
             address_length);
      memcpy(plaintext + crypto_box_ZEROBYTES + address_length,
             my_public_keys
             + (i+1)*crypto_box_PUBLICKEYBYTES, crypto_box_PUBLICKEYBYTES);
    }
    /* Now we encrypt the plaintext, which expands it just a tad. */
    int retval = crypto_box(ciphertext, plaintext, cb_length, nonce,
                            their_public_keys + i*crypto_box_PUBLICKEYBYTES,
                            my_secret_keys+i*crypto_box_SECRETKEYBYTES);
    if (retval) return retval;

    for (long long j=cb_length - layer_overhead; j<cb_length; j++) {
      assert(!ciphertext[j]);
    }
    if (i == 0) break;
    /* Now shift things to the right to make room for the next
       address and public key. */
    memcpy(plaintext + layer_overhead,
           ciphertext,
           cb_length - layer_overhead);
    memset(plaintext, 0, crypto_box_ZEROBYTES);
  }
  memmove(ciphertext + onion_box_AUTHENTICATIONBYTES,
          ciphertext,
          cb_length - layer_overhead);
  memcpy(ciphertext, my_public_keys, crypto_box_PUBLICKEYBYTES);
  memset(buffer, 0, cb_length + num_layers*onion_box_PERLAYERBUFFERBYTES);

  return 0;
}

int onion_box_open(unsigned char *plaintext,
                   unsigned char *ciphertext,
                   unsigned long long cb_length,
                   unsigned long long address_length,
                   const unsigned char *secret_key) {
  const long long layer_overhead =
    address_length + onion_box_LAYEROVERHEADBYTES;
  const long long encrypted_length =
    cb_length - crypto_box_BOXZEROBYTES - layer_overhead;
  const long long transmitted_length =
    encrypted_length + crypto_box_PUBLICKEYBYTES;

  /* first rescue the public key */
  unsigned char public_key[crypto_box_PUBLICKEYBYTES];
  memcpy(public_key, ciphertext, crypto_box_PUBLICKEYBYTES);
  /* then shift things into place for the decryption. */
  assert(crypto_box_PUBLICKEYBYTES == crypto_box_ZEROBYTES);
  memmove(ciphertext + crypto_box_BOXZEROBYTES,
          ciphertext + crypto_box_PUBLICKEYBYTES,
          cb_length - crypto_box_PUBLICKEYBYTES);
  /* zero out the initial padding */
  memset(ciphertext, 0, crypto_box_BOXZEROBYTES);
  /* zero out the extra padding at the end */
  //memset(ciphertext + cb_length - layer_overhead, 0, layer_overhead);
  /* we just always use a zero nonce, since we never reuse a public
     key for encryption */
  unsigned char nonce[crypto_box_NONCEBYTES] = {0};

  int retval = crypto_box_open(plaintext, ciphertext,
                               cb_length, nonce, public_key, secret_key);
  memmove(plaintext, plaintext + crypto_box_ZEROBYTES,
          transmitted_length + address_length);
  memset(plaintext+transmitted_length + address_length, 0,
         cb_length - transmitted_length - address_length);
  return retval;
}
