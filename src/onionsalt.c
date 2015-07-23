#include "onionsalt.h"

#include <string.h>

extern int onion_box(unsigned char *ciphertext,
                     unsigned char *buffer,
                     const unsigned char *interior_plaintext,
                     unsigned long long interior_plaintext_length,
                     const unsigned char *address_labels,
                     unsigned long long address_label_length,
                     int num_layers,
                     const unsigned char *their_public_keys) {
  /* We always use a zero nonce. */
  const unsigned char nonce[crypto_box_NONCEBYTES] = {0};

  /* layer_overhead is the amount of space needed for each additional
     layer.  This ends up being equal to the amount of zero padding
     that we have to add to the end. */
  const long long layer_overhead = address_label_length + onion_box_LAYEROVERHEADBYTES;
  /* message_length is the length of the transmitted message. */
  const long long message_length = interior_plaintext_length + num_layers*layer_overhead;
  /* cb_len is the length that we always pass to crypto_box.  It
     corresponds to message_length plus one layer_overhead (filled
     with zeros at the end) plus crypto_box_ZEROBYTES, which we pad at
     the beginning, minus crypto_box_PUBLICKEYBYTES, since we do not
     encrypt the public key (which would defeat the purpose of
     including it). */
  const long long cb_len = crypto_box_ZEROBYTES + message_length - crypto_box_PUBLICKEYBYTES + layer_overhead;

  /* Here we split up the buffer into three sections: my_public_keys,
     my_private_keys, and plaintext. */
  unsigned char *my_public_keys = buffer;
  unsigned char *my_secret_keys = my_public_keys + num_layers*crypto_box_PUBLICKEYBYTES;
  for (int i=0;i<num_layers;i++) {
    crypto_box_keypair(my_public_keys + i*crypto_box_PUBLICKEYBYTES,
                       my_secret_keys + i*crypto_box_SECRETKEYBYTES);
  }
  unsigned char *plaintext = buffer + num_layers*(crypto_box_PUBLICKEYBYTES + crypto_box_SECRETKEYBYTES);

  memset(plaintext, 0, cb_len);
  for (int i=0;i<num_layers;i++) {
    int retval = crypto_box(ciphertext, plaintext, cb_len, nonce,
                            their_public_keys + i*crypto_box_PUBLICKEYBYTES,
                            my_secret_keys+i*crypto_box_SECRETKEYBYTES);
    if (retval) return retval;
    memcpy(plaintext + crypto_box_ZEROBYTES,
           ciphertext + crypto_box_BOXZEROBYTES + layer_overhead,
           cb_len - crypto_box_BOXZEROBYTES - layer_overhead);
    memset(plaintext, 0, crypto_box_ZEROBYTES);
    memset(plaintext + cb_len - layer_overhead, 0, layer_overhead);
  }
  /* At this stage, plaintext should be set up for the innermost layer
     of the onion, with everything but the actual plaintext that we
     want. */
  for (int i=num_layers-1;i>=0;i--) {
    /* There should already be room for the true message at the beginning. */
    if (i == num_layers-1) {
      memcpy(plaintext + crypto_box_ZEROBYTES, interior_plaintext, interior_plaintext_length);
    } else {
      memcpy(plaintext + crypto_box_ZEROBYTES, address_labels + i*address_label_length, address_label_length);
    }
    /* Now we encrypt the plaintext, which expands it just a tad. */
    int retval = crypto_box(ciphertext, plaintext, cb_len, nonce,
                            their_public_keys + i*crypto_box_PUBLICKEYBYTES,
                            my_secret_keys+i*crypto_box_SECRETKEYBYTES);
    if (retval) return retval;
    /* Now to construct our message, we need to add our public key at
       the very beginning, which means budging things over a tad.
       And, of course, copying over to plaintext for the next round of
       fun. */
    memcpy(plaintext + crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES,
           ciphertext + crypto_box_BOXZEROBYTES, cb_len - crypto_box_ZEROBYTES);
    /* Finally, we just need to copy our public key into the gap we left. */
    memcpy(plaintext + crypto_box_ZEROBYTES,
           my_public_keys + i*crypto_box_PUBLICKEYBYTES,
           crypto_box_PUBLICKEYBYTES);
  }
  memcpy(ciphertext, plaintext + crypto_box_ZEROBYTES, message_length);

  return 0;
}

int onion_box_open(unsigned char *plaintext,
                   unsigned char *ciphertext,
                   unsigned long long length,
                   unsigned long long address_label_length,
                   const unsigned char *secret_key) {
  const long long layer_overhead = address_label_length + onion_box_LAYEROVERHEADBYTES;
  const long long cb_len = crypto_box_BOXZEROBYTES + length - crypto_box_PUBLICKEYBYTES;

  /* first rescue the public key */
  unsigned char public_key[crypto_box_PUBLICKEYBYTES];
  memcpy(public_key, ciphertext, crypto_box_PUBLICKEYBYTES);
  /* then shift things into place for the decryption. */
  memmove(ciphertext + crypto_box_BOXZEROBYTES,
          ciphertext + crypto_box_PUBLICKEYBYTES,
          length - crypto_box_PUBLICKEYBYTES - layer_overhead);
  /* zero out the initial padding */
  memset(ciphertext, 0, crypto_box_BOXZEROBYTES);
  /* zero out the extra padding at the end */
  memset(ciphertext + (cb_len - layer_overhead), 0, layer_overhead);
  /* we just always use a zero nonce, since we never reuse a public
     key for encryption */
  unsigned char nonce[crypto_box_NONCEBYTES] = {0};

  return crypto_box_open(plaintext, ciphertext, cb_len, nonce, public_key, secret_key);
}
