#ifndef ONIONSALT_H
#define ONIONSALT_H

#include "tweetnacl.h"

#define onion_box_AUTHENTICATIONBYTES (crypto_box_ZEROBYTES \
                                       - crypto_box_BOXZEROBYTES)
#define onion_box_LAYEROVERHEADBYTES (onion_box_AUTHENTICATIONBYTES \
                                      + crypto_box_PUBLICKEYBYTES)
#define onion_box_PERLAYERBUFFERBYTES (onion_box_LAYEROVERHEADBYTES \
                                       + crypto_box_SECRETKEYBYTES \
                                       + crypto_box_PUBLICKEYBYTES)

extern int onion_box(unsigned char *ciphertext,
                     unsigned char *buffer,
                     const unsigned char *secret,
                     unsigned long long secret_length,
                     const unsigned char *addresses,
                     unsigned long long address_length,
                     int num_layers,
                     const unsigned char *their_public_keys);
/*

cb_length = crypto_box_ZEROBYTES + secret_length +
        (num_layers+1)*(address_length + onion_box_LAYEROVERHEADBYTES

    is the length that will be passed to crypto_box and
    crypto_box_open.

ciphertext[cb_length]

    holds the output ciphertext (and some padding).

buffer[cb_length + num_layers*onion_box_PERLAYERBUFFERBYTES]

    is just a buffer used for intermediate values, to avoid allocation
    in onion_box.

secret[secret_length]

    is the plaintext that is at the center of the onion, completely
    unpadded.

addresses[address_length*(num_layers-1)]

    holds all the routing information for all routers.

num_layers is the number of routers + 1.

their_public_keys[num_layers*crypto_box_PUBLICKEYBYTES]

    holds the public keys to which we want to encrypt.

 */

extern int onion_box_open(unsigned char *plaintext,
                          unsigned char *ciphertext,
                          unsigned long long cb_length,
                          unsigned long long address_length,
                          const unsigned char *secret_key);

/*

plaintext[cb_length]

    is the decrypted plaintext, with no padding on the left, but
    zero-padded on the right.

ciphertext[cb_length]

    holds the ciphertext.  There is no padding at the beginning, but
    it should be padded on the right.
    WARNING! The ciphertext is overwritten during the course of the
    decryption!

cb_length

    is the length of the two buffers, which should be address_length +
    crypto_box_PUBLICKEYBYTES + crypto_box_ZEROBYTES longer than the
    transmitted message was.

address_length

    is the length of the routing information.
 */

#endif
