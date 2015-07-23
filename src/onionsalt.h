#ifndef ONIONSALT_H
#define ONIONSALT_H

#include "tweetnacl.h"

#define onion_box_LAYEROVERHEADBYTES (crypto_box_ZEROBYTES - crypto_box_BOXZEROBYTES \
                                      + crypto_box_PUBLICKEYBYTES)

#define onion_box_PERLAYERBUFFERBYTES (onion_box_LAYEROVERHEADBYTES + crypto_box_SECRETKEYBYTES + crypto_box_PUBLICKEYBYTES)

/*

ciphertext[crypto_box_ZEROBYTES + interior_plaintext_length
           + (num_layers+1)*(address_length + onion_box_LAYEROVERHEADBYTES)]

    holds the output ciphertext (and a bit extra), of which the first
    crypto_box_BOXZEROBYTES will be zero.

buffer[crypto_box_ZEROBYTES + interior_plaintext_length
       + (num_layers+1)*(address_length + onion_box_LAYEROVERHEADBYTES)
       + num_layers*onion_box_PERLAYERBUFFERBYTES]

    is just a buffer used for intermediate values.  Should be set to
    zero upon return to hide any intermediate results from later
    leakage.

interior_plaintext[interior_plaintext_length]

    is the plaintext that is at the center of the onion, completely
    unpadded.

address_labels[address_label_length*num_layers]

    holds all the "address labels", which is to say the cleartext
    intended for intermediary parties.

their_public_keys[num_layers*crypto_box_PUBLICKEYBYTES]

    holds the public keys to which we want to encrypt.

onion_box generates a new key pair for each layer so as to ensure
anonymity, and transmits the public key in the box so it can be
decrypted.  A zero nonce is always used, since each layer involves a
unique key.

 */

extern int onion_box(unsigned char *ciphertext,
                     unsigned char *buffer,
                     const unsigned char *plaintext,
                     unsigned long long interior_plaintext_length,
                     const unsigned char *address_labels,
                     unsigned long long address_label_length,
                     int num_layers,
                     const unsigned char *their_public_keys);


/*


plaintext[length]

    is the decrypted plaintext.  The first crypto_box_ZEROBYTES are
    zero, and the remaining bytes hold the decrypted bytes.

ciphertext[length]

    holds the ciphertext.  There is no padding at the beginning, but
    the end should be padded with address_label_length bytes.
    WARNING! The ciphertext is overwritten during the course of the
    decryption!

length

    is the length of the two buffers, which should be
    crypto_box_BOXZEROBYTES + address_label_length longer than the
    transmitted message was.

address_label_length

    is the length of the decrypted "address_label", which is going to
    be clear to this user, unless this is the interior box, in which
    case the amount of cleartext will have been determined by the call
    to onion_box.


onion_box_open opens one layer of an onion box.

 */

extern int onion_box_open(unsigned char *plaintext,
                          unsigned char *ciphertext,
                          unsigned long long length,
                          unsigned long long address_label_length,
                          const unsigned char *secret_key);

#endif
