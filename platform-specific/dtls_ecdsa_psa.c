/*******************************************************************************
 *
 * Copyright (c) 2011-2025 Lukas Luger (TUD) and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v. 1.0 which accompanies this distribution.
 *
 * The Eclipse Public License is available at http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at 
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * Contributors:
 *    Lukas Luger    - adding psa crypto support
 *
 *******************************************************************************/
#include "crypto.h"
#include "psa/crypto.h"
#include "numeric.h"
#include "hmac.h"

/* 0x04<1>, x_P <DTLS_EC_KEY_SIZE>, y_P <DTLS_EC_KEY_SIZE> */
#define DTLS_EC_PUB_KEY_SIZE   (1 + 2 * DTLS_EC_KEY_SIZE)

/* curve type<1>, namedcurve<2>, 
 * pub_key_size<1>, pub_key<DTLS_EC_PUB_KEY_SIZE>
 */
#define DTLS_KEYX_PARAMS_SIZE  (4 + DTLS_EC_PUB_KEY_SIZE)

void
dtls_ecdsa_generate_key(unsigned char *priv_key,
            unsigned char *pub_key_x,
            unsigned char *pub_key_y,
            size_t key_size) {
  assert(DTLS_EC_KEY_SIZE == key_size);

  uint8_t public_key[DTLS_EC_PUB_KEY_SIZE]; 

  size_t actual_len;

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  /* usage flags
   * only export needed, because no use of psa key storage
   */
  psa_key_usage_t usage = PSA_KEY_USAGE_EXPORT;
  psa_set_key_usage_flags(&attr, usage);
  
  /* permitted alg
   * PSA_ALG_ECDSA(PSA_ALG_SHA_256) - with hashing
   */
  psa_algorithm_t algo = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
  psa_set_key_algorithm(&attr, algo);
  
  /* type for ECDSA with hashing (weierstrass family) */
  psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
  psa_set_key_type(&attr, type);
  
  psa_set_key_bits(&attr, DTLS_EC_KEY_SIZE * 8);
  
  psa_generate_key(&attr, &key_id);
  
  psa_export_public_key(key_id, public_key, PSA_EXPORT_PUBLIC_KEY_MAX_SIZE, &actual_len);
  
  if(actual_len != DTLS_EC_PUB_KEY_SIZE) return;
 
  memcpy(pub_key_x, &public_key[1], DTLS_EC_KEY_SIZE);
  memcpy(pub_key_y, &public_key[1 + DTLS_EC_KEY_SIZE], DTLS_EC_KEY_SIZE); 

  psa_export_key(key_id, (uint8_t *)priv_key, DTLS_EC_KEY_SIZE, &actual_len);

  psa_destroy_key(key_id);
}

/* rfc4492#section-5.4 */
void
dtls_ecdsa_create_sig_hash(const unsigned char *priv_key, size_t key_size,
               const unsigned char *sign_hash, size_t sign_hash_size,
               uint32_t point_r[9], uint32_t point_s[9]) {
  assert(DTLS_EC_KEY_SIZE == key_size);
  assert(DTLS_HMAC_DIGEST_SIZE == sign_hash_size);

  size_t actual_len;

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_HASH;
  psa_set_key_usage_flags(&attr, usage);

  /* permitted alg
   * PSA_ALG_ECDSA_ANY - randomized, without hashing
   */
  psa_algorithm_t algo = PSA_ALG_ECDSA_ANY;
  psa_set_key_algorithm(&attr, algo);

  /* type for ECDSA without hashing (weierstrass family) */
  psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
  psa_set_key_type(&attr, type);

  psa_set_key_bits(&attr, DTLS_EC_KEY_SIZE * 8);

  psa_import_key(&attr, (uint8_t *)priv_key, DTLS_EC_KEY_SIZE, &key_id);

  size_t sig_len = PSA_SIGN_OUTPUT_SIZE(type, DTLS_EC_KEY_SIZE * 8, algo);
  uint8_t sig[sig_len]; 

  psa_sign_hash(key_id, algo, (uint8_t *)sign_hash, DTLS_HMAC_DIGEST_SIZE, sig, sig_len, &actual_len);

  if(actual_len != sig_len) return;

  dtls_ec_key_from_uint32((uint32_t *)&sig[0], sig_len/2, (unsigned char *)point_r);
  dtls_ec_key_from_uint32((uint32_t *)&sig[sig_len/2], sig_len/2, (unsigned char *)point_s);  
  
  psa_destroy_key(key_id);
}

void
dtls_ecdsa_create_sig(const unsigned char *priv_key, size_t key_size,
              const unsigned char *client_random, size_t client_random_size,
              const unsigned char *server_random, size_t server_random_size,
              const unsigned char *keyx_params, size_t keyx_params_size,
              uint32_t point_r[9], uint32_t point_s[9]) {
  assert(DTLS_EC_KEY_SIZE == key_size);
  assert(DTLS_RANDOM_LENGTH == client_random_size);
  assert(DTLS_RANDOM_LENGTH == server_random_size);
  assert(DTLS_KEYX_PARAMS_SIZE == keyx_params_size);
  /* psa only accepts uint8 arrays */
  uint8_t message[2 * DTLS_RANDOM_LENGTH + DTLS_KEYX_PARAMS_SIZE];
  memcpy(&message[0], client_random, DTLS_RANDOM_LENGTH);
  memcpy(&message[DTLS_RANDOM_LENGTH], server_random, DTLS_RANDOM_LENGTH);
  memcpy(&message[2 * DTLS_RANDOM_LENGTH], keyx_params, DTLS_KEYX_PARAMS_SIZE);

  size_t actual_len; 

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_key_usage_t usage = PSA_KEY_USAGE_SIGN_MESSAGE;
  psa_set_key_usage_flags(&attr, usage);
  
  /* permitted alg
   * PSA_ALG_ECDSA(PSA_ALG_SHA_256) - with hashing
   */
  psa_algorithm_t algo = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
  psa_set_key_algorithm(&attr, algo);
  
  /* type for ECDSA with hashing (weierstrass family) */
  psa_key_type_t type = PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1);
  psa_set_key_type(&attr, type);

  psa_set_key_bits(&attr, DTLS_EC_KEY_SIZE * 8);
  
  psa_import_key(&attr, (uint8_t *)priv_key, DTLS_EC_KEY_SIZE, &key_id);

  size_t sig_len = PSA_SIGN_OUTPUT_SIZE(type, DTLS_EC_KEY_SIZE * 8, algo);
  uint8_t sig[sig_len]; 
  
  psa_sign_message(key_id, algo, message, sizeof(message), sig, sig_len, &actual_len);

  if(actual_len != sig_len) return;

  dtls_ec_key_from_uint32((uint32_t *)&sig[0], sig_len/2, (unsigned char *)point_r);
  dtls_ec_key_from_uint32((uint32_t *)&sig[sig_len/2], sig_len/2, (unsigned char *)point_s);

  psa_destroy_key(key_id);
}

/* rfc4492#section-5.4 */
int
dtls_ecdsa_verify_sig_hash(const unsigned char *pub_key_x,
               const unsigned char *pub_key_y, size_t key_size,
               const unsigned char *sign_hash, size_t sign_hash_size,
               unsigned char *result_r, unsigned char *result_s) {
  assert(DTLS_EC_KEY_SIZE == key_size);
  assert(DTLS_HMAC_DIGEST_SIZE == sign_hash_size);
  /* psa only accepts uint8 arrays */
  uint8_t public_key[DTLS_EC_PUB_KEY_SIZE];
  public_key[0] = 0x04;
  memcpy(&public_key[1], pub_key_x, DTLS_EC_KEY_SIZE);
  memcpy(&public_key[1 + DTLS_EC_KEY_SIZE], pub_key_y, DTLS_HMAC_DIGEST_SIZE);

  uint8_t sig[DTLS_EC_KEY_SIZE * 2];
  memcpy(&sig[0], result_r, DTLS_EC_KEY_SIZE); 
  memcpy(&sig[DTLS_EC_KEY_SIZE], result_s, DTLS_EC_KEY_SIZE);
  
  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_key_usage_t usage = PSA_KEY_USAGE_VERIFY_HASH;
  psa_set_key_usage_flags(&attr, usage);
  
  /* permitted alg
   * PSA_ALG_ECDSA_ANY - randomized, without hashing
   */
  psa_algorithm_t algo = PSA_ALG_ECDSA_ANY;
  psa_set_key_algorithm(&attr, algo);
  
  /* type for ECDSA without hashing (weierstrass family) */
  psa_key_type_t type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
  
  psa_set_key_type(&attr, type);

  psa_set_key_bits(&attr, DTLS_EC_KEY_SIZE * 8);

  psa_import_key(&attr, public_key, DTLS_EC_PUB_KEY_SIZE, &key_id);
  
  psa_status_t ret = psa_verify_hash(key_id, algo, (uint8_t *)sign_hash, DTLS_HMAC_DIGEST_SIZE, sig, DTLS_EC_KEY_SIZE * 2);

  psa_destroy_key(key_id);

  return ret;
}

int
dtls_ecdsa_verify_sig(const unsigned char *pub_key_x,
              const unsigned char *pub_key_y, size_t key_size,
              const unsigned char *client_random, size_t client_random_size,
              const unsigned char *server_random, size_t server_random_size,
              const unsigned char *keyx_params, size_t keyx_params_size,
              unsigned char *result_r, unsigned char *result_s) {
  assert(DTLS_EC_KEY_SIZE == key_size);
  assert(DTLS_RANDOM_LENGTH == client_random_size);
  assert(DTLS_RANDOM_LENGTH == server_random_size);
  assert(DTLS_KEYX_PARAMS_SIZE == keyx_params_size);
  /* psa only accepts uint8 arrays */
  uint8_t public_key[DTLS_EC_PUB_KEY_SIZE];
  public_key[0] = 0x04;
  memcpy(&public_key[1], pub_key_x, DTLS_EC_KEY_SIZE);
  memcpy(&public_key[1+ DTLS_EC_KEY_SIZE], pub_key_y, DTLS_EC_KEY_SIZE);

  uint8_t message[2 * DTLS_RANDOM_LENGTH + DTLS_KEYX_PARAMS_SIZE];
  memcpy(&message[0], client_random, DTLS_RANDOM_LENGTH);
  memcpy(&message[DTLS_RANDOM_LENGTH], server_random, DTLS_RANDOM_LENGTH);
  memcpy(&message[2 * DTLS_RANDOM_LENGTH], keyx_params, DTLS_KEYX_PARAMS_SIZE);

  uint8_t sig[DTLS_EC_KEY_SIZE * 2];
  memcpy(&sig[0], result_r, DTLS_EC_KEY_SIZE); 
  memcpy(&sig[DTLS_EC_KEY_SIZE], result_s, DTLS_EC_KEY_SIZE);

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_key_usage_t usage = PSA_KEY_USAGE_VERIFY_MESSAGE;
  psa_set_key_usage_flags(&attr, usage);
  
  /* permitted alg
   * PSA_ALG_ECDSA(PSA_ALG_SHA_256) - with hashing
   */
  psa_algorithm_t algo = PSA_ALG_ECDSA(PSA_ALG_SHA_256);
  psa_set_key_algorithm(&attr, algo);
  
  /* type for ECDSA with hashing (weierstrass family) */
  psa_key_type_t type = PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1);
  psa_set_key_type(&attr, type);

  psa_set_key_bits(&attr, DTLS_EC_KEY_SIZE * 8);
 
  psa_import_key(&attr, public_key, DTLS_EC_PUB_KEY_SIZE, &key_id);
  
  psa_status_t ret = psa_verify_message(key_id, algo, message, sizeof(message), sig, DTLS_EC_KEY_SIZE * 2);

  psa_destroy_key(key_id);

  return ret;
}
