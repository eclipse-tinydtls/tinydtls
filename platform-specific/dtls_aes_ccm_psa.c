
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

int
dtls_encrypt_params(const dtls_ccm_params_t *params,
                    const unsigned char *src, size_t length,
                    unsigned char *buf,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *aad, size_t la)
{
  size_t actual_len;

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_key_usage_t usage = PSA_KEY_USAGE_ENCRYPT;
  psa_set_key_usage_flags(&attr, usage);

  psa_algorithm_t algo = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, params->tag_length);
  psa_set_key_algorithm(&attr, algo);

  psa_key_type_t type = PSA_KEY_TYPE_AES;
  psa_set_key_type(&attr, type);

  psa_set_key_bits(&attr, keylen * 8);

  psa_import_key(&attr, key, keylen, &key_id);

  psa_status_t status = psa_aead_encrypt(key_id, algo, params->nonce, 15 - params->l, aad, la,
                                         src, length, buf, length + params->tag_length, &actual_len);
  
  psa_destroy_key(key_id);

  if (status == PSA_SUCCESS) {
    return (int) actual_len;
  }

  return -1;
}

int
dtls_decrypt_params(const dtls_ccm_params_t *params,
                    const unsigned char *src, size_t length,
                    unsigned char *buf,
                    const unsigned char *key, size_t keylen,
                    const unsigned char *aad, size_t la)
{
  size_t actual_len;

  psa_key_attributes_t attr = psa_key_attributes_init();
  psa_key_id_t key_id = 0;

  psa_key_usage_t usage = PSA_KEY_USAGE_DECRYPT;
  psa_set_key_usage_flags(&attr, usage);

  psa_algorithm_t algo = PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, params->tag_length);
  psa_set_key_algorithm(&attr, algo);

  psa_key_type_t type = PSA_KEY_TYPE_AES;
  psa_set_key_type(&attr, type);

  psa_set_key_bits(&attr, keylen * 8);

  psa_import_key(&attr, key, keylen, &key_id);

  psa_status_t status = psa_aead_decrypt(key_id, algo, params->nonce, 15 - params->l, aad, la,
                                         src, length, buf, length - params->tag_length, &actual_len);

  psa_destroy_key(key_id);
  
  if (status == PSA_SUCCESS) {
    return (int) actual_len;
  }

  return -1;
}
