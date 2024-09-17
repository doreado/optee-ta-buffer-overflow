/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

/* _utee_log and _utee_return */
#include <utee_syscalls.h>

#include <aes_ta.h>

#define AES128_KEY_BIT_SIZE 128
#define AES128_KEY_BYTE_SIZE (AES128_KEY_BIT_SIZE / 8)
#define AES256_KEY_BIT_SIZE 256
#define AES256_KEY_BYTE_SIZE (AES256_KEY_BIT_SIZE / 8)
#define BUFFER_SIZE 64

/*
 * Ciphering context: each opened session relates to a cipehring operation.
 * - configure the AES flavour from a command.
 * - load key from a command (here the key is provided by the REE)
 * - reset init vector (here IV is provided by the REE)
 * - cipher a buffer frame (here input and output buffers are non-secure)
 */
struct aes_cipher {
  uint32_t algo;                 /* AES flavour */
  uint32_t mode;                 /* Encode or decode */
  uint32_t key_size;             /* AES key size in byte */
  TEE_OperationHandle op_handle; /* AES ciphering operation */
  TEE_ObjectHandle key_handle;   /* transient object to load the key */
  char key_buffer[BUFFER_SIZE];  /* Buffer to store the key */
};

const char *SECRET = "09 F9 11 02 9D 74 E3 5B D8 41 56 C5 63 56 88 C0";
bool PRINTSECRET = false;

static char const remember_id[] =
    "storage:b39193c4-bff6-4325-9598-0753f0ec1fd2"; // some magic string shorter
                                                    // than 64 bytes

static char *session_name;

/* Obsolete in newer optee */
static inline uint64_t reg_pair_to_64(uint32_t reg0, uint32_t reg1) {
  return (uint64_t)reg0 << 32 | reg1;
}

static inline void reg_pair_from_64(uint64_t val, uint32_t *reg0,
                                    uint32_t *reg1) {
  *reg0 = val >> 32;
  *reg1 = val;
}

/*
 * Few routines to convert IDs from TA API into IDs from OP-TEE.
 */
static TEE_Result ta2tee_algo_id(uint32_t param, uint32_t *algo) {
  switch (param) {
  case TA_AES_ALGO_ECB:
    *algo = TEE_ALG_AES_ECB_NOPAD;
    return TEE_SUCCESS;
  case TA_AES_ALGO_CBC:
    *algo = TEE_ALG_AES_CBC_NOPAD;
    return TEE_SUCCESS;
  case TA_AES_ALGO_CTR:
    *algo = TEE_ALG_AES_CTR;
    return TEE_SUCCESS;
  default:
    EMSG("Invalid algo %u", param);
    return TEE_ERROR_BAD_PARAMETERS;
  }
}
static TEE_Result ta2tee_key_size(uint32_t param, uint32_t *key_size) {
  switch (param) {
  case AES128_KEY_BYTE_SIZE:
  case AES256_KEY_BYTE_SIZE:
    *key_size = param;
    return TEE_SUCCESS;
  default:
    EMSG("Invalid key size %u", param);
    return TEE_ERROR_BAD_PARAMETERS;
  }
}
static TEE_Result ta2tee_mode_id(uint32_t param, uint32_t *mode) {
  switch (param) {
  case TA_AES_MODE_ENCODE:
    *mode = TEE_MODE_ENCRYPT;
    return TEE_SUCCESS;
  case TA_AES_MODE_DECODE:
    *mode = TEE_MODE_DECRYPT;
    return TEE_SUCCESS;
  default:
    EMSG("Invalid mode %u", param);
    return TEE_ERROR_BAD_PARAMETERS;
  }
}

/* Creates a persistent object with `remember_id` to recall later. */
static TEE_Result call_remember(uint32_t param_types, TEE_Param params[4]) {
  uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
                      TEE_PARAM_TYPE_NONE, // output its address (insecure!)
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  // SIGN();

  // oops, I forgot...
  if (param_types != exp_param_types) {
  } // return TEE_ERROR_BAD_PARAMETERS;

  TEE_Result res;
  TEE_ObjectHandle handle;
  res = TEE_CreatePersistentObject(
      TEE_STORAGE_PRIVATE,              // storage id
      remember_id, sizeof(remember_id), // object id
      0 |                               // access flags
          0 |                           // sharing flags
          TEE_DATA_FLAG_OVERWRITE,      // overwrite if present
      NULL, // attributes, here pure data object TEE_TYPE_DATA
      params[0].memref.buffer, params[0].memref.size, // initial data contents
      &handle                                         // output
  );

  if (res != TEE_SUCCESS) {
    DMSG("Remember failed, code: %u", (unsigned int)res);
    return res;
  }

  TEE_CloseObject(handle);
  return TEE_SUCCESS;
}

void hint(char iterations);
void hint(char iterations) { DMSG("Iteration: %i", iterations); }

/**
Intended to avoid GCC optimizing away recursion, which it can't due to
referenced memory arrays. textlen: like strlen, not a size.
*/
char *fibufnacci(const char *text, size_t textlen, const char *textprev,
                 size_t textprevlen, char iterations);
char *fibufnacci(const char *text, size_t textlen, const char *textprev,
                 size_t textprevlen, char iterations) {
  DMSG("With params: %p, %zu, %p, %zu, %i", text, textlen, textprev,
       textprevlen, (int)iterations);
  DMSG("With values: %s, %s", text, textprev); /*vuln*/
  char tmp[128];
  if (iterations == 0) {
    // DMSG("strduping"); /*vuln*/
    return strdup(text);
  } else {
    memcpy(&tmp[0], text, textlen);               /*vuln*/
    memcpy(&tmp[textlen], textprev, textprevlen); /*vuln*/

    // char* address = (char*)tmp;
    // IMSG("    %16p: %02hhx %02hhx  %02hhx %02hhx", (void*)address,
    // address[0], address[1], address[2], address[3]); address+=4; IMSG(" %16p:
    // %02hhx %02hhx  %02hhx %02hhx", (void*)address, address[0], address[1],
    // address[2], address[3]); address+=4; IMSG("    %16p: %02hhx %02hhx %02hhx
    // %02hhx", (void*)address, address[0], address[1], address[2], address[3]);
    // address+=4;

    // tmp[textlen+textprevlen-1] += 1;
    // if (tmp[textlen+textprevlen-1] > 126)
    // tmp[textlen+textprevlen] -= ' ';

    tmp[textlen + textprevlen] = 0;
  }

  hint(iterations);
  DMSG("%s", tmp);
  return fibufnacci(tmp, textlen + textprevlen, text, textlen, iterations - 1);
}

static TEE_Result call_fibufnacci(uint32_t param_types, TEE_Param params[4]) {
  uint32_t exp_param_types = TEE_PARAM_TYPES(
      TEE_PARAM_TYPE_MEMREF_INOUT, // input a buffer, output with buffer size
      TEE_PARAM_TYPE_VALUE_INOUT, // input a size (input a buffer is longer than
                                  // input)
      TEE_PARAM_TYPE_MEMREF_INPUT, // input b with size
      TEE_PARAM_TYPE_VALUE_INPUT   // iterations
  );

  // SIGN();

  // oops, I forgot...
  if (param_types != exp_param_types) {
  } // return TEE_ERROR_BAD_PARAMETERS;

  DMSG("Hello, I'm VULN!\n");
  DMSG("fibufnacci is at %p", (void *)fibufnacci);
  DMSG("memcpy is at %p", (void *)memcpy);
  DMSG("TA_OpenSessionEntryPoint is at %p", (void *)TA_OpenSessionEntryPoint);
  DMSG("TEE_InvokeTACommand is at %p", (void *)TEE_InvokeTACommand);
  DMSG("utee_log is at %p", (void *)_utee_log);
  DMSG("utee_return is at %p", (void *)_utee_return);
  DMSG("SECRET is at %p", (void *)SECRET);
  DMSG("TEE_ReadObjectData is at %p", (void *)TEE_ReadObjectData);

  // fibufnacci("a",1,"a",1, 6);

  size_t size0 = reg_pair_to_64(params[1].value.a, params[1].value.b);
  size_t size2 = params[2].memref.size;
  size_t iterations = reg_pair_to_64(params[3].value.a, params[3].value.b);

  // INOUT memrefs might be larger than we shall use (to fit a longer result,
  // too), but must not be shorter.
  if (size0 > params[0].memref.size) {
    DMSG("refusing short input buffer a with size %u!", params[0].memref.size);
    return TEE_ERROR_SHORT_BUFFER;
  }

  char *result = fibufnacci((char *)params[0].memref.buffer, size0,
                            (char *)params[2].memref.buffer, size2, iterations);

  DMSG("! %s !", result);
  if (strlen(result) + 1 > params[0].memref.size) {
    DMSG("refusing short output buffer!");
    TEE_Free(result);
    return TEE_ERROR_SHORT_BUFFER;
  }
  DMSG("! eheh eheh !");
  strcpy((char *)params[0].memref.buffer, result);
  DMSG("! eheh eheh !");
  TEE_Free(result);
  if (PRINTSECRET) {
    DMSG("%s", SECRET);
  }
  return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_PREPARE. API in aes_ta.h
 *
 * Allocate resources required for the ciphering operation.
 * During ciphering operation, when expect client can:
 * - update the key materials (provided by client)
 * - reset the initial vector (provided by client)
 * - cipher an input buffer into an output buffer (provided by client)
 */
static TEE_Result alloc_resources(void *session, uint32_t param_types,
                                  TEE_Param params[4]) {
  const uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_INPUT,
                      TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE);
  struct aes_cipher *sess;
  TEE_Attribute attr;
  TEE_Result res;
  char *key;

  DMSG("Hello, I'm VULN!\n");
  DMSG("utee_log is at %p", (void *)_utee_log);
  DMSG("TEE_OpenPersistentObject is at %p", (void *)TEE_OpenPersistentObject);
  DMSG("TEE_ReadObjectData is at %p", (void *)TEE_ReadObjectData);
  DMSG("TA_OpenSessionEntryPoint is at %p", (void *)TA_OpenSessionEntryPoint);
  DMSG("TEE_InvokeTACommand is at %p", (void *)TEE_InvokeTACommand);
  DMSG("utee_log is at %p", (void *)_utee_log);
  DMSG("utee_return is at %p", (void *)_utee_return);
  DMSG("SECRET is at %p", (void *)SECRET);

  /* Get ciphering context from session ID */
  DMSG("Session %p: get ciphering resources", session);
  sess = (struct aes_cipher *)session;

  /* Safely get the invocation parameters */
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  res = ta2tee_algo_id(params[0].value.a, &sess->algo);
  if (res != TEE_SUCCESS)
    return res;

  res = ta2tee_key_size(params[1].value.a, &sess->key_size);
  if (res != TEE_SUCCESS)
    return res;

  res = ta2tee_mode_id(params[2].value.a, &sess->mode);
  if (res != TEE_SUCCESS)
    return res;

  /*
   * Ready to allocate the resources which are:
   * - an operation handle, for an AES ciphering of given configuration
   * - a transient object that will be use to load the key materials
   *   into the AES ciphering operation.
   */

  /* Free potential previous operation */
  if (sess->op_handle != TEE_HANDLE_NULL)
    TEE_FreeOperation(sess->op_handle);

  /* Allocate operation: AES/CTR, mode and size from params */
  res = TEE_AllocateOperation(&sess->op_handle, sess->algo, sess->mode,
                              sess->key_size * 8);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to allocate operation");
    sess->op_handle = TEE_HANDLE_NULL;
    goto err;
  }

  /* Free potential previous transient object */
  if (sess->key_handle != TEE_HANDLE_NULL)
    TEE_FreeTransientObject(sess->key_handle);

  /* Allocate transient object according to target key size */
  res = TEE_AllocateTransientObject(TEE_TYPE_AES, sess->key_size * 8,
                                    &sess->key_handle);
  if (res != TEE_SUCCESS) {
    EMSG("Failed to allocate transient object");
    sess->key_handle = TEE_HANDLE_NULL;
    goto err;
  }

  /*
   * When loading a key in the cipher session, set_aes_key()
   * will reset the operation and load a key. But we cannot
   * reset and operation that has no key yet (GPD TEE Internal
   * Core API Specification – Public Release v1.1.1, section
   * 6.2.5 TEE_ResetOperation). In consequence, we will load a
   * dummy key in the operation so that operation can be reset
   * when updating the key.
   */
  key = TEE_Malloc(sess->key_size, 0);
  if (!key) {
    res = TEE_ERROR_OUT_OF_MEMORY;
    goto err;
  }

  TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, sess->key_size);

  res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_PopulateTransientObject failed, %x", res);
    goto err;
  }

  res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_SetOperationKey failed %x", res);
    goto err;
  }

  return res;

err:
  if (sess->op_handle != TEE_HANDLE_NULL)
    TEE_FreeOperation(sess->op_handle);
  sess->op_handle = TEE_HANDLE_NULL;

  if (sess->key_handle != TEE_HANDLE_NULL)
    TEE_FreeTransientObject(sess->key_handle);
  sess->key_handle = TEE_HANDLE_NULL;

  return res;
}

/*
 * Process command TA_AES_CMD_SET_KEY. API in aes_ta.h
 */
static TEE_Result set_aes_key(void *session, uint32_t param_types,
                              TEE_Param params[4]) {
  const uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  struct aes_cipher *sess;
  TEE_Attribute attr;
  TEE_Result res;
  uint32_t key_sz;
  char *key;

  /* Get ciphering context from session ID */
  DMSG("Session %p: load key material", session);
  sess = (struct aes_cipher *)session;

  /* Safely get the invocation parameters */
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  key = params[0].memref.buffer;
  key_sz = params[0].memref.size;

  DMSG("Received key: %s, key_sz: %d", key, key_sz);
  /*
   * Introduce Buffer overflow vulnerability: copying key in a
   * intermediate buffer without bounds checking. It is erronous, since
   * it is supposed to pass the key directly to the TEE APIs.
   */
  memmove(sess->key_buffer, key, key_sz);

  if (key_sz != sess->key_size) {
    EMSG("Wrong key size %" PRIu32 ", expect %" PRIu32 " bytes", key_sz,
         sess->key_size);
    // return TEE_ERROR_BAD_PARAMETERS;
  }

  /*
   * Load the key material into the configured operation
   * - create a secret key attribute with the key material
   *   TEE_InitRefAttribute()
   * - reset transient object and load attribute data
   *   TEE_ResetTransientObject()
   *   TEE_PopulateTransientObject()
   * - load the key (transient object) into the ciphering operation
   *   TEE_SetOperationKey()
   *
   * TEE_SetOperationKey() requires operation to be in "initial state".
   * We can use TEE_ResetOperation() to reset the operation but this
   * API cannot be used on operation with key(s) not yet set. Hence,
   * when allocating the operation handle, we load a dummy key.
   * Thus, set_key sequence always reset then set key on operation.
   */

  TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, key_sz);

  TEE_ResetTransientObject(sess->key_handle);
  res = TEE_PopulateTransientObject(sess->key_handle, &attr, 1);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_PopulateTransientObject failed, %x", res);
    return res;
  }

  TEE_ResetOperation(sess->op_handle);
  res = TEE_SetOperationKey(sess->op_handle, sess->key_handle);
  if (res != TEE_SUCCESS) {
    EMSG("TEE_SetOperationKey failed %x", res);
    return res;
  }

  return res;
}

/*
 * Process command TA_AES_CMD_SET_IV. API in aes_ta.h
 */
static TEE_Result reset_aes_iv(void *session, uint32_t param_types,
                               TEE_Param params[4]) {
  const uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_NONE,
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  struct aes_cipher *sess;
  size_t iv_sz;
  char *iv;

  /* Get ciphering context from session ID */
  DMSG("Session %p: reset initial vector", session);
  sess = (struct aes_cipher *)session;

  /* Safely get the invocation parameters */
  if (param_types != exp_param_types)
    return TEE_ERROR_BAD_PARAMETERS;

  iv = params[0].memref.buffer;
  iv_sz = params[0].memref.size;

  /*
   * Init cipher operation with the initialization vector.
   */
  TEE_CipherInit(sess->op_handle, iv, iv_sz);

  return TEE_SUCCESS;
}

void *memdup(const void *mem, size_t size);
void *memdup(const void *mem, size_t size) {
  void *out = malloc(size);

  if (out != NULL)
    memcpy(out, mem, size);

  return out;
}

static TEE_Result call_strdup(uint32_t param_types, TEE_Param params[4]) {
  uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
                      TEE_PARAM_TYPE_NONE, // output its address (insecure!)
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  // SIGN();

  // oops, I forgot...
  if (param_types != exp_param_types) {
  } // return TEE_ERROR_BAD_PARAMETERS;

  if (session_name != NULL)
    free(session_name);

  // use memdup/memcpy, since strdup is insecure here! strndup? Never heard
  // of...
  session_name = memdup(params[0].memref.buffer, params[0].memref.size);
  IMSG("Got session name %s at %p", session_name,
       session_name); // overflow again!
  return TEE_SUCCESS;
}

static TEE_Result call_check1(uint32_t param_types, TEE_Param params[4]) {

  uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // string to store here
                      TEE_PARAM_TYPE_NONE, // output its address (insecure!)
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

  // SIGN();

  // oops, I forgot...
  if (param_types != exp_param_types) {
  } // return TEE_ERROR_BAD_PARAMETERS;

  TEE_Result res;
  TEE_ObjectHandle handle;
  res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,              // storage id
                                 remember_id, sizeof(remember_id), // object id
                                 TEE_DATA_FLAG_ACCESS_READ |   // access flags
                                     TEE_DATA_FLAG_SHARE_READ, // sharing flags
                                 &handle                       // output
  );

  if (res != TEE_SUCCESS) {
    DMSG("Open failed, code: %u", (unsigned int)res);
    return res;
  }

  // spec says, we shall copy input parameters, so we do.
  char *input = memdup(
      params[0].memref.buffer,
      params[0].memref.size); // Generate hash instead? Not yet implemented. ;)
  // size_t size;
  uint32_t size; // yes, the API spec forgot 64bit here (amongst other
                 // locations, too)

  // the input buffer is now free. ;)
  // yes, this is wrong, it does not return an error on the size mismatch. feed
  // it a zero size, and you'll get the secret too. this means: reading is
  // difficult, since there is no simple eof-check, except getting object-info
  // inbefore. No idea how well a correct implementation handles shared data
  // objects written while read, probably not at all. However, there is an
  // atomic replace available.
  res = TEE_ReadObjectData(handle, params[0].memref.buffer,
                           params[0].memref.size, &size);
  if (res != TEE_SUCCESS) {
    DMSG("Read failed, code: %u", (unsigned int)res);
    return res;
  }

  if (size != params[0].memref.size) {
    DMSG("Wrong size, guess again!");
    return TEE_ERROR_GENERIC;
  }
  // has a constant-time implementation, but only in OPTEE, not mandated by TEE
  // API standard. Enough for now. ;)
  if (TEE_MemCompare(params[0].memref.buffer, input, size) != 0) {
    DMSG("Wrong contents, guess again!");
    return TEE_ERROR_GENERIC;
  }
  DMSG("SUCCESS. Here, have a secret: %s", SECRET);
  free(input);

  TEE_CloseObject(handle);
  return TEE_SUCCESS;
}

/*
 * Process command TA_AES_CMD_CIPHER. API in aes_ta.h
 */
static TEE_Result cipher_buffer(void *session, uint32_t param_types,
                                TEE_Param params[4]) {
  const uint32_t exp_param_types =
      TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
                      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
  struct aes_cipher *sess;

  /* Get ciphering context from session ID */
  DMSG("Session %p: cipher buffer", session);
  sess = (struct aes_cipher *)session;

  /* Safely get the invocation parameters */
  if (param_types != exp_param_types) {
  }
  // return TEE_ERROR_BAD_PARAMETERS;

  if (params[1].memref.size < params[0].memref.size) {
    EMSG("Bad sizes: in %d, out %d", params[0].memref.size,
         params[1].memref.size);
    return TEE_ERROR_BAD_PARAMETERS;
  }

  if (sess->op_handle == TEE_HANDLE_NULL)
    return TEE_ERROR_BAD_STATE;

  /*
   * Process ciphering operation on provided buffers
   */
  return TEE_CipherUpdate(sess->op_handle, params[0].memref.buffer,
                          params[0].memref.size, params[1].memref.buffer,
                          &params[1].memref.size);
}

TEE_Result TA_CreateEntryPoint(void) {
  /* Nothing to do */
  return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) { /* Nothing to do */ }

TEE_Result TA_OpenSessionEntryPoint(uint32_t __unused param_types,
                                    TEE_Param __unused params[4],
                                    void __unused **session) {
  struct aes_cipher *sess;

  /*
   * Allocate and init ciphering materials for the session.
   * The address of the structure is used as session ID for
   * the client.
   */
  sess = TEE_Malloc(sizeof(*sess), 0);
  if (!sess)
    return TEE_ERROR_OUT_OF_MEMORY;

  sess->key_handle = TEE_HANDLE_NULL;
  sess->op_handle = TEE_HANDLE_NULL;

  *session = (void *)sess;
  DMSG("Session %p: newly allocated", *session);

  return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *session) {
  struct aes_cipher *sess;

  /* Get ciphering context from session ID */
  DMSG("Session %p: release session", session);
  sess = (struct aes_cipher *)session;

  /* Release the session resources */
  if (sess->key_handle != TEE_HANDLE_NULL)
    TEE_FreeTransientObject(sess->key_handle);
  if (sess->op_handle != TEE_HANDLE_NULL)
    TEE_FreeOperation(sess->op_handle);
  TEE_Free(sess);
}

TEE_Result TA_InvokeCommandEntryPoint(void *session, uint32_t cmd,
                                      uint32_t param_types,
                                      TEE_Param params[4]) {
  (void *)session;

  if (session_name)
    IMSG("Session Name: %s", session_name);

  switch (cmd) {
  case TA_AES_CMD_PREPARE: // remember
    return call_remember(param_types, params);
  case TA_AES_CMD_SET_KEY: // set_name
    return call_strdup(param_types, params);
  case TA_AES_CMD_SET_IV: // fibufnacci
    return call_fibufnacci(param_types, params);
  case TA_AES_CMD_CIPHER:
    return cipher_buffer(session, param_types, params);
  case TA_AES_CMD_CHECK1:
    return call_check1(param_types, params);
  case TA_AES_CMD_CHECK2:
    return call_check1(param_types, params);
  default:
    EMSG("Command ID 0x%x is not supported", cmd);
    return TEE_ERROR_NOT_SUPPORTED;
  }
}
