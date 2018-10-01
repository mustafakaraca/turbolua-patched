/* Wrapper for FFI calls where its is difficult because
of long header file, macros, define's etc.

Copyright John Abrahamsen 2011 - 2015

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License. */

#include <stdint.h>
#include <stdlib.h>

#ifndef TURBO_NO_SSL
#include <openssl/ssl.h>
#endif
#include <stdbool.h>
#include "http-parser/http_parser.h"

// http-parser wrapper functions.

struct turbo_key_value_field{
    /* Size of strings.  */
    size_t key_sz;
    size_t value_sz;
    /* These are offsets for passed in char ptr. */
    const char *key;       ///< Header key.
    const char *value;     ///< Value corresponding to key.
};

/** Used internally  */
enum header_state{
    NOTHING,
    FIELD,
    VALUE
};

struct turbo_parser_wrapper{
    int32_t url_rc;
    size_t parsed_sz;
    bool headers_complete;
    enum header_state _state; ///< Used internally

    const char *url_str; ///< Offset for passed in char ptr
    size_t url_sz;
    size_t hkv_sz;
    size_t hkv_mem ;  ///< We allocate in chunks of 10 structs at a time.
    struct turbo_key_value_field **hkv;
    struct http_parser parser;
    struct http_parser_url url;
};

struct turbo_parser_wrapper *turbo_parser_wrapper_init(
        const char* data,
        size_t len,
        int32_t type);

void turbo_parser_wrapper_exit(struct turbo_parser_wrapper *src);

int32_t http_parser_parse_url(
        const char *buf,
        size_t buflen,
        int32_t is_connect,
        struct http_parser_url *u);

/** Check if a given field is set in http_parser_url  */
bool url_field_is_set(
        const struct http_parser_url *url,
        enum http_parser_url_fields prop);
char *url_field(
        const char *url_str,
        const struct http_parser_url *url,
        enum http_parser_url_fields prop);
bool turbo_parser_check(struct turbo_parser_wrapper *s);

char* turbo_websocket_mask(const char *mask32, const char* in, size_t sz);
uint64_t turbo_bswap_u64(uint64_t swap);

// OpenSSL wrapper functions.
#ifndef TURBO_NO_SSL
#define MatchFound 0
#define MatchNotFound 1
#define NoSANPresent 2
#define MalformedCertificate 3
#define Error 4

/** Validate a X509 cert against provided hostname. */
int32_t validate_hostname(const char *hostname, const SSL *server);
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>

struct ffi_stat {
    unsigned long  st_dev;
    unsigned long  st_ino;
    unsigned long  st_mode;
    unsigned long  st_nlink;
    unsigned long  st_uid;
    unsigned long  st_gid;
    unsigned long  st_rdev;
    unsigned long  st_size;
    unsigned long  st_blksize;
    unsigned long  st_blocks;
    unsigned long  _st_atime;
    unsigned long  _st_atime_nsec;
    unsigned long  _st_mtime;
    unsigned long  _st_mtime_nsec;
    unsigned long  _st_ctime;
    unsigned long  _st_ctime_nsec;
};

int ffi_stat(const char *pathname, struct ffi_stat *buf);

uint32_t get_c_def(const char *name);
void turbo_ssl_init();

void register_escape(int c);
const char * __strescape(const char *s, size_t len);
