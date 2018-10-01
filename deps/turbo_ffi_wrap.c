/* Wrapper for FFI calls from Turbo.lua, where its is difficult because
of long header file, macros, define's etc.

Copyright 2013 John Abrahamsen

"Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."			*/

#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <limits.h>

#include "http_parser.h"
#include "turbo_ffi_wrap.h"

#ifndef TURBO_NO_SSL
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#endif

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

#define ENDIAN_SWAP_U64(val) ((uint64_t) ( \
    (((uint64_t) (val) & (uint64_t) 0x00000000000000ff) << 56) | \
    (((uint64_t) (val) & (uint64_t) 0x000000000000ff00) << 40) | \
    (((uint64_t) (val) & (uint64_t) 0x0000000000ff0000) << 24) | \
    (((uint64_t) (val) & (uint64_t) 0x00000000ff000000) <<  8) | \
    (((uint64_t) (val) & (uint64_t) 0x000000ff00000000) >>  8) | \
    (((uint64_t) (val) & (uint64_t) 0x0000ff0000000000) >> 24) | \
    (((uint64_t) (val) & (uint64_t) 0x00ff000000000000) >> 40) | \
    (((uint64_t) (val) & (uint64_t) 0xff00000000000000) >> 56)))

#ifndef TURBO_NO_SSL

#pragma GCC diagnostic push 
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int matches_common_name(const char *hostname, const X509 *server_cert)
{
    int common_name_loc = -1;
    X509_NAME_ENTRY *common_name_entry = 0;
    ASN1_STRING *common_name_asn1 = 0;
    char *common_name_str = 0;

    common_name_loc = X509_NAME_get_index_by_NID(X509_get_subject_name(
                                                     (X509 *) server_cert),
                                                 NID_commonName, -1);
    if (common_name_loc < 0) {
        return Error;
    }
    common_name_entry = X509_NAME_get_entry(
                X509_get_subject_name(
                    (X509 *) server_cert),
                common_name_loc);
    if (!common_name_entry) {
        return Error;
    }
    common_name_asn1 = X509_NAME_ENTRY_get_data(common_name_entry);
    if (!common_name_asn1) {
        return Error;
    }
    common_name_str = (char *) ASN1_STRING_data(common_name_asn1);
    if (ASN1_STRING_length(common_name_asn1) != strlen(common_name_str)) {
        return MalformedCertificate;
    }
    if (!strcasecmp(hostname, common_name_str)) {
        return MatchFound;
    }
    else {
        return MatchNotFound;
    }
}

static int32_t matches_subject_alternative_name(
        const char *hostname,
        const X509 *server_cert)
{
    int32_t result = MatchNotFound;
    int32_t i;
    int32_t san_names_nb = -1;
    int32_t hostname_is_domain;
    const char *subdomain_offset;
    size_t dns_name_sz;
    size_t hostname_sz = strlen(hostname);
    STACK_OF(GENERAL_NAME) *san_names = 0;

    san_names = X509_get_ext_d2i(
                (X509 *) server_cert,
                NID_subject_alt_name,
                0,
                0);
    if (san_names == 0)
        return NoSANPresent;
    san_names_nb = sk_GENERAL_NAME_num(san_names);
    for (i=0; i<san_names_nb; i++){
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);
        if (current_name->type == GEN_DNS){
            char *dns_name = (char *)ASN1_STRING_data(current_name->d.dNSName);
            dns_name_sz = strlen(dns_name);
            if (ASN1_STRING_length(current_name->d.dNSName) != dns_name_sz){
                result = MalformedCertificate;
                break;
            } else {
                if (strcasecmp(hostname, dns_name) == 0){
                    result = MatchFound;
                    break;
                }
                if (dns_name_sz <= 2)
                    continue;
                if (dns_name[0] == '*' && dns_name[1] == '.'){
                    // Wildcard subdomain.
                    subdomain_offset = strchr(hostname, '.');
                    if (!subdomain_offset)
                        continue;
                    hostname_is_domain = strchr(subdomain_offset, '.') ? 0 : 1;
                    if (hostname_is_domain){
                        if (strcasecmp(hostname, dns_name + 2) == 0){
                            result = MatchFound;
                            break;
                        }
                    } else {
                        if (hostname_sz - (subdomain_offset - hostname) > 0){
                            if (strcasecmp(
                                        subdomain_offset + 1,
                                        dns_name + 2) == 0){
                                result = MatchFound;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);

    return result;
}

int32_t validate_hostname(const char *hostname, const SSL *server){
    int32_t result;
    X509 *server_cert = 0;

    if (!hostname || !server){
        return Error;
    }
    server_cert = SSL_get_peer_certificate(server);
    if (!server_cert){
        return Error;
    }
    result = matches_subject_alternative_name(hostname, server_cert);
    if (result == NoSANPresent) {
        result = matches_common_name(hostname, server_cert);
    }
    X509_free(server_cert);
    return result;
}
#pragma GCC diagnostic pop
#endif

bool url_field_is_set(
        const struct http_parser_url *url,
        enum http_parser_url_fields prop)
{
    if (url->field_set & (1 << prop))
        return true;
    else
        return false;
}

char *url_field(const char *url_str,
                const struct http_parser_url *url,
                enum http_parser_url_fields prop)
{
    char * urlstr = malloc(url->field_data[prop].len + 1);
    if (!urlstr)
        return NULL;
    memcpy(urlstr, url_str + url->field_data[prop].off, url->field_data[prop].len);
    urlstr[url->field_data[prop].len] = '\0';
    return urlstr;
}


static int32_t request_url_cb(http_parser *p, const char *buf, size_t len)
{
    struct turbo_parser_wrapper *nw = (struct turbo_parser_wrapper*)p->data;

    nw->url_str = buf;
    nw->url_sz = len;
    nw->url_rc = http_parser_parse_url(buf, len, 0, &nw->url);
    return 0;
}

static int32_t header_field_cb(http_parser *p, const char *buf, size_t len)
{
    struct turbo_parser_wrapper *nw = (struct turbo_parser_wrapper*)p->data;
    struct turbo_key_value_field *kv_field;
    void *ptr;

    switch(nw->_state){
    case NOTHING:
    case VALUE:
        if (nw->hkv_sz == nw->hkv_mem){
        ptr = realloc(
                        nw->hkv,
                    sizeof(struct turbo_key_value_field *) *
                        (nw->hkv_sz + 10));
            if (!ptr)
            return -1;
            nw->hkv = ptr;
            nw->hkv_mem += 10;
        }
        kv_field = malloc(sizeof(struct turbo_key_value_field));
        if (!kv_field)
            return -1;
        kv_field->key = buf;
        kv_field->key_sz = len;
        nw->hkv[nw->hkv_sz] = kv_field;
        break;
    case FIELD:
        break;
    }
    nw->_state = FIELD;
    return 0;
}

static int32_t header_value_cb(http_parser *p, const char *buf, size_t len)
{
    struct turbo_parser_wrapper *nw = (struct turbo_parser_wrapper*)p->data;
    struct turbo_key_value_field *kv_field;

    switch(nw->_state){
    case FIELD:
        kv_field = nw->hkv[nw->hkv_sz];
        kv_field->value = buf;
        kv_field->value_sz = len;
        nw->hkv_sz++;
        break;
    case VALUE:
    case NOTHING:
        break;
    }
    nw->_state = VALUE;
    return 0;
}

int32_t headers_complete_cb (http_parser *p)
{
    struct turbo_parser_wrapper *nw = (struct turbo_parser_wrapper*)p->data;
    nw->headers_complete = true;
    return 0;
}

static http_parser_settings settings =
{.on_message_begin = 0
 ,.on_header_field = header_field_cb
 ,.on_header_value = header_value_cb
 ,.on_url = request_url_cb
 ,.on_body = 0
 ,.on_headers_complete = headers_complete_cb
 ,.on_message_complete = 0
};

struct turbo_parser_wrapper *turbo_parser_wrapper_init(
        const char* data,
        size_t len,
        int32_t type)
{
    struct turbo_parser_wrapper *dest = malloc(
                sizeof(struct turbo_parser_wrapper));
    if (!dest)
        return 0;
    dest->parser.data = dest;
    dest->url_str = 0;
    dest->hkv = 0;
    dest->hkv_sz = 0;
    dest->hkv_mem = 0;
    dest->headers_complete = false;
    dest->_state = NOTHING;
    if (type == 0)
        http_parser_init(&dest->parser, HTTP_REQUEST);
    else
        http_parser_init(&dest->parser, HTTP_RESPONSE);
    dest->parsed_sz = http_parser_execute(&dest->parser, &settings, data, len);
    return dest;
}

void turbo_parser_wrapper_exit(struct turbo_parser_wrapper *src)
{
    size_t i = 0;
    for (; i < src->hkv_sz; i++){
        free(src->hkv[i]);
    }
    free(src->hkv);
    free(src);
}

bool turbo_parser_check(struct turbo_parser_wrapper *s)
{
    if (s->parser.http_errno != 0 || s->parsed_sz == 0)
        return false;
    else
        return true;
}


char* turbo_websocket_mask(const char* mask32, const char* in, size_t sz)
{
    size_t i = 0;
    char* buf = malloc(sz);

    if (!buf)
        return 0;
    for (i = 0; i < sz; i++) {
        buf[i] = in[i] ^ mask32[i % 4];
    }
    return buf;
 }

uint64_t turbo_bswap_u64(uint64_t swap)
{
    uint64_t swapped;

    swapped = ENDIAN_SWAP_U64(swap);
    return swapped;
}

int ffi_stat(const char *pathname, struct ffi_stat *buf)
{
    struct stat st;
    int rc = stat(pathname, &st);
    if (rc) {
        return rc;
    }
    buf->st_dev = st.st_dev;
    buf->st_ino = st.st_ino;
    buf->st_mode = st.st_mode;
    buf->st_nlink = st.st_nlink;
    buf->st_uid = st.st_uid;
    buf->st_gid = st.st_gid;
    buf->st_rdev = st.st_rdev;
    buf->st_size = st.st_size;
    buf->st_blksize = st.st_blksize;
    buf->st_blocks = st.st_blocks;
    buf->_st_atime = st.st_atim.tv_sec;
    buf->_st_atime_nsec = st.st_atim.tv_nsec;
    buf->_st_mtime = st.st_mtim.tv_sec;
    buf->_st_mtime_nsec = st.st_mtim.tv_nsec;
    buf->_st_ctime = st.st_ctim.tv_sec;
    buf->_st_ctime_nsec = st.st_ctim.tv_nsec;
    return 0;
}

uint32_t get_c_def(const char *name)
{
    #define RETURN_DEF(def) do { if (!strcmp(name, #def)) return def; } while(0)

    RETURN_DEF(O_ACCMODE);
    RETURN_DEF(O_RDONLY);
    RETURN_DEF(O_WRONLY);
    RETURN_DEF(O_RDWR);
    RETURN_DEF(O_CREAT);
    RETURN_DEF(O_EXCL);
    RETURN_DEF(O_NOCTTY);
    RETURN_DEF(O_TRUNC);
    RETURN_DEF(O_APPEND);
    RETURN_DEF(O_NONBLOCK);
    RETURN_DEF(O_NDELAY);
    RETURN_DEF(O_SYNC);
    //RETURN_DEF(O_FSYNC);
    RETURN_DEF(O_ASYNC);

    RETURN_DEF(F_DUPFD);
    RETURN_DEF(F_GETFD);
    RETURN_DEF(F_SETFD);
    RETURN_DEF(F_GETFL);
    RETURN_DEF(F_SETFL);

    RETURN_DEF(SOCK_STREAM);
    RETURN_DEF(SOCK_DGRAM);
    RETURN_DEF(SOCK_RAW);
    RETURN_DEF(SOCK_RDM);
    RETURN_DEF(SOCK_SEQPACKET);
    RETURN_DEF(SOCK_DCCP);
    RETURN_DEF(SOCK_PACKET);
    RETURN_DEF(SOCK_CLOEXEC);
    RETURN_DEF(SOCK_NONBLOCK);

    RETURN_DEF(PF_UNSPEC);
    RETURN_DEF(PF_LOCAL);
    RETURN_DEF(PF_UNIX);
    RETURN_DEF(PF_FILE);
    RETURN_DEF(PF_INET);
    RETURN_DEF(PF_IPX);
    RETURN_DEF(PF_APPLETALK);
    RETURN_DEF(PF_NETROM);
    RETURN_DEF(PF_BRIDGE);
    RETURN_DEF(PF_ATMPVC);
    RETURN_DEF(PF_X25);
    RETURN_DEF(PF_INET6);
    RETURN_DEF(PF_PACKET);
    RETURN_DEF(PF_PPPOX);
    RETURN_DEF(PF_ROUTE);
    RETURN_DEF(PF_NETLINK);
    RETURN_DEF(PF_LLC);
    RETURN_DEF(PF_BLUETOOTH);

    RETURN_DEF(SOL_SOCKET);

    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_DEBUG);

    RETURN_DEF(SO_DEBUG);
    RETURN_DEF(SO_REUSEADDR);
    RETURN_DEF(SO_TYPE);
    RETURN_DEF(SO_ERROR);
    RETURN_DEF(SO_DONTROUTE);
    RETURN_DEF(SO_BROADCAST);
    RETURN_DEF(SO_SNDBUF);
    RETURN_DEF(SO_RCVBUF);
    RETURN_DEF(SO_SNDBUFFORCE);
    RETURN_DEF(SO_RCVBUFFORCE);
    RETURN_DEF(SO_KEEPALIVE);
    RETURN_DEF(SO_OOBINLINE);
    RETURN_DEF(SO_NO_CHECK);
    RETURN_DEF(SO_PRIORITY);
    RETURN_DEF(SO_LINGER);
    RETURN_DEF(SO_BSDCOMPAT);
    RETURN_DEF(SO_PASSCRED);
    RETURN_DEF(SO_PEERCRED);
    RETURN_DEF(SO_RCVLOWAT);
    RETURN_DEF(SO_SNDLOWAT);
    RETURN_DEF(SO_RCVTIMEO);
    RETURN_DEF(SO_SNDTIMEO);
    RETURN_DEF(SO_SECURITY_AUTHENTICATION);
    RETURN_DEF(SO_SECURITY_ENCRYPTION_TRANSPORT);
    RETURN_DEF(SO_SECURITY_ENCRYPTION_NETWORK);
    RETURN_DEF(SO_BINDTODEVICE);
    RETURN_DEF(SO_ATTACH_FILTER);
    RETURN_DEF(SO_DETACH_FILTER);
    RETURN_DEF(SO_PEERNAME);
    RETURN_DEF(SO_TIMESTAMP);
    RETURN_DEF(SCM_TIMESTAMP);
    RETURN_DEF(SO_ACCEPTCONN);
    RETURN_DEF(SO_PEERSEC);
    RETURN_DEF(SO_PASSSEC);
    RETURN_DEF(SO_TIMESTAMPNS);
    RETURN_DEF(SCM_TIMESTAMPNS);
    RETURN_DEF(SO_MARK);
    RETURN_DEF(SO_TIMESTAMPING);
    RETURN_DEF(SCM_TIMESTAMPING);
    RETURN_DEF(SO_PROTOCOL);
    RETURN_DEF(SO_DOMAIN);
    RETURN_DEF(SO_RXQ_OVFL);
    RETURN_DEF(SO_WIFI_STATUS);
    RETURN_DEF(SCM_WIFI_STATUS);
    RETURN_DEF(SO_PEEK_OFF);
    RETURN_DEF(SO_NOFCS);

    RETURN_DEF(EAGAIN);
    RETURN_DEF(EWOULDBLOCK);
    RETURN_DEF(EINPROGRESS);
    RETURN_DEF(ECONNRESET);
    RETURN_DEF(EPIPE);
    RETURN_DEF(EAI_AGAIN);

    RETURN_DEF(O_DIRECTORY);
    RETURN_DEF(O_NOFOLLOW);
    RETURN_DEF(S_IFMT);
    RETURN_DEF(S_IFSOCK);
    RETURN_DEF(S_IFLNK);
    RETURN_DEF(S_IFREG);
    RETURN_DEF(S_IFBLK);
    RETURN_DEF(S_IFDIR);
    RETURN_DEF(S_IFCHR);
    RETURN_DEF(S_IFIFO);
    RETURN_DEF(S_ISUID);
    RETURN_DEF(S_ISGID);
    RETURN_DEF(S_ISVTX);
    RETURN_DEF(S_IRWXU);
    RETURN_DEF(S_IRUSR);
    RETURN_DEF(S_IWUSR);
    RETURN_DEF(S_IXUSR);
    RETURN_DEF(S_IRWXG);
    RETURN_DEF(S_IRGRP);
    RETURN_DEF(S_IWGRP);
    RETURN_DEF(S_IXGRP);
    RETURN_DEF(S_IRWXO);
    RETURN_DEF(S_IROTH);
    RETURN_DEF(S_IWOTH);
    RETURN_DEF(S_IXOTH);

    RETURN_DEF(SIG_BLOCK);
    RETURN_DEF(SIG_UNBLOCK);
    RETURN_DEF(SIG_SETMASK);
    RETURN_DEF(SIGHUP);
    RETURN_DEF(SIGINT);
    RETURN_DEF(SIGQUIT);
    RETURN_DEF(SIGILL);
    RETURN_DEF(SIGTRAP);
    RETURN_DEF(SIGIOT);
    RETURN_DEF(SIGABRT);
    RETURN_DEF(SIGBUS);
    RETURN_DEF(SIGFPE);
    RETURN_DEF(SIGKILL);
    RETURN_DEF(SIGUSR1);
    RETURN_DEF(SIGSEGV);
    RETURN_DEF(SIGUSR2);
    RETURN_DEF(SIGPIPE);
    RETURN_DEF(SIGALRM);
    RETURN_DEF(SIGTERM);
    RETURN_DEF(SIGSTKFLT);
    //RETURN_DEF(SIGCLD);
    RETURN_DEF(SIGCHLD);
    RETURN_DEF(SIGCONT);
    RETURN_DEF(SIGSTOP);
    RETURN_DEF(SIGTSTP);
    RETURN_DEF(SIGTTIN);
    RETURN_DEF(SIGTTOU);
    RETURN_DEF(SIGURG);
    RETURN_DEF(SIGXCPU);
    RETURN_DEF(SIGXFSZ);
    RETURN_DEF(SIGVTALRM);
    RETURN_DEF(SIGPROF);
    RETURN_DEF(SIGWINCH);
    RETURN_DEF(SIGPOLL);
    RETURN_DEF(SIGIO);
    RETURN_DEF(SIGPWR);
    RETURN_DEF(SIGSYS);
    RETURN_DEF(_NSIG);


    #undef RETURN_DEF
    fprintf(stderr, "undefined C symbol: %s\n", name);
    exit(0);
    return 0;
}

#include <openssl/err.h>

void turbo_ssl_init()
{
    SSL_load_error_strings();
    SSL_library_init();
    OPENSSL_add_all_algorithms_noconf();
}


static unsigned char *strbuf = NULL;
static unsigned int strbuflen = 0;

static int __strbuf_realloc(unsigned int size)
{
    void *p;
    unsigned int slen = strbuflen;
    if (slen == 0) {
        slen = 32;
    }
    while (slen < size) {
        slen *= 2;
    }
    p = realloc(strbuf, slen);
    if (!p) {
        return -1;
    }
    strbuf = p;
    strbuflen = slen;
    return 0;
}

static inline int strbuf_realloc(unsigned int size)
{
    if (size < strbuflen) {
        return 0;
    }
    return __strbuf_realloc(size);
}

static char *escape_table[256] = { NULL };
static int escape_table_initialised = 0;

static void escape_table_initialise(void)
{
    int i;
    char buf[16];

    for (i = 0; i < 256; i++) {
        if (!((i >= 'a' && i <= 'z') ||
              (i >= 'A' && i <= 'Z') ||
              (i >= '0' && i <= '9') ||
              (i == '_'))
          ) {
            sprintf(buf, "%%%02x", i);
            escape_table[i] = strdup(buf);
          }
    }
}

const char * __strescape(const char *s, size_t len)
{
    uint8_t *p = (uint8_t *)s;
    int i, c, idx;
    const char *es;
    idx = 0;

    if (!escape_table_initialised) {
        escape_table_initialise();
        escape_table_initialised = 1;
    }

    for (i = 0; i < len; i++) {
        c = p[i];
        if ((es = escape_table[c]) != NULL) {
            if (strbuf_realloc(idx + 5)) {
                return NULL;
            }
            memcpy(strbuf + idx, es, 3);
            idx += 3;
        } else {
            if (strbuf_realloc(idx + 3)) {
                return NULL;
            }
            strbuf[idx++] = c;
        }
    }
    strbuf[idx] = 0;
    return (const char *)strbuf;
}

static inline int fromhex(int c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    } else if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else {
        return -1;
    }
}

const char * __strunescape(const char *s, size_t len, unsigned int *unescapedlen)
{
    uint8_t *p = (uint8_t *)s;
    int i, c, idx;
    idx = 0;
    for (i = 0; i < len; i++) {
        c = p[i];
        if (c == '%' && (i + 2) < len) {
            int c1, c2;

            c1 = fromhex(p[i + 1]);
            if (c1 < 0) {
                goto noescape;
            }

            c2 = fromhex(p[i + 2]);
            if (c2 < 0) {
                goto noescape;
            }

            c = (c1 << 4) | c2;
            i += 2;
        }

    noescape:
        if (strbuf_realloc(idx + 3)) {
            return NULL;
        }
        strbuf[idx++] = c;
    }

    strbuf[idx] = 0;
    if (unescapedlen) {
        *unescapedlen = idx;
    }
    return (const char *)strbuf;
}
