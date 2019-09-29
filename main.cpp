#include <openssl/hmac.h>
#include <mbedtls/md.h>

#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>

#include <mbedtls/base64.h>

#include <iostream>

#define _MS_LOG_SEPARATOR_CHAR_STD "\n"
#define _MS_LOG_STR "%s:%d | %s::%s()"
#define _MS_LOG_STR_DESC _MS_LOG_STR " | "
#define _MS_FILE (std::strchr(__FILE__, '/') ? std::strchr(__FILE__, '/') + 1 : __FILE__)
#define MS_CLASS "crypto"
#define _MS_LOG_ARG _MS_FILE, __LINE__, MS_CLASS, __FUNCTION__

#define MS_ABORT(desc, ...) \
do \
{ \
std::fprintf(stderr, "ABORT" _MS_LOG_STR_DESC desc _MS_LOG_SEPARATOR_CHAR_STD, _MS_LOG_ARG, ##__VA_ARGS__); \
std::fflush(stderr); \
std::abort(); \
} \
while (false)

#define MS_ASSERT(condition, desc, ...) \
if (!(condition)) \
{ \
MS_ABORT("failed assertion `%s': " desc, #condition, ##__VA_ARGS__); \
}

std::string base64_encode(char* sha1) {
    char res[40] = {0};
    size_t olen;
    mbedtls_base64_encode ((unsigned char *)res, sizeof(res), &olen, (const unsigned char *)sha1, 20);
    return res;
}

std::string getOpensslHmac(char **argv) {
    HMAC_CTX* hmacSha1Ctx = nullptr;
    hmacSha1Ctx = HMAC_CTX_new();
    
    int ret = 0;
    std::string key = argv[2];
    char hmacSha1Buffer[21] = {0};
    std::string data = argv[3];
    
    ret = HMAC_Init_ex(hmacSha1Ctx, key.c_str(), key.length(), EVP_sha1(), nullptr);
    std::cout<<ret<<std::endl;
    MS_ASSERT(ret == 1, "OpenSSL HMAC_Init_ex() failed with key '%s', %d", key.c_str(), ret);
    std::cout<<ret<<std::endl;
    
    ret = HMAC_Update(hmacSha1Ctx, reinterpret_cast<const unsigned char *>(data.c_str()), static_cast<int>(data.length()));
    
    MS_ASSERT(
              ret == 1,
              "OpenSSL HMAC_Update() failed with key '%s' and data length %zu bytes",
              key.c_str(),
              data.length());
    
    uint32_t resultLen;
    
    ret = HMAC_Final(hmacSha1Ctx, (uint8_t*)hmacSha1Buffer, &resultLen);
    
    MS_ASSERT(
              ret == 1, "OpenSSL HMAC_Final() failed with key '%s' and data length %zu bytes", key.c_str(), data.length());
    MS_ASSERT(resultLen == 20, "OpenSSL HMAC_Final() resultLen is %u instead of 20", resultLen);
    
    return base64_encode(hmacSha1Buffer);
}

std::string getMbedtlsHmac(char **argv) {
    mbedtls_md_context_t* hmacSha1Ctx = nullptr;
    hmacSha1Ctx = new(mbedtls_md_context_t);
    
    int ret = 0;
    std::string key = argv[2];
    char hmacSha1Buffer[21] = {0};
    std::string data = argv[3];
    
    ret = mbedtls_md_setup(hmacSha1Ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), 1);
    MS_ASSERT(ret == 0, "mbedtls_md_setup() failed with key '%s'", key.c_str());
    ret = mbedtls_md_hmac_starts(hmacSha1Ctx, (const unsigned char *)key.c_str(), key.length());
    MS_ASSERT(ret == 0, "mbedtls_md_hmac_starts() failed with key '%s'", key.c_str());
    ret = mbedtls_md_hmac_update(hmacSha1Ctx, reinterpret_cast<const unsigned char *>(data.c_str()), data.length());
    MS_ASSERT(ret == 0, "mbedtls_md_hmac_update() failed with key '%s'", key.c_str());
    
    ret = mbedtls_md_hmac_finish(hmacSha1Ctx, reinterpret_cast<unsigned char *>(hmacSha1Buffer));
    MS_ASSERT(ret == 0, "mbedtls_md_hmac_finish() resultLen is %u instead of 20", ret);
    
    return base64_encode(hmacSha1Buffer);
}

void handleHmac(int argc, char **argv) {
    if (argc != 4) {
        std::cout<<"usage as:"<<argv[0] <<" hmac key data\n"<<std::endl;
        exit(2);
    }
    auto opensslHmac = getOpensslHmac(argv);
    auto mbedtlsHmac = getMbedtlsHmac(argv);
    std::cout<<opensslHmac<<" "<<opensslHmac.length()<<std::endl;
    std::cout<<mbedtlsHmac<<" "<<mbedtlsHmac.length()<<std::endl;
}

void opensslSsl(char **argv) {
    static SSL_CTX* sslCtx;
    SSL* ssl;
}

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ssl_cookie.h"
void mbedtlsSsl(char **argv) {
    mbedtls_x509_crt crt;
    mbedtls_x509_crt_init(&crt);
    mbedtls_x509_crt_parse_file(&crt, argv[2]);
    
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    mbedtls_pk_parse_keyfile(&key, argv[3], NULL);
    
    mbedtls_ssl_context sslCtx;
    mbedtls_ssl_init(&sslCtx);
    
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    const unsigned char *custom = (const unsigned char *)"mediasoup_server";
    
    
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, custom, strlen((char *)custom));
    
    mbedtls_ssl_config conf;
    mbedtls_ssl_config_init( &conf );
    mbedtls_ssl_config_defaults( &conf,
                                MBEDTLS_SSL_IS_SERVER,
                                MBEDTLS_SSL_TRANSPORT_DATAGRAM,
                                MBEDTLS_SSL_PRESET_DEFAULT );
    
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_ca_chain(&conf, &crt, NULL);
    mbedtls_ssl_conf_own_cert( &conf, &crt, &key );
    
    mbedtls_ssl_cookie_ctx cookie_ctx;
    mbedtls_ssl_cookie_init( &cookie_ctx );
    mbedtls_ssl_cookie_setup( &cookie_ctx, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dtls_cookies( &conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check,
                                  &cookie_ctx );
    mbedtls_ssl_setup( &sslCtx, &conf );
    
    
    
}

void handleSsl(int argc, char **argv) {
    
}


int main(int argc, char **argv) {
    if (argc < 2) {
        std::cout<<"usage as:"<<argv[0] <<" command args...\n"<<std::endl;
        exit(1);
    }
    
    std::string cmd = argv[1];
    if (cmd == "hmac") {
        handleHmac(argc, argv);
    }  if (cmd == "ssl") {
        handleSsl(argc, argv);
    }
    return 0;
}
