#include <string>

#include "openssl/evp.h"



#include "trustflow/attestation/verification/hyperenclave/sm3.h"
#include "spdlog/spdlog.h"
#include "trustflow/attestation/verification/hyperenclave/type.h"
constexpr int kSm3HashSize = 32;

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>

int sm3_digest_z(const unsigned char* id,
                 const int id_len,
                 const unsigned char* pub_key,
                 unsigned char* z_digest) {
  int id_bit_len = id_len * 8;
  unsigned char entl[2];
  unsigned char sm2_param_a[32] = {
      0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00,
      0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfc};
  unsigned char sm2_param_b[32] = {
      0x28, 0xe9, 0xfa, 0x9e, 0x9d, 0x9f, 0x5e, 0x34, 0x4d, 0x5a, 0x9e,
      0x4b, 0xcf, 0x65, 0x09, 0xa7, 0xf3, 0x97, 0x89, 0xf5, 0x15, 0xab,
      0x8f, 0x92, 0xdd, 0xbc, 0xbd, 0x41, 0x4d, 0x94, 0x0e, 0x93};
  unsigned char sm2_param_x_G[32] = {
      0x32, 0xc4, 0xae, 0x2c, 0x1f, 0x19, 0x81, 0x19, 0x5f, 0x99, 0x04,
      0x46, 0x6a, 0x39, 0xc9, 0x94, 0x8f, 0xe3, 0x0b, 0xbf, 0xf2, 0x66,
      0x0b, 0xe1, 0x71, 0x5a, 0x45, 0x89, 0x33, 0x4c, 0x74, 0xc7};
  unsigned char sm2_param_y_G[32] = {
      0xbc, 0x37, 0x36, 0xa2, 0xf4, 0xf6, 0x77, 0x9c, 0x59, 0xbd, 0xce,
      0xe3, 0x6b, 0x69, 0x21, 0x53, 0xd0, 0xa9, 0x87, 0x7c, 0xc6, 0x2a,
      0x47, 0x40, 0x02, 0xdf, 0x32, 0xe5, 0x21, 0x39, 0xf0, 0xa0};
  unsigned char x_coordinate[32];
  unsigned char y_coordinate[32];
  EVP_MD_CTX* md_ctx;
  const EVP_MD* md;
  if (!(id) || !(pub_key) || !(z_digest)) {
    return INVALID_NULL_VALUE_INPUT;
  }

  if ((id_bit_len <= 0) || (id_bit_len > 65535)) {
    return INVALID_INPUT_LENGTH;
  }

  entl[0] = (id_bit_len & 0xff00) >> 8;
  entl[1] = id_bit_len & 0xff;
  SPDLOG_DEBUG("entl[1]=0x%x", entl[1]);
  memcpy(x_coordinate, (pub_key + 1), sizeof(x_coordinate));
  memcpy(y_coordinate, (pub_key + 1 + sizeof(x_coordinate)),
         sizeof(y_coordinate));
  md = EVP_sm3();
  if (!(md_ctx = EVP_MD_CTX_new())) {
    SPDLOG_ERROR("Fail to allocate a digest context");
    return COMPUTE_SM3_DIGEST_FAIL;
  }
  EVP_DigestInit_ex(md_ctx, md, NULL);
  EVP_DigestUpdate(md_ctx, entl, sizeof(entl));
  EVP_DigestUpdate(md_ctx, id, id_len);
  EVP_DigestUpdate(md_ctx, sm2_param_a, sizeof(sm2_param_a));
  EVP_DigestUpdate(md_ctx, sm2_param_b, sizeof(sm2_param_b));
  EVP_DigestUpdate(md_ctx, sm2_param_x_G, sizeof(sm2_param_x_G));
  EVP_DigestUpdate(md_ctx, sm2_param_y_G, sizeof(sm2_param_y_G));
  EVP_DigestUpdate(md_ctx, x_coordinate, sizeof(x_coordinate));
  EVP_DigestUpdate(md_ctx, y_coordinate, sizeof(y_coordinate));
  EVP_DigestFinal_ex(md_ctx, z_digest, NULL);
  EVP_MD_CTX_free(md_ctx);
  return 0;
}

/*********************************************************/
int sm3_digest_with_preprocess(const unsigned char* message,
                               const int message_len,
                               const unsigned char* id,
                               const int id_len,
                               const unsigned char* pub_key,
                               unsigned char* digest,
                               bool use_z) {
  int error_code;
  unsigned char z_digest[32];
  EVP_MD_CTX* md_ctx;
  const EVP_MD* md;

  if (!use_z) {  // only hash the message
    global_sm3_hash(message, message_len, digest);
    return 0;
  }
  error_code = sm3_digest_z(id, id_len, pub_key, z_digest);
  if (error_code != 0) {
    SPDLOG_ERROR("Compute SM3 digest of leading data Z failed");
    return COMPUTE_SM3_DIGEST_FAIL;
  }

  md = EVP_sm3();
  if (!(md_ctx = EVP_MD_CTX_new())) {
#ifdef _DEBUG
    printf("Allocate a digest context failed at %s, line %d!\n", __FILE__,
           __LINE__);
#endif
    return COMPUTE_SM3_DIGEST_FAIL;
  }
  EVP_DigestInit_ex(md_ctx, md, NULL);
  EVP_DigestUpdate(md_ctx, z_digest, sizeof(z_digest));
  EVP_DigestUpdate(md_ctx, message, message_len);
  EVP_DigestFinal_ex(md_ctx, digest, NULL);
  EVP_MD_CTX_free(md_ctx);
  return 0;
}

EVP_MD_CTX* global_md_ctx;
const EVP_MD* global_md;

bool global_sm3_init() {
  global_md = EVP_sm3();

  if (!(global_md_ctx = EVP_MD_CTX_new())) {
    return false;
  }
  EVP_DigestInit_ex(global_md_ctx, global_md, NULL);
  return true;
}

bool global_sm3_update(const unsigned char* data, unsigned int len) {
  if (!data || len <= 0) return false;
  EVP_DigestUpdate(global_md_ctx, data, len);
  return true;
}

unsigned int global_sm3_final(unsigned char* digest) {
  if (!digest) return 0;
  EVP_DigestFinal_ex(global_md_ctx, digest, NULL);
  EVP_MD_CTX_free(global_md_ctx);
  return 32;
}

unsigned int global_sm3_hash(const unsigned char* message,
                             unsigned int message_len,
                             unsigned char* digest) {
  unsigned int len = 0;
  if (!message || !message_len || !digest) return 0;
  if (!global_sm3_init()) return 0;
  global_sm3_update(message, message_len);
  len = global_sm3_final(digest);
  return len;
}

#ifdef __cplusplus
}
#endif

namespace trustflow {
namespace attestation {
namespace verification {

int Sm3Crypto::Hash(const std::string& data, std::string* hash) {
  char hash_buf[kSm3HashSize] = {0};
  unsigned int hash_len = 0;
  const EVP_MD* md = EVP_sm3();
  EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    SPDLOG_ERROR("Fail to create sm3 ctx");
    return -1;
  }

  EVP_DigestInit_ex(md_ctx, md, NULL);
  EVP_DigestUpdate(md_ctx, RCAST(uint8_t*, CCAST(char*, data.data())),
                   data.size());
  EVP_DigestFinal_ex(md_ctx, RCAST(uint8_t*, hash_buf), &hash_len);
  EVP_MD_CTX_free(md_ctx);
  if (hash_len != kSm3HashSize) {
    SPDLOG_ERROR("Unexpected hash result length");
    return -1;
  }
  hash->assign(hash_buf, kSm3HashSize);
  return 0;
}

int Sm3Crypto::GetHashSize() {
  return kSm3HashSize;
}

}  // namespace verification
}  // namespace attestation
}  // namespace trustflow