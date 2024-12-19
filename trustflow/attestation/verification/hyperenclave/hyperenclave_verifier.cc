// Copyright 2024 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "trustflow/attestation/verification/hyperenclave/hyperenclave_verifier.h"

#include "absl/strings/escaping.h"
#include "cppcodec/base64_rfc4648.hpp"
#include "sgx_quote.h"
#include "yacl/base/byte_container_view.h"
#include "yacl/base/exception.h"
#include "yacl/crypto/hash/ssl_hash.h"

#include "trustflow/attestation/common/constants.h"
#include "trustflow/attestation/utils/json2pb.h"

namespace trustflow {
namespace attestation {
namespace verification {

namespace {

constexpr uint32_t kReportDataSize = 64;
constexpr char kUserId[SM2_USERID_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09, 0x0A,
                                           0x0B, 0x0C, 0x0D, 0x0E};
constexpr char kSm2PubId[] = {0x04};
// TODO: Obtain the TPM Attestation Key (AK) public ECC Qx and Qy from a configuration file or over the network.
const std::string kAkEccPubQx = "8888F1B69B1F71AAD460E1AF85D032D44A63C148A2FF677172E0666AD2192C3D";
const std::string kAkEccPubQy = "EE4C860208D4333AEED756FBB2FE471C152E3E00A7C4FAF2E46D3506FEFB2B72";
using base64 = cppcodec::base64_rfc4648;


}  // namespace
void HyperenclaveAttestationVerifier::CheckEnclaveSignature(sgx_quote_t* pquote) {
  platform_quote_sig_t* psig = RCAST(platform_quote_sig_t*, pquote->signature);

  // Get the report_body as data
  std::string data_str(RCCHAR(&pquote->report_body), sizeof(sgx_report_body_t));
  // Get the sm2_signaure_t type signature
  std::string sig_str(RCCHAR(psig->enclave_sig), SM2_SIG_SIZE);
  // Get the sm2_pub_key_t type public key with public key ID;
  std::string pubkey(kSm2PubId, 1);
  pubkey.append(RCCHAR(psig->hv_att_key_pub), SM2_SIG_SIZE);
  // Get the UsedrID
  std::string user_id(kUserId, sizeof(kUserId));

  YACL_ENFORCE_EQ(
    Sm2Crypto::VerifyUseZ(data_str, user_id, pubkey, sig_str), 0, 
    "Sm2 verify failed, hyperenclave's quote sig check failed");

}
void HyperenclaveAttestationVerifier::CheckPlatformAttestation(
    sgx_quote_t* pquote) {
  platform_quote_sig_t* psig = RCAST(platform_quote_sig_t*, pquote->signature);

  // Verify the attestation signature
  std::string data_str(RCCHAR(psig->platform_attest), TPM_ATTEST_SIZE);
  std::string sig_str(RCCHAR(psig->platform_sig), SM2_SIG_SIZE);
  std::string user_id(kUserId, sizeof(kUserId));
  YACL_ENFORCE_EQ(
    Sm2Crypto::Verify(data_str, user_id, tpm_signing_pubkey_, sig_str), 0, 
    "Sm2 verify failed, verify the TPM quote's signature failed");
 
  // Get the TPM attestation data
  init_tpms_attest(&tpm_attest_);
  YACL_ENFORCE_EQ(
    decode_tpm_attest_data(psig->platform_attest, TPM_ATTEST_SIZE,
                              &tpm_attest_), true, 
    "decode_tpm_attest_data failed");


  // Also calculate the PCSs digest in certificate and compare to
  // which in attestation data, this digest in attestation data is
  // calculated based on current platform status when create
  // attestation report each time.
  // Since the open-source HyperEnclave does not support certificate mode, we skip the CheckPlatformPcrList
//   TEE_CHECK_RETURN(CheckPlatformPcrList(pquote)); 

}
void HyperenclaveAttestationVerifier::Init() {
  YACL_ENFORCE_EQ(report_.str_report_version(), kReportVersion,
                  "Only version {} is supported, but {}", kReportVersion,
                  report_.str_report_version());
  YACL_ENFORCE_EQ(report_.str_report_type(), ReportType::kReportTypePassport,
                  "Only {} is supported now, but {}",
                  ReportType::kReportTypePassport, report_.str_report_type());

  // Check the platform
  YACL_ENFORCE_EQ(report_.str_tee_platform(), Platform::kPlatformHyperEnclave,
                  "It's not {} platfrom, input platform is {}",
                  Platform::kPlatformHyperEnclave, report_.str_tee_platform());

  // Get the report data, which is serialized json string of HyperEnclaveReport
  secretflowapis::v2::sdc::HyperEnclaveReport hyper_report;
  JSON2PB(report_.json_report(), &hyper_report);
  quote_ = base64::decode(hyper_report.b64_quote());

  // Attempt to read AK public key Qx and Qy from environment variables
  const char* env_qx = std::getenv("AKPubQx");
  const char* env_qy = std::getenv("AKPubQy");

  std::string ak_ecc_pub_qx = env_qx ? env_qx : kAkEccPubQx;
  std::string ak_ecc_pub_qy = env_qy ? env_qy : kAkEccPubQy;

  //Create TPM AK public key via Qx and Qy
  sm2_pub_key_t pubkey;

  YACL_ENFORCE_EQ(
    createSm2PubKeyFromHex(ak_ecc_pub_qx, ak_ecc_pub_qy, pubkey), true, 
    "Failed to create SM2 public key.");

  size_t keylen = sizeof(sm2_pub_key_t);
  tpm_signing_pubkey_.assign(RCCHAR(pubkey.key), keylen);

}

void HyperenclaveAttestationVerifier::ParseUnifiedReport(
    secretflowapis::v2::sdc::UnifiedAttestationAttributes& attrs) {
  attrs.set_str_tee_platform(report_.str_tee_platform());
  YACL_ENFORCE_GE(quote_.size(), sizeof(sgx_quote_t),
                  "quote size:{} is less than sgx_quote3_t:{}", quote_.size(),
                  sizeof(sgx_quote_t));
  const sgx_quote_t* pquote =
      reinterpret_cast<const sgx_quote_t*>(quote_.data());
  const sgx_report_body_t* report_body = &(pquote->report_body);

  // MRENCLAVE
  std::string mr_enclave = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(&(report_body->mr_enclave)),
      sizeof(sgx_measurement_t)));

  // MRSIGNER
  std::string mr_signer = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(&(report_body->mr_signer)),
      sizeof(sgx_measurement_t)));

  // ISV product id
  auto prod_id = report_body->isv_prod_id;

  // ISV SVN
  auto svn = report_body->isv_svn;

  // User Data
  YACL_ENFORCE_EQ(kReportDataSize, sizeof(sgx_report_data_t),
                  "Report data size is not {}", kReportDataSize);
  uint32_t half_report_data_size = kReportDataSize >> 1;
  const char* p_report_data =
      reinterpret_cast<const char*>(&(report_body->report_data.d));
  // Export the lower 32 bytes as user data
  std::string hex_user_data = absl::BytesToHexString(
      absl::string_view(p_report_data, half_report_data_size));
  // Export the higher 32 bytes as public key hash
  std::string hex_public_key_hash = absl::BytesToHexString(absl::string_view(
      p_report_data + half_report_data_size, half_report_data_size));

  attrs.set_hex_ta_measurement(mr_enclave);
  attrs.set_hex_signer(mr_signer);
  // TODO: hex prod_id
  attrs.set_hex_prod_id(std::to_string(prod_id));
  attrs.set_str_min_isvsvn(std::to_string(svn));
  attrs.set_hex_user_data(hex_user_data);
  attrs.set_hex_hash_or_pem_pubkey(hex_public_key_hash);

  uint64_t flags = report_body->attributes.flags;
  if ((flags & SGX_FLAGS_DEBUG) == SGX_FLAGS_DEBUG) {
    attrs.set_bool_debug_disabled("false");
  } else {
    attrs.set_bool_debug_disabled("true");
  }
  //For hyperenclave, fill the pcr_digest into boot measurement
  // pcr_digest
  std::string pcr_digest = absl::BytesToHexString(absl::string_view(
      reinterpret_cast<const char*>(&tpm_attest_.quote.pcr_digest.t.buffer),
      HASH_LENGTH));
  attrs.set_hex_boot_measurement(pcr_digest);
}

void HyperenclaveAttestationVerifier::VerifyPlatform() {
 
  sgx_quote_t* pquote = RCAST(sgx_quote_t*, quote_.data());

  //Step1. Verify the report_body signature via Hyperencalve signin public key
  CheckEnclaveSignature(pquote);

  //Step2. Verify the attestation signature via TPM signing public key
  CheckPlatformAttestation(pquote);

 
}

}  // namespace verification
}  // namespace attestation
}  // namespace trustflow