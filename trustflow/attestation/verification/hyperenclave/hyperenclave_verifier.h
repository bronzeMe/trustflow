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

#pragma once

#include "yacl/base/buffer.h"
#include "sgx_quote_3.h"
#include "trustflow/attestation/verification/interface/verifier.h"
#include "trustflow/attestation/verification/hyperenclave/platform.h"
#include "trustflow/attestation/verification/hyperenclave/sm2.h"
#include "trustflow/attestation/verification/hyperenclave/type.h"
namespace trustflow {
namespace attestation {
namespace verification {

typedef struct platform_quote_sig_s {
  unsigned char enclave_sig[SM2_SIG_SIZE];
  unsigned char hv_att_key_pub[SM2_SIG_SIZE];
  unsigned char platform_attest[TPM_ATTEST_SIZE];
  unsigned char platform_sig[SM2_SIG_SIZE];
  unsigned char cert[];
} platform_quote_sig_t;

class HyperenclaveAttestationVerifier : public AttestationVerifier {
 public:
  explicit HyperenclaveAttestationVerifier(const std::string& report_json_str)
      : AttestationVerifier(report_json_str) {
    Init();
  }

  explicit HyperenclaveAttestationVerifier(
      const secretflowapis::v2::sdc::UnifiedAttestationReport& report)
      : AttestationVerifier(report) {
    Init();
  }

  void ParseUnifiedReport(
      secretflowapis::v2::sdc::UnifiedAttestationAttributes& attrs) override;

  void VerifyPlatform() override;

  static std::unique_ptr<AttestationVerifier> Create(
      const secretflowapis::v2::sdc::UnifiedAttestationReport& report) {
    return std::make_unique<HyperenclaveAttestationVerifier>(report);
  }

 protected:
  void Init();

 private:
  void CheckEnclaveSignature(sgx_quote_t* pquote);
  void CheckPlatformAttestation(sgx_quote_t* pquote);
  // Internal variables
  TPMS_ATTEST tpm_attest_;
  std::string tpm_signing_pubkey_;
  std::vector<uint8_t> quote_;

};

}  // namespace verification
}  // namespace attestation
}  // namespace trustflow