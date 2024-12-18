set(SOURCES hyperenclave_verifier.cc platform.cc sm2.cc sm3.cc)

add_library(hyperenclave_verifier STATIC ${SOURCES})
target_link_libraries(
  hyperenclave_verifier
  ual_proto
  yacl_buffer
  cppcodec
  sgx_headers
  yacl_crypto spdlog::spdlog_header_only)
