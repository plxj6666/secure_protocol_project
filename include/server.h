#include "sig.h"

void init_server_socket();

void receive_handshake_request();

void* receive_thread_func(void* arg);

void* send_thread_func(void* arg);

Certificate server_current_cert = {
        .version = "v3",
        .serial_number = {0x02, 0x3A, 0xF1, 0xE6, 0xA7, 0x11, 0xA9, 0xA0, 0xBB, 0x28, 0x64, 0xB1, 0x1D, 0x09, 0xFA, 0xE5},
        .signature_algo = "sha256WithRSAEncryption",
        .issuer = "CN = DigiCert Global Root G2, OU = www.digicert.com, O = DigiCert Inc, C = US",
        .subject = "CN=Server",
        .validity_not_before = "2025-01-01 00:00:00",
        .validity_not_after = "2026-01-01 00:00:00",
        .public_key_n =  {0x00},
        .public_key_e = {0x00},
        .extensions = "Key Usage: Digital Signature, Key Encipherment",
        .signature = {0x00}
};
