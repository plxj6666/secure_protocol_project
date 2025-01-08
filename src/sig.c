#include "sig.h"

// 全局变量定义
Certificate root_cert = {
        .version = "v3",
        .serial_number = {0x03, 0x3A, 0xF1, 0xE6, 0xA7, 0x11, 0xA9, 0xA0, 0xBB, 0x28, 0x64, 0xB1, 0x1D, 0x09, 0xFA, 0xE5},
        .signature_algo = "sha256WithRSAEncryption",
        .issuer = "CN = DigiCert Global Root G2, OU = www.digicert.com, O = DigiCert Inc, C = US",
        .subject = "CN = DigiCert Global Root G2, OU = www.digicert.com, O = DigiCert Inc, C = US",
        .validity_not_before = "2013-08-01 00:00:00",
        .validity_not_after = "2038-1-15 00:00:00",
        .public_key_n =  {
            0xBB, 0x37, 0xCD, 0x34, 0xDC, 0x7B, 0x6B, 0xC9, 0xB2, 0x68, 0x90, 0xAD, 0x4A, 0x75, 0xFF, 0x46,
            0xBA, 0x21, 0x0A, 0x08, 0x8D, 0xF5, 0x19, 0x54, 0xC9, 0xFB, 0x88, 0xDB, 0xF3, 0xAE, 0xF2, 0x3A,
            0x89, 0x91, 0x3C, 0x7A, 0xE6, 0xAB, 0x06, 0x1A, 0x6B, 0xCF, 0xAC, 0x2D, 0xE8, 0x5E, 0x09, 0x24,
            0x44, 0xBA, 0x62, 0x9A, 0x7E, 0xD6, 0xA3, 0xA8, 0x7E, 0xE0, 0x54, 0x75, 0x20, 0x05, 0xAC, 0x50,
            0xB7, 0x9C, 0x63, 0x1A, 0x6C, 0x30, 0xDC, 0xDA, 0x1F, 0x19, 0xB1, 0xD7, 0x1E, 0xDE, 0xFD, 0xD7,
            0xE0, 0xCB, 0x94, 0x83, 0x37, 0xAE, 0xEC, 0x1F, 0x43, 0x4E, 0xDD, 0x7B, 0x2C, 0xD2, 0xBD, 0x2E,
            0xA5, 0x2F, 0xE4, 0xA9, 0xB8, 0xAD, 0x3A, 0xD4, 0x99, 0xA4, 0xB6, 0x25, 0xE9, 0x9B, 0x6B, 0x00,
            0x60, 0x92, 0x60, 0xFF, 0x4F, 0x21, 0x49, 0x18, 0xF7, 0x67, 0x90, 0xAB, 0x61, 0x06, 0x9C, 0x8F,
            0xF2, 0xBA, 0xE9, 0xB4, 0xE9, 0x92, 0x32, 0x6B, 0xB5, 0xF3, 0x57, 0xE8, 0x5D, 0x1B, 0xCD, 0x8C,
            0x1D, 0xAB, 0x95, 0x04, 0x95, 0x49, 0xF3, 0x35, 0x2D, 0x96, 0xE3, 0x49, 0x6D, 0xDD, 0x77, 0xE3,
            0xFB, 0x49, 0x4B, 0xB4, 0xAC, 0x55, 0x07, 0xA9, 0x8F, 0x95, 0xB3, 0xB4, 0x23, 0xBB, 0x4C, 0x6D,
            0x45, 0xF0, 0xF6, 0xA9, 0xB2, 0x95, 0x30, 0xB4, 0xFD, 0x4C, 0x55, 0x8C, 0x27, 0x4A, 0x57, 0x14,
            0x7C, 0x82, 0x9D, 0xCD, 0x73, 0x92, 0xD3, 0x16, 0x4A, 0x06, 0x0C, 0x8C, 0x50, 0xD1, 0x8F, 0x1E,
            0x09, 0xBE, 0x17, 0xA1, 0xE6, 0x21, 0xCA, 0xFD, 0x83, 0xE5, 0x10, 0xBC, 0x83, 0xA5, 0x0A, 0xC4,
            0x67, 0x28, 0xF6, 0x73, 0x14, 0x14, 0x3D, 0x46, 0x76, 0xC3, 0x87, 0x14, 0x89, 0x21, 0x34, 0x4D,
            0xAF, 0x0F, 0x45, 0x0C, 0xA6, 0x49, 0xA1, 0xBA, 0xBB, 0x9C, 0xC5, 0xB1, 0x33, 0x83, 0x29, 0x85
        },
        .public_key_e = {0x01, 0x00, 0x01},
        .extensions = "Key Usage: Digital Signature, Key Encipherment",
        .signature = {0xAB}
};

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

unsigned char server_session_key[16];
unsigned char client_session_key[16];
int client_socket = -1;
int server_socket = -1;
int client_seq = 0;
int server_seq = 0;
int flag = 1;