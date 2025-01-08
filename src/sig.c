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
            0xB0, 0x6D, 0x07, 0x30, 0xC2, 0xAB, 0x82, 0xD5, 0x48, 0x23, 0xDF, 0x02, 0x00, 0xE8, 0x1F, 0x04, 
            0x09, 0x6F, 0x9E, 0xAD, 0xE7, 0x51, 0x7E, 0xD7, 0x45, 0x6E, 0xF8, 0x37, 0xC2, 0xC1, 0x1F, 0xA4, 
            0xA2, 0x50, 0x67, 0xD8, 0xF7, 0xF8, 0x13, 0xB3, 0x91, 0xC1, 0xA6, 0x35, 0x29, 0x9B, 0xE7, 0x75, 
            0xD1, 0x38, 0xBB, 0x2C, 0xD7, 0xA1, 0xBB, 0x5B, 0x29, 0x7E, 0xBE, 0xC0, 0xF5, 0xFE, 0x2A, 0x96, 
            0xF2, 0x4C, 0x1F, 0x08, 0xC6, 0x0B, 0xB8, 0xDC, 0xE3, 0x60, 0x25, 0xE1, 0x75, 0xD2, 0x11, 0x3F, 
            0x29, 0x36, 0xCE, 0x55, 0xE3, 0x68, 0xF9, 0xFE, 0x97, 0x3F, 0xC5, 0xB3, 0x7E, 0x34, 0x3F, 0xD9, 
            0x91, 0x0E, 0x83, 0xC7, 0x9B, 0xEB, 0xF8, 0xAD, 0xDD, 0x35, 0xE4, 0x23, 0x66, 0xB0, 0xD2, 0x2D, 
            0xF5, 0x8D, 0x4C, 0x38, 0x69, 0xD3, 0x66, 0x88, 0xB3, 0x05, 0xA5, 0xFB, 0x30, 0xE7, 0xF8, 0xA7, 
            0x2E, 0x4B, 0xC4, 0xD6, 0x84, 0x01, 0x6E, 0x68, 0xA2, 0x1F, 0x7E, 0xAC, 0xF9, 0x10, 0xAA, 0xF8, 
            0xCF, 0xCD, 0x85, 0x2A, 0x49, 0x6B, 0xB5, 0x5A, 0xE1, 0x2C, 0xAD, 0xFA, 0x84, 0xE5, 0x16, 0x33, 
            0xCF, 0xB7, 0xEC, 0xCA, 0x5B, 0xE4, 0x60, 0xD8, 0x88, 0xF1, 0x65, 0xAA, 0xD5, 0x94, 0xBE, 0x6E, 
            0x7E, 0x82, 0xE4, 0xCC, 0x30, 0xA7, 0x44, 0x67, 0xE3, 0x71, 0xA3, 0x42, 0xBD, 0xEC, 0x0B, 0xA9, 
            0xB1, 0x08, 0xF8, 0x10, 0xA4, 0xDF, 0x59, 0xCD, 0xB4, 0xB0, 0xCF, 0x7C, 0xDB, 0x64, 0x35, 0x8E, 
            0x5B, 0xEE, 0x41, 0xC9, 0xFC, 0xCE, 0x13, 0x13, 0x35, 0xC7, 0x4C, 0x16, 0xE6, 0x0B, 0xEA, 0x76, 
            0xD1, 0x02, 0x1D, 0xB8, 0x19, 0xC2, 0xDC, 0xCC, 0x25, 0x52, 0x45, 0x99, 0x88, 0x0A, 0xF2, 0xAE, 
            0x56, 0x7A, 0xF7, 0xD7, 0x5E, 0xC8, 0xB0, 0x84, 0x72, 0x49, 0x83, 0x50, 0x69, 0x16, 0x29, 0xF5
        },
        .public_key_e = {0x01, 0x00, 0x01},
        .extensions = "Key Usage: Digital Signature, Key Encipherment",
        .signature = {
            0x6C, 0x8C, 0xB2, 0xA3, 0xE2, 0x2E, 0x80, 0xE2, 0x9F, 0x35, 0xD2, 0xCD, 0x8D, 0x8F, 0xEA, 0x98, 
            0x49, 0x63, 0x71, 0xA3, 0xD7, 0x0A, 0x3C, 0x01, 0xC4, 0xE0, 0x99, 0x6B, 0xB8, 0x25, 0x6E, 0xEE, 
            0x49, 0xD8, 0x7A, 0xE3, 0xDF, 0x0B, 0xB0, 0xFD, 0xCE, 0x21, 0xEF, 0x7A, 0xAF, 0xFD, 0x6B, 0x2A, 
            0xEA, 0x04, 0x20, 0x61, 0x49, 0x11, 0xD8, 0xA3, 0x2A, 0x5E, 0xE9, 0xE8, 0x8E, 0x11, 0x49, 0xD1, 
            0xDD, 0x7B, 0x3F, 0xCC, 0x13, 0xAB, 0xE6, 0xA9, 0xBC, 0xC7, 0x79, 0x17, 0x24, 0x4F, 0x8B, 0x77, 
            0x4F, 0x8F, 0xDC, 0x71, 0xFC, 0x2B, 0x9E, 0x24, 0x23, 0x3D, 0x9D, 0x70, 0x42, 0x79, 0x35, 0xB2, 
            0x08, 0x67, 0x83, 0xFF, 0x34, 0x11, 0x24, 0x12, 0x87, 0x5F, 0x23, 0x5C, 0x8C, 0x9C, 0x9C, 0xB3, 
            0xAB, 0x66, 0xA2, 0xA8, 0xBA, 0x00, 0xFF, 0xAC, 0xEC, 0x35, 0x0B, 0xAF, 0xF3, 0xC2, 0x0D, 0x6A, 
            0x63, 0xBD, 0x2B, 0x66, 0xAF, 0x13, 0xF2, 0xEC, 0xF2, 0x9C, 0xE8, 0x4A, 0x32, 0xF3, 0xD8, 0xF0, 
            0xA5, 0xFC, 0x4F, 0xC2, 0x32, 0x79, 0x71, 0xEE, 0x49, 0xB9, 0xE7, 0x75, 0xC3, 0xCF, 0xF4, 0xAE, 
            0x6B, 0x74, 0x23, 0x16, 0x98, 0x2F, 0x64, 0xB8, 0x89, 0x78, 0xAB, 0x94, 0x6D, 0xF5, 0x65, 0xF4, 
            0xA2, 0x20, 0x09, 0xC5, 0x28, 0xB2, 0x76, 0xA4, 0x84, 0xD4, 0xEE, 0xB2, 0x20, 0x4C, 0x08, 0x74, 
            0x10, 0x7A, 0xE8, 0x53, 0x9B, 0x0E, 0x31, 0xD8, 0x2A, 0x93, 0x1A, 0xC4, 0xA5, 0xD7, 0xE4, 0x12, 
            0x4C, 0xCA, 0x16, 0x93, 0xB2, 0xFA, 0x15, 0xFD, 0xDD, 0x92, 0x1F, 0xFB, 0x7D, 0xF4, 0x16, 0xC5, 
            0x3F, 0xE7, 0x50, 0x65, 0x0C, 0x62, 0xE3, 0x8B, 0x86, 0x83, 0xF1, 0xFA, 0x06, 0x69, 0x88, 0x1A, 
            0x71, 0x41, 0x22, 0x7C, 0x58, 0xF9, 0x85, 0xCA, 0x9B, 0x02, 0x3B, 0x0C, 0xCD, 0x2A, 0x04, 0x2D
        }
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
