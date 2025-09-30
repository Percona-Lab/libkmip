//
// Created by al on 29.09.25.
//

#ifndef KMIP_KMIP_ENUMS_H
#define KMIP_KMIP_ENUMS_H
#ifdef __cplusplus
extern "C"
{
#endif

#define KMIP_MAX_MESSAGE_SIZE 8192
#define KMIP_ERROR_MESSAGE_SIZE  200

  /*
  Types and Constants
  */

  typedef int8_t  int8;
  typedef int16_t int16;
  typedef int32_t int32;
  typedef int64_t int64;
  typedef int32   bool32;

  typedef uint8_t  uint8;
  typedef uint16_t uint16;
  typedef uint32_t uint32;
  typedef uint64_t uint64;

  typedef size_t memory_index;

#ifdef intptr_t
  typedef intptr_t intptr;
#else
typedef int64 intptr;
#endif

  typedef float  real32;
  typedef double real64;

#define KMIP_TRUE  (1)
#define KMIP_FALSE (0)

#define KMIP_UNSET (-1)

#define KMIP_MIN(a, b) (((a) < (b)) ? (a) : (b))

#define KMIP_OK                      (0)
#define KMIP_NOT_IMPLEMENTED         (-1)
#define KMIP_ERROR_BUFFER_FULL       (-2)
#define KMIP_ERROR_ATTR_UNSUPPORTED  (-3)
#define KMIP_TAG_MISMATCH            (-4)
#define KMIP_TYPE_MISMATCH           (-5)
#define KMIP_LENGTH_MISMATCH         (-6)
#define KMIP_PADDING_MISMATCH        (-7)
#define KMIP_BOOLEAN_MISMATCH        (-8)
#define KMIP_ENUM_MISMATCH           (-9)
#define KMIP_ENUM_UNSUPPORTED        (-10)
#define KMIP_INVALID_FOR_VERSION     (-11)
#define KMIP_MEMORY_ALLOC_FAILED     (-12)
#define KMIP_IO_FAILURE              (-13)
#define KMIP_EXCEED_MAX_MESSAGE_SIZE (-14)
#define KMIP_MALFORMED_RESPONSE      (-15)
#define KMIP_OBJECT_MISMATCH         (-16)
#define KMIP_ARG_INVALID             (-17)
#define KMIP_ERROR_BUFFER_UNDERFULL  (-18)
#define KMIP_INVALID_ENCODING        (-19)
#define KMIP_INVALID_FIELD           (-20)
#define KMIP_INVALID_LENGTH          (-21)

  /*
  Enumerations
  */

  enum attestation_type
  {
    /* KMIP 1.2 */
    KMIP_ATTEST_TPM_QUOTE            = 0x01,
    KMIP_ATTEST_TCG_INTEGRITY_REPORT = 0x02,
    KMIP_ATTEST_SAML_ASSERTION       = 0x03
  };

  enum attribute_type
  {
    /* KMIP 1.0 */
    KMIP_ATTR_UNIQUE_IDENTIFIER                = 0,
    KMIP_ATTR_NAME                             = 1,
    KMIP_ATTR_OBJECT_TYPE                      = 2,
    KMIP_ATTR_CRYPTOGRAPHIC_ALGORITHM          = 3,
    KMIP_ATTR_CRYPTOGRAPHIC_LENGTH             = 4,
    KMIP_ATTR_OPERATION_POLICY_NAME            = 5,
    KMIP_ATTR_CRYPTOGRAPHIC_USAGE_MASK         = 6,
    KMIP_ATTR_STATE                            = 7,
    KMIP_ATTR_APPLICATION_SPECIFIC_INFORMATION = 8,
    KMIP_ATTR_OBJECT_GROUP                     = 9,
    KMIP_ATTR_ACTIVATION_DATE                  = 10,
    KMIP_ATTR_DEACTIVATION_DATE                = 11,
    KMIP_ATTR_PROCESS_START_DATE               = 12,
    KMIP_ATTR_PROTECT_STOP_DATE                = 13,
    KMIP_ATTR_CRYPTOGRAPHIC_PARAMETERS         = 14
  };

  enum batch_error_continuation_option
  {
    /* KMIP 1.0 */
    KMIP_BATCH_CONTINUE = 0x01,
    KMIP_BATCH_STOP     = 0x02,
    KMIP_BATCH_UNDO     = 0x03
  };

  enum block_cipher_mode
  {
    /* KMIP 1.0 */
    KMIP_BLOCK_CBC                  = 0x01,
    KMIP_BLOCK_ECB                  = 0x02,
    KMIP_BLOCK_PCBC                 = 0x03,
    KMIP_BLOCK_CFB                  = 0x04,
    KMIP_BLOCK_OFB                  = 0x05,
    KMIP_BLOCK_CTR                  = 0x06,
    KMIP_BLOCK_CMAC                 = 0x07,
    KMIP_BLOCK_CCM                  = 0x08,
    KMIP_BLOCK_GCM                  = 0x09,
    KMIP_BLOCK_CBC_MAC              = 0x0A,
    KMIP_BLOCK_XTS                  = 0x0B,
    KMIP_BLOCK_AES_KEY_WRAP_PADDING = 0x0C,
    KMIP_BLOCK_NIST_KEY_WRAP        = 0x0D,
    KMIP_BLOCK_X9102_AESKW          = 0x0E,
    KMIP_BLOCK_X9102_TDKW           = 0x0F,
    KMIP_BLOCK_X9102_AKW1           = 0x10,
    KMIP_BLOCK_X9102_AKW2           = 0x11,
    /* KMIP 1.4 */
    KMIP_BLOCK_AEAD                 = 0x12
  };

  enum credential_type
  {
    /* KMIP 1.0 */
    KMIP_CRED_USERNAME_AND_PASSWORD = 0x01,
    /* KMIP 1.1 */
    KMIP_CRED_DEVICE                = 0x02,
    /* KMIP 1.2 */
    KMIP_CRED_ATTESTATION           = 0x03,
    /* KMIP 2.0 */
    KMIP_CRED_ONE_TIME_PASSWORD     = 0x04,
    KMIP_CRED_HASHED_PASSWORD       = 0x05,
    KMIP_CRED_TICKET                = 0x06
  };

  enum cryptographic_algorithm
  {
    KMIP_CRYPTOALG_UNSET             = 0x00,
    /* KMIP 1.0 */
    KMIP_CRYPTOALG_DES               = 0x01,
    KMIP_CRYPTOALG_TRIPLE_DES        = 0x02,
    KMIP_CRYPTOALG_AES               = 0x03,
    KMIP_CRYPTOALG_RSA               = 0x04,
    KMIP_CRYPTOALG_DSA               = 0x05,
    KMIP_CRYPTOALG_ECDSA             = 0x06,
    KMIP_CRYPTOALG_HMAC_SHA1         = 0x07,
    KMIP_CRYPTOALG_HMAC_SHA224       = 0x08,
    KMIP_CRYPTOALG_HMAC_SHA256       = 0x09,
    KMIP_CRYPTOALG_HMAC_SHA384       = 0x0A,
    KMIP_CRYPTOALG_HMAC_SHA512       = 0x0B,
    KMIP_CRYPTOALG_HMAC_MD5          = 0x0C,
    KMIP_CRYPTOALG_DH                = 0x0D,
    KMIP_CRYPTOALG_ECDH              = 0x0E,
    KMIP_CRYPTOALG_ECMQV             = 0x0F,
    KMIP_CRYPTOALG_BLOWFISH          = 0x10,
    KMIP_CRYPTOALG_CAMELLIA          = 0x11,
    KMIP_CRYPTOALG_CAST5             = 0x12,
    KMIP_CRYPTOALG_IDEA              = 0x13,
    KMIP_CRYPTOALG_MARS              = 0x14,
    KMIP_CRYPTOALG_RC2               = 0x15,
    KMIP_CRYPTOALG_RC4               = 0x16,
    KMIP_CRYPTOALG_RC5               = 0x17,
    KMIP_CRYPTOALG_SKIPJACK          = 0x18,
    KMIP_CRYPTOALG_TWOFISH           = 0x19,
    /* KMIP 1.2 */
    KMIP_CRYPTOALG_EC                = 0x1A,
    /* KMIP 1.3 */
    KMIP_CRYPTOALG_ONE_TIME_PAD      = 0x1B,
    /* KMIP 1.4 */
    KMIP_CRYPTOALG_CHACHA20          = 0x1C,
    KMIP_CRYPTOALG_POLY1305          = 0x1D,
    KMIP_CRYPTOALG_CHACHA20_POLY1305 = 0x1E,
    KMIP_CRYPTOALG_SHA3_224          = 0x1F,
    KMIP_CRYPTOALG_SHA3_256          = 0x20,
    KMIP_CRYPTOALG_SHA3_384          = 0x21,
    KMIP_CRYPTOALG_SHA3_512          = 0x22,
    KMIP_CRYPTOALG_HMAC_SHA3_224     = 0x23,
    KMIP_CRYPTOALG_HMAC_SHA3_256     = 0x24,
    KMIP_CRYPTOALG_HMAC_SHA3_384     = 0x25,
    KMIP_CRYPTOALG_HMAC_SHA3_512     = 0x26,
    KMIP_CRYPTOALG_SHAKE_128         = 0x27,
    KMIP_CRYPTOALG_SHAKE_256         = 0x28,
    /* KMIP 2.0 */
    KMIP_CRYPTOALG_ARIA              = 0x29,
    KMIP_CRYPTOALG_SEED              = 0x2A,
    KMIP_CRYPTOALG_SM2               = 0x2B,
    KMIP_CRYPTOALG_SM3               = 0x2C,
    KMIP_CRYPTOALG_SM4               = 0x2D,
    KMIP_CRYPTOALG_GOST_R_34_10_2012 = 0x2E,
    KMIP_CRYPTOALG_GOST_R_34_11_2012 = 0x2F,
    KMIP_CRYPTOALG_GOST_R_34_13_2015 = 0x30,
    KMIP_CRYPTOALG_GOST_28147_89     = 0x31,
    KMIP_CRYPTOALG_XMSS              = 0x32,
    KMIP_CRYPTOALG_SPHINCS_256       = 0x33,
    KMIP_CRYPTOALG_MCELIECE          = 0x34,
    KMIP_CRYPTOALG_MCELIECE_6960119  = 0x35,
    KMIP_CRYPTOALG_MCELIECE_8192128  = 0x36,
    KMIP_CRYPTOALG_ED25519           = 0x37,
    KMIP_CRYPTOALG_ED448             = 0x38
  };

  enum cryptographic_usage_mask
  {
    KMIP_CRYPTOMASK_UNSET               = 0x00000000,
    /* KMIP 1.0 */
    KMIP_CRYPTOMASK_SIGN                = 0x00000001,
    KMIP_CRYPTOMASK_VERIFY              = 0x00000002,
    KMIP_CRYPTOMASK_ENCRYPT             = 0x00000004,
    KMIP_CRYPTOMASK_DECRYPT             = 0x00000008,
    KMIP_CRYPTOMASK_WRAP_KEY            = 0x00000010,
    KMIP_CRYPTOMASK_UNWRAP_KEY          = 0x00000020,
    KMIP_CRYPTOMASK_EXPORT              = 0x00000040,
    KMIP_CRYPTOMASK_MAC_GENERATE        = 0x00000080,
    KMIP_CRYPTOMASK_MAC_VERIFY          = 0x00000100,
    KMIP_CRYPTOMASK_DERIVE_KEY          = 0x00000200,
    KMIP_CRYPTOMASK_CONTENT_COMMITMENT  = 0x00000400,
    KMIP_CRYPTOMASK_KEY_AGREEMENT       = 0x00000800,
    KMIP_CRYPTOMASK_CERTIFICATE_SIGN    = 0x00001000,
    KMIP_CRYPTOMASK_CRL_SIGN            = 0x00002000,
    KMIP_CRYPTOMASK_GENERATE_CRYPTOGRAM = 0x00004000,
    KMIP_CRYPTOMASK_VALIDATE_CRYPTOGRAM = 0x00008000,
    KMIP_CRYPTOMASK_TRANSLATE_ENCRYPT   = 0x00010000,
    KMIP_CRYPTOMASK_TRANSLATE_DECRYPT   = 0x00020000,
    KMIP_CRYPTOMASK_TRANSLATE_WRAP      = 0x00040000,
    KMIP_CRYPTOMASK_TRANSLATE_UNWRAP    = 0x00080000,
    /* KMIP 2.0 */
    KMIP_CRYPTOMASK_AUTHENTICATE        = 0x00100000,
    KMIP_CRYPTOMASK_UNRESTRICTED        = 0x00200000,
    KMIP_CRYPTOMASK_FPE_ENCRYPT         = 0x00400000,
    KMIP_CRYPTOMASK_FPE_DECRYPT         = 0x00800000
  };

  enum digital_signature_algorithm
  {
    /* KMIP 1.1 */
    KMIP_DIGITAL_MD2_WITH_RSA      = 0x01,
    KMIP_DIGITAL_MD5_WITH_RSA      = 0x02,
    KMIP_DIGITAL_SHA1_WITH_RSA     = 0x03,
    KMIP_DIGITAL_SHA224_WITH_RSA   = 0x04,
    KMIP_DIGITAL_SHA256_WITH_RSA   = 0x05,
    KMIP_DIGITAL_SHA384_WITH_RSA   = 0x06,
    KMIP_DIGITAL_SHA512_WITH_RSA   = 0x07,
    KMIP_DIGITAL_RSASSA_PSS        = 0x08,
    KMIP_DIGITAL_DSA_WITH_SHA1     = 0x09,
    KMIP_DIGITAL_DSA_WITH_SHA224   = 0x0A,
    KMIP_DIGITAL_DSA_WITH_SHA256   = 0x0B,
    KMIP_DIGITAL_ECDSA_WITH_SHA1   = 0x0C,
    KMIP_DIGITAL_ECDSA_WITH_SHA224 = 0x0D,
    KMIP_DIGITAL_ECDSA_WITH_SHA256 = 0x0E,
    KMIP_DIGITAL_ECDSA_WITH_SHA384 = 0x0F,
    KMIP_DIGITAL_ECDSA_WITH_SHA512 = 0x10,
    /* KMIP 1.4 */
    KMIP_DIGITAL_SHA3_256_WITH_RSA = 0x11,
    KMIP_DIGITAL_SHA3_384_WITH_RSA = 0x12,
    KMIP_DIGITAL_SHA3_512_WITH_RSA = 0x13
  };

  enum encoding_option
  {
    /* KMIP 1.1 */
    KMIP_ENCODE_NO_ENCODING   = 0x01,
    KMIP_ENCODE_TTLV_ENCODING = 0x02
  };

  enum hashing_algorithm
  {
    /* KMIP 1.0 */
    KMIP_HASH_MD2        = 0x01,
    KMIP_HASH_MD4        = 0x02,
    KMIP_HASH_MD5        = 0x03,
    KMIP_HASH_SHA1       = 0x04,
    KMIP_HASH_SHA224     = 0x05,
    KMIP_HASH_SHA256     = 0x06,
    KMIP_HASH_SHA384     = 0x07,
    KMIP_HASH_SHA512     = 0x08,
    KMIP_HASH_RIPEMD160  = 0x09,
    KMIP_HASH_TIGER      = 0x0A,
    KMIP_HASH_WHIRLPOOL  = 0x0B,
    /* KMIP 1.2 */
    KMIP_HASH_SHA512_224 = 0x0C,
    KMIP_HASH_SHA512_256 = 0x0D,
    /* KMIP 1.4 */
    KMIP_HASH_SHA3_224   = 0x0E,
    KMIP_HASH_SHA3_256   = 0x0F,
    KMIP_HASH_SHA3_384   = 0x10,
    KMIP_HASH_SHA3_512   = 0x11
  };

  enum key_compression_type
  {
    /* KMIP 1.0 */
    KMIP_KEYCOMP_EC_PUB_UNCOMPRESSED          = 0x01,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_PRIME = 0x02,
    KMIP_KEYCOMP_EC_PUB_X962_COMPRESSED_CHAR2 = 0x03,
    KMIP_KEYCOMP_EC_PUB_X962_HYBRID           = 0x04
  };

  enum key_format_type
  {
    /* KMIP 1.0 */
    KMIP_KEYFORMAT_RAW                     = 0x01,
    KMIP_KEYFORMAT_OPAQUE                  = 0x02,
    KMIP_KEYFORMAT_PKCS1                   = 0x03,
    KMIP_KEYFORMAT_PKCS8                   = 0x04,
    KMIP_KEYFORMAT_X509                    = 0x05,
    KMIP_KEYFORMAT_EC_PRIVATE_KEY          = 0x06,
    KMIP_KEYFORMAT_TRANS_SYMMETRIC_KEY     = 0x07,
    KMIP_KEYFORMAT_TRANS_DSA_PRIVATE_KEY   = 0x08,
    KMIP_KEYFORMAT_TRANS_DSA_PUBLIC_KEY    = 0x09,
    KMIP_KEYFORMAT_TRANS_RSA_PRIVATE_KEY   = 0x0A,
    KMIP_KEYFORMAT_TRANS_RSA_PUBLIC_KEY    = 0x0B,
    KMIP_KEYFORMAT_TRANS_DH_PRIVATE_KEY    = 0x0C,
    KMIP_KEYFORMAT_TRANS_DH_PUBLIC_KEY     = 0x0D,
    KMIP_KEYFORMAT_TRANS_ECDSA_PRIVATE_KEY = 0x0E, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDSA_PUBLIC_KEY  = 0x0F, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDH_PRIVATE_KEY  = 0x10, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECDH_PUBLIC_KEY   = 0x11, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECMQV_PRIVATE_KEY = 0x12, /* Deprecated as of KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_ECMQV_PUBLIC_KEY  = 0x13, /* Deprecated as of KMIP 1.3 */
    /* KMIP 1.3 */
    KMIP_KEYFORMAT_TRANS_EC_PRIVATE_KEY    = 0x14,
    KMIP_KEYFORMAT_TRANS_EC_PUBLIC_KEY     = 0x15,
    /* KMIP 1.4 */
    KMIP_KEYFORMAT_PKCS12                  = 0x16,
    /* KMIP 2.0 */
    KMIP_KEYFORMAT_PKCS10                  = 0x17
  };

  enum key_role_type
  {
    /* KMIP 1.0 */
    KMIP_ROLE_BDK      = 0x01,
    KMIP_ROLE_CVK      = 0x02,
    KMIP_ROLE_DEK      = 0x03,
    KMIP_ROLE_MKAC     = 0x04,
    KMIP_ROLE_MKSMC    = 0x05,
    KMIP_ROLE_MKSMI    = 0x06,
    KMIP_ROLE_MKDAC    = 0x07,
    KMIP_ROLE_MKDN     = 0x08,
    KMIP_ROLE_MKCP     = 0x09,
    KMIP_ROLE_MKOTH    = 0x0A,
    KMIP_ROLE_KEK      = 0x0B,
    KMIP_ROLE_MAC16609 = 0x0C,
    KMIP_ROLE_MAC97971 = 0x0D,
    KMIP_ROLE_MAC97972 = 0x0E,
    KMIP_ROLE_MAC97973 = 0x0F,
    KMIP_ROLE_MAC97974 = 0x10,
    KMIP_ROLE_MAC97975 = 0x11,
    KMIP_ROLE_ZPK      = 0x12,
    KMIP_ROLE_PVKIBM   = 0x13,
    KMIP_ROLE_PVKPVV   = 0x14,
    KMIP_ROLE_PVKOTH   = 0x15,
    /* KMIP 1.4 */
    KMIP_ROLE_DUKPT    = 0x16,
    KMIP_ROLE_IV       = 0x17,
    KMIP_ROLE_TRKBK    = 0x18
  };

  enum key_wrap_type
  {
    /* KMIP 1.4 */
    KMIP_WRAPTYPE_NOT_WRAPPED   = 0x01,
    KMIP_WRAPTYPE_AS_REGISTERED = 0x02
  };

  enum kmip_version
  {
    KMIP_1_0 = 0,
    KMIP_1_1 = 1,
    KMIP_1_2 = 2,
    KMIP_1_3 = 3,
    KMIP_1_4 = 4,
    KMIP_2_0 = 5
  };

  enum mask_generator
  {
    /* KMIP 1.4 */
    KMIP_MASKGEN_MGF1 = 0x01
  };

  enum name_type
  {
    /* KMIP 1.0 */
    KMIP_NAME_UNINTERPRETED_TEXT_STRING = 0x01,
    KMIP_NAME_URI                       = 0x02
  };

  enum object_type
  {
    /* KMIP 1.0 */
    KMIP_OBJTYPE_CERTIFICATE         = 0x01,
    KMIP_OBJTYPE_SYMMETRIC_KEY       = 0x02,
    KMIP_OBJTYPE_PUBLIC_KEY          = 0x03,
    KMIP_OBJTYPE_PRIVATE_KEY         = 0x04,
    KMIP_OBJTYPE_SPLIT_KEY           = 0x05,
    KMIP_OBJTYPE_TEMPLATE            = 0x06, /* Deprecated as of KMIP 1.3 */
    KMIP_OBJTYPE_SECRET_DATA         = 0x07,
    KMIP_OBJTYPE_OPAQUE_OBJECT       = 0x08,
    /* KMIP 1.2 */
    KMIP_OBJTYPE_PGP_KEY             = 0x09,
    /* KMIP 2.0 */
    KMIP_OBJTYPE_CERTIFICATE_REQUEST = 0x0A
  };

  enum operation
  {
    // # KMIP 1.0
    KMIP_OP_CREATE               = 0x01,
    KMIP_OP_CREATE_KEY_PAIR      = 0x02,
    KMIP_OP_REGISTER             = 0x03,
    KMIP_OP_REKEY                = 0x04,
    KMIP_OP_DERIVE_KEY           = 0x05,
    KMIP_OP_CERTIFY              = 0x06,
    KMIP_OP_RECERTIFY            = 0x07,
    KMIP_OP_LOCATE               = 0x08,
    KMIP_OP_CHECK                = 0x09,
    KMIP_OP_GET                  = 0x0A,
    KMIP_OP_GET_ATTRIBUTES       = 0x0B,
    KMIP_OP_GET_ATTRIBUTE_LIST   = 0x0C,
    KMIP_OP_ADD_ATTRIBUTE        = 0x0D,
    KMIP_OP_MODIFY_ATTRIBUTE     = 0x0E,
    KMIP_OP_DELETE_ATTRIBUTE     = 0x0F,
    KMIP_OP_OBTAIN_LEASE         = 0x10,
    KMIP_OP_GET_USAGE_ALLOCATION = 0x11,
    KMIP_OP_ACTIVATE             = 0x12,
    KMIP_OP_REVOKE               = 0x13,
    KMIP_OP_DESTROY              = 0x14,
    KMIP_OP_ARCHIVE              = 0x15,
    KMIP_OP_RECOVER              = 0x16,
    KMIP_OP_VALIDATE             = 0x17,
    KMIP_OP_QUERY                = 0x18,
    KMIP_OP_CANCEL               = 0x19,
    KMIP_OP_POLL                 = 0x1A,
    KMIP_OP_NOTIFY               = 0x1B,
    KMIP_OP_PUT                  = 0x1C,
    // # KMIP 1.1
    KMIP_OP_REKEY_KEY_PAIR       = 0x1D,
    KMIP_OP_DISCOVER_VERSIONS    = 0x1E,
    // # KMIP 1.2
    KMIP_OP_ENCRYPT              = 0x1F,
    KMIP_OP_DECRYPT              = 0x20,
    KMIP_OP_SIGN                 = 0x21,
    KMIP_OP_SIGNATURE_VERIFY     = 0x22,
    KMIP_OP_MAC                  = 0x23,
    KMIP_OP_MAC_VERIFY           = 0x24,
    KMIP_OP_RNG_RETRIEVE         = 0x25,
    KMIP_OP_RNG_SEED             = 0x26,
    KMIP_OP_HASH                 = 0x27,
    KMIP_OP_CREATE_SPLIT_KEY     = 0x28,
    KMIP_OP_JOIN_SPLIT_KEY       = 0x29,
    // # KMIP 1.4
    KMIP_OP_IMPORT               = 0x2A,
    KMIP_OP_EXPORT               = 0x2B,
    // # KMIP 2.0
    KMIP_OP_LOG                  = 0x2C,
    KMIP_OP_LOGIN                = 0x2D,
    KMIP_OP_LOGOUT               = 0x2E,
    KMIP_OP_DELEGATED_LOGIN      = 0x2F,
    KMIP_OP_ADJUST_ATTRIBUTE     = 0x30,
    KMIP_OP_SET_ATTRIBUTE        = 0x31,
    KMIP_OP_SET_ENDPOINT_ROLE    = 0x32,
    KMIP_OP_PKCS_11              = 0x33,
    KMIP_OP_INTEROP              = 0x34,
    KMIP_OP_REPROVISION          = 0x35,
  };

  enum padding_method
  {
    /* KMIP 1.0 */
    KMIP_PAD_NONE      = 0x01,
    KMIP_PAD_OAEP      = 0x02,
    KMIP_PAD_PKCS5     = 0x03,
    KMIP_PAD_SSL3      = 0x04,
    KMIP_PAD_ZEROS     = 0x05,
    KMIP_PAD_ANSI_X923 = 0x06,
    KMIP_PAD_ISO_10126 = 0x07,
    KMIP_PAD_PKCS1v15  = 0x08,
    KMIP_PAD_X931      = 0x09,
    KMIP_PAD_PSS       = 0x0A
  };

  enum protection_storage_mask
  {
    /* KMIP 2.0 */
    KMIP_PROTECT_SOFTWARE          = 0x00000001,
    KMIP_PROTECT_HARDWARE          = 0x00000002,
    KMIP_PROTECT_ON_PROCESSOR      = 0x00000004,
    KMIP_PROTECT_ON_SYSTEM         = 0x00000008,
    KMIP_PROTECT_OFF_SYSTEM        = 0x00000010,
    KMIP_PROTECT_HYPERVISOR        = 0x00000020,
    KMIP_PROTECT_OPERATING_SYSTEM  = 0x00000040,
    KMIP_PROTECT_CONTAINER         = 0x00000080,
    KMIP_PROTECT_ON_PREMISES       = 0x00000100,
    KMIP_PROTECT_OFF_PREMISES      = 0x00000200,
    KMIP_PROTECT_SELF_MANAGED      = 0x00000400,
    KMIP_PROTECT_OUTSOURCED        = 0x00000800,
    KMIP_PROTECT_VALIDATED         = 0x00001000,
    KMIP_PROTECT_SAME_JURISDICTION = 0x00002000
  };

  enum query_function
  {
    /* KMIP 1.0 */
    KMIP_QUERY_OPERATIONS                  = 0x0001,
    KMIP_QUERY_OBJECTS                     = 0x0002,
    KMIP_QUERY_SERVER_INFORMATION          = 0x0003,
    KMIP_QUERY_APPLICATION_NAMESPACES      = 0x0004,
    /* KMIP 1.1 */
    KMIP_QUERY_EXTENSION_LIST              = 0x0005,
    KMIP_QUERY_EXTENSION_MAP               = 0x0006,
    /* KMIP 1.2 */
    KMIP_QUERY_ATTESTATION_TYPES           = 0x0007,
    /* KMIP 1.3 */
    KMIP_QUERY_RNGS                        = 0x0008,
    KMIP_QUERY_VALIDATIONS                 = 0x0009,
    KMIP_QUERY_PROFILES                    = 0x000A,
    KMIP_QUERY_CAPABILITIES                = 0x000B,
    KMIP_QUERY_CLIENT_REGISTRATION_METHODS = 0x000C,
    /* KMIP 2.0 */
    KMIP_QUERY_DEFAULTS_INFORMATION        = 0x000D,
    KMIP_QUERY_STORAGE_PROTECTION_MASKS    = 0x000E
  };

  enum result_reason
  {
    /* KMIP 1.0 */
    KMIP_REASON_GENERAL_FAILURE                        = 0x0100,
    KMIP_REASON_ITEM_NOT_FOUND                         = 0x0001,
    KMIP_REASON_RESPONSE_TOO_LARGE                     = 0x0002,
    KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL          = 0x0003,
    KMIP_REASON_INVALID_MESSAGE                        = 0x0004,
    KMIP_REASON_OPERATION_NOT_SUPPORTED                = 0x0005,
    KMIP_REASON_MISSING_DATA                           = 0x0006,
    KMIP_REASON_INVALID_FIELD                          = 0x0007,
    KMIP_REASON_FEATURE_NOT_SUPPORTED                  = 0x0008,
    KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER        = 0x0009,
    KMIP_REASON_CRYPTOGRAPHIC_FAILURE                  = 0x000A,
    KMIP_REASON_ILLEGAL_OPERATION                      = 0x000B,
    KMIP_REASON_PERMISSION_DENIED                      = 0x000C,
    KMIP_REASON_OBJECT_ARCHIVED                        = 0x000D,
    KMIP_REASON_INDEX_OUT_OF_BOUNDS                    = 0x000E,
    KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED    = 0x000F,
    KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED          = 0x0010,
    KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED     = 0x0011,
    /* KMIP 1.1 */
    KMIP_REASON_ENCODING_OPTION_FAILURE                = 0x0012,
    /* KMIP 1.2 */
    KMIP_REASON_KEY_VALUE_NOT_PRESENT                  = 0x0013,
    KMIP_REASON_ATTESTATION_REQUIRED                   = 0x0014,
    KMIP_REASON_ATTESTATION_FAILED                     = 0x0015,
    /* KMIP 1.4 */
    KMIP_REASON_SENSITIVE                              = 0x0016,
    KMIP_REASON_NOT_EXTRACTABLE                        = 0x0017,
    KMIP_REASON_OBJECT_ALREADY_EXISTS                  = 0x0018,
    /* KMIP 2.0 */
    KMIP_REASON_INVALID_TICKET                         = 0x0019,
    KMIP_REASON_USAGE_LIMIT_EXCEEDED                   = 0x001A,
    KMIP_REASON_NUMERIC_RANGE                          = 0x001B,
    KMIP_REASON_INVALID_DATA_TYPE                      = 0x001C,
    KMIP_REASON_READ_ONLY_ATTRIBUTE                    = 0x001D,
    KMIP_REASON_MULTI_VALUED_ATTRIBUTE                 = 0x001E,
    KMIP_REASON_UNSUPPORTED_ATTRIBUTE                  = 0x001F,
    KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND           = 0x0020,
    KMIP_REASON_ATTRIBUTE_NOT_FOUND                    = 0x0021,
    KMIP_REASON_ATTRIBUTE_READ_ONLY                    = 0x0022,
    KMIP_REASON_ATTRIBUTE_SINGLE_VALUED                = 0x0023,
    KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS           = 0x0024,
    KMIP_REASON_BAD_PASSWORD                           = 0x0025,
    KMIP_REASON_CODEC_ERROR                            = 0x0026,
    /* Reserved                                       = 0x0027, */
    KMIP_REASON_ILLEGAL_OBJECT_TYPE                    = 0x0028,
    KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK  = 0x0029,
    KMIP_REASON_INTERNAL_SERVER_ERROR                  = 0x002A,
    KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE = 0x002B,
    KMIP_REASON_INVALID_ATTRIBUTE                      = 0x002C,
    KMIP_REASON_INVALID_ATTRIBUTE_VALUE                = 0x002D,
    KMIP_REASON_INVALID_CORRELATION_VALUE              = 0x002E,
    KMIP_REASON_INVALID_CSR                            = 0x002F,
    KMIP_REASON_INVALID_OBJECT_TYPE                    = 0x0030,
    /* Reserved                                        = 0x0031, */
    KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED            = 0x0032,
    /* Reserved                                        = 0x0033, */
    KMIP_REASON_MISSING_INITIALIZATION_VECTOR          = 0x0034,
    KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE              = 0x0035,
    KMIP_REASON_OBJECT_DESTROYED                       = 0x0036,
    KMIP_REASON_OBJECT_NOT_FOUND                       = 0x0037,
    /* Reserved                                        = 0x0038, */
    KMIP_REASON_NOT_AUTHORISED                         = 0x0039,
    KMIP_REASON_SERVER_LIMIT_EXCEEDED                  = 0x003A,
    KMIP_REASON_UNKNOWN_ENUMERATION                    = 0x003B,
    KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION              = 0x003C,
    KMIP_REASON_UNKNOWN_TAG                            = 0x003D,
    KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS   = 0x003E,
    KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION           = 0x003F,
    KMIP_REASON_WRAPPING_OBJECT_ARCHIVED               = 0x0040,
    KMIP_REASON_WRAPPING_OBJECT_DESTROYED              = 0x0041,
    KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND              = 0x0042,
    KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE              = 0x0043,
    KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE         = 0x0044,
    KMIP_REASON_PKCS11_CODEC_ERROR                     = 0x0045,
    KMIP_REASON_PKCS11_INVALID_FUNCTION                = 0x0046,
    KMIP_REASON_PKCS11_INVALID_INTERFACE               = 0x0047,
    KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE = 0x0048,
    KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE  = 0x0049
  };

  enum result_status
  {
    /* KMIP 1.0 */
    KMIP_STATUS_SUCCESS           = 0x00,
    KMIP_STATUS_OPERATION_FAILED  = 0x01,
    KMIP_STATUS_OPERATION_PENDING = 0x02,
    KMIP_STATUS_OPERATION_UNDONE  = 0x03
  };

  enum state
  {
    /* KMIP 1.0 */
    KMIP_STATE_PRE_ACTIVE            = 0x01,
    KMIP_STATE_ACTIVE                = 0x02,
    KMIP_STATE_DEACTIVATED           = 0x03,
    KMIP_STATE_COMPROMISED           = 0x04,
    KMIP_STATE_DESTROYED             = 0x05,
    KMIP_STATE_DESTROYED_COMPROMISED = 0x06
  };

  enum tag
  {
    KMIP_TAG_TAG                              = 0x000000,
    KMIP_TAG_TYPE                             = 0x000001,
    KMIP_TAG_DEFAULT                          = 0x420000,
    /* KMIP 1.0 */
    KMIP_TAG_ACTIVATION_DATE                  = 0x420001,
    KMIP_TAG_APPLICATION_DATA                 = 0x420002,
    KMIP_TAG_APPLICATION_NAMESPACE            = 0x420003,
    KMIP_TAG_APPLICATION_SPECIFIC_INFORMATION = 0x420004,
    KMIP_TAG_ASYNCHRONOUS_CORRELATION_VALUE   = 0x420006,
    KMIP_TAG_ASYNCHRONOUS_INDICATOR           = 0x420007,
    KMIP_TAG_ATTRIBUTE                        = 0x420008,
    KMIP_TAG_ATTRIBUTE_INDEX                  = 0x420009,
    KMIP_TAG_ATTRIBUTE_NAME                   = 0x42000A,
    KMIP_TAG_ATTRIBUTE_VALUE                  = 0x42000B,
    KMIP_TAG_AUTHENTICATION                   = 0x42000C,
    KMIP_TAG_BATCH_COUNT                      = 0x42000D,
    KMIP_TAG_BATCH_ERROR_CONTINUATION_OPTION  = 0x42000E,
    KMIP_TAG_BATCH_ITEM                       = 0x42000F,
    KMIP_TAG_BATCH_ORDER_OPTION               = 0x420010,
    KMIP_TAG_BLOCK_CIPHER_MODE                = 0x420011,
    KMIP_TAG_COMPROMISE_OCCURRANCE_DATE       = 0x420021,
    KMIP_TAG_CREDENTIAL                       = 0x420023,
    KMIP_TAG_CREDENTIAL_TYPE                  = 0x420024,
    KMIP_TAG_CREDENTIAL_VALUE                 = 0x420025,
    KMIP_TAG_CRYPTOGRAPHIC_ALGORITHM          = 0x420028,
    KMIP_TAG_CRYPTOGRAPHIC_LENGTH             = 0x42002A,
    KMIP_TAG_CRYPTOGRAPHIC_PARAMETERS         = 0x42002B,
    KMIP_TAG_CRYPTOGRAPHIC_USAGE_MASK         = 0x42002C,
    KMIP_TAG_DEACTIVATION_DATE                = 0x42002F,
    KMIP_TAG_ENCRYPTION_KEY_INFORMATION       = 0x420036,
    KMIP_TAG_HASHING_ALGORITHM                = 0x420038,
    KMIP_TAG_IV_COUNTER_NONCE                 = 0x42003D,
    KMIP_TAG_KEY                              = 0x42003F,
    KMIP_TAG_KEY_BLOCK                        = 0x420040,
    KMIP_TAG_KEY_COMPRESSION_TYPE             = 0x420041,
    KMIP_TAG_KEY_FORMAT_TYPE                  = 0x420042,
    KMIP_TAG_KEY_MATERIAL                     = 0x420043,
    KMIP_TAG_KEY_VALUE                        = 0x420045,
    KMIP_TAG_KEY_WRAPPING_DATA                = 0x420046,
    KMIP_TAG_KEY_WRAPPING_SPECIFICATION       = 0x420047,
    KMIP_TAG_MAC_SIGNATURE                    = 0x42004D,
    KMIP_TAG_MAC_SIGNATURE_KEY_INFORMATION    = 0x42004E,
    KMIP_TAG_MAXIMUM_ITEMS                    = 0x42004F,
    KMIP_TAG_MAXIMUM_RESPONSE_SIZE            = 0x420050,
    KMIP_TAG_NAME                             = 0x420053,
    KMIP_TAG_NAME_TYPE                        = 0x420054,
    KMIP_TAG_NAME_VALUE                       = 0x420055,
    KMIP_TAG_OBJECT_GROUP                     = 0x420056,
    KMIP_TAG_OBJECT_TYPE                      = 0x420057,
    KMIP_TAG_OPERATION                        = 0x42005C,
    KMIP_TAG_OPERATION_POLICY_NAME            = 0x42005D,
    KMIP_TAG_PADDING_METHOD                   = 0x42005F,
    KMIP_TAG_PRIVATE_KEY                      = 0x420064,
    KMIP_TAG_PROCESS_START_DATE               = 0x420067,
    KMIP_TAG_PROTECT_STOP_DATE                = 0x420068,
    KMIP_TAG_PROTOCOL_VERSION                 = 0x420069,
    KMIP_TAG_PROTOCOL_VERSION_MAJOR           = 0x42006A,
    KMIP_TAG_PROTOCOL_VERSION_MINOR           = 0x42006B,
    KMIP_TAG_PUBLIC_KEY                       = 0x42006D,
    KMIP_TAG_QUERY_FUNCTION                   = 0x420074,
    KMIP_TAG_REQUEST_HEADER                   = 0x420077,
    KMIP_TAG_REQUEST_MESSAGE                  = 0x420078,
    KMIP_TAG_REQUEST_PAYLOAD                  = 0x420079,
    KMIP_TAG_RESPONSE_HEADER                  = 0x42007A,
    KMIP_TAG_RESPONSE_MESSAGE                 = 0x42007B,
    KMIP_TAG_RESPONSE_PAYLOAD                 = 0x42007C,
    KMIP_TAG_RESULT_MESSAGE                   = 0x42007D,
    KMIP_TAG_RESULT_REASON                    = 0x42007E,
    KMIP_TAG_RESULT_STATUS                    = 0x42007F,
    KMIP_TAG_REVOKATION_MESSAGE               = 0x420080,
    KMIP_TAG_REVOCATION_REASON                = 0x420081,
    KMIP_TAG_REVOCATION_REASON_CODE           = 0x420082,
    KMIP_TAG_KEY_ROLE_TYPE                    = 0x420083,
    KMIP_TAG_SALT                             = 0x420084,
    KMIP_TAG_SECRET_DATA                      = 0x420085,
    KMIP_TAG_SECRET_DATA_TYPE                 = 0x420086,
    KMIP_TAG_SERVER_INFORMATION               = 0x420088,
    KMIP_TAG_STATE                            = 0x42008D,
    KMIP_TAG_STORAGE_STATUS_MASK              = 0x42008E,
    KMIP_TAG_SYMMETRIC_KEY                    = 0x42008F,
    KMIP_TAG_TEMPLATE_ATTRIBUTE               = 0x420091,
    KMIP_TAG_TIME_STAMP                       = 0x420092,
    KMIP_TAG_UNIQUE_BATCH_ITEM_ID             = 0x420093,
    KMIP_TAG_UNIQUE_IDENTIFIER                = 0x420094,
    KMIP_TAG_USERNAME                         = 0x420099,
    KMIP_TAG_VENDOR_IDENTIFICATION            = 0x42009D,
    KMIP_TAG_WRAPPING_METHOD                  = 0x42009E,
    KMIP_TAG_PASSWORD                         = 0x4200A1,
    /* KMIP 1.1 */
    KMIP_TAG_DEVICE_IDENTIFIER                = 0x4200A2,
    KMIP_TAG_ENCODING_OPTION                  = 0x4200A3,
    KMIP_TAG_MACHINE_IDENTIFIER               = 0x4200A9,
    KMIP_TAG_MEDIA_IDENTIFIER                 = 0x4200AA,
    KMIP_TAG_NETWORK_IDENTIFIER               = 0x4200AB,
    KMIP_TAG_OBJECT_GROUP_MEMBER              = 0x4200AC,
    KMIP_TAG_DIGITAL_SIGNATURE_ALGORITHM      = 0x4200AE,
    KMIP_TAG_DEVICE_SERIAL_NUMBER             = 0x4200B0,
    /* KMIP 1.2 */
    KMIP_TAG_RANDOM_IV                        = 0x4200C5,
    KMIP_TAG_ATTESTATION_TYPE                 = 0x4200C7,
    KMIP_TAG_NONCE                            = 0x4200C8,
    KMIP_TAG_NONCE_ID                         = 0x4200C9,
    KMIP_TAG_NONCE_VALUE                      = 0x4200CA,
    KMIP_TAG_ATTESTATION_MEASUREMENT          = 0x4200CB,
    KMIP_TAG_ATTESTATION_ASSERTION            = 0x4200CC,
    KMIP_TAG_IV_LENGTH                        = 0x4200CD,
    KMIP_TAG_TAG_LENGTH                       = 0x4200CE,
    KMIP_TAG_FIXED_FIELD_LENGTH               = 0x4200CF,
    KMIP_TAG_COUNTER_LENGTH                   = 0x4200D0,
    KMIP_TAG_INITIAL_COUNTER_VALUE            = 0x4200D1,
    KMIP_TAG_INVOCATION_FIELD_LENGTH          = 0x4200D2,
    KMIP_TAG_ATTESTATION_CAPABLE_INDICATOR    = 0x4200D3,
    KMIP_TAG_OFFSET_ITEMS                     = 0x4200D4,
    KMIP_TAG_LOCATED_ITEMS                    = 0x4200D5,
    /* KMIP 1.4 */
    KMIP_TAG_KEY_WRAP_TYPE                    = 0x4200F8,
    KMIP_TAG_SALT_LENGTH                      = 0x420100,
    KMIP_TAG_MASK_GENERATOR                   = 0x420101,
    KMIP_TAG_MASK_GENERATOR_HASHING_ALGORITHM = 0x420102,
    KMIP_TAG_P_SOURCE                         = 0x420103,
    KMIP_TAG_TRAILER_FIELD                    = 0x420104,
    KMIP_TAG_CLIENT_CORRELATION_VALUE         = 0x420105,
    KMIP_TAG_SERVER_CORRELATION_VALUE         = 0x420106,
    /* KMIP 2.0 */
    KMIP_TAG_ATTRIBUTES                       = 0x420125,
    KMIP_TAG_SERVER_NAME                      = 0x42012D,
    KMIP_TAG_SERVER_SERIAL_NUMBER             = 0x42012E,
    KMIP_TAG_SERVER_VERSION                   = 0x42012F,
    KMIP_TAG_SERVER_LOAD                      = 0x420130,
    KMIP_TAG_PRODUCT_NAME                     = 0x420131,
    KMIP_TAG_BUILD_LEVEL                      = 0x420132,
    KMIP_TAG_BUILD_DATE                       = 0x420133,
    KMIP_TAG_CLUSTER_INFO                     = 0x420134,
    KMIP_TAG_ALTERNATE_FAILOVER_ENDPOINTS     = 0x420135,
    KMIP_TAG_EPHEMERAL                        = 0x420154,
    KMIP_TAG_SERVER_HASHED_PASSWORD           = 0x420155,
    KMIP_TAG_PROTECTION_STORAGE_MASK          = 0x42015E,
    KMIP_TAG_PROTECTION_STORAGE_MASKS         = 0x42015F,
    KMIP_TAG_COMMON_PROTECTION_STORAGE_MASKS  = 0x420163,
    KMIP_TAG_PRIVATE_PROTECTION_STORAGE_MASKS = 0x420164,
    KMIP_TAG_PUBLIC_PROTECTION_STORAGE_MASKS  = 0x420165
  };

  enum type
  {
    /* KMIP 1.0 */
    KMIP_TYPE_STRUCTURE          = 0x01,
    KMIP_TYPE_INTEGER            = 0x02,
    KMIP_TYPE_LONG_INTEGER       = 0x03,
    KMIP_TYPE_BIG_INTEGER        = 0x04,
    KMIP_TYPE_ENUMERATION        = 0x05,
    KMIP_TYPE_BOOLEAN            = 0x06,
    KMIP_TYPE_TEXT_STRING        = 0x07,
    KMIP_TYPE_BYTE_STRING        = 0x08,
    KMIP_TYPE_DATE_TIME          = 0x09,
    KMIP_TYPE_INTERVAL           = 0x0A,
    /* KMIP 2.0 */
    KMIP_TYPE_DATE_TIME_EXTENDED = 0x0B
  };

  enum wrapping_method
  {
    /* KMIP 1.0 */
    KMIP_WRAP_ENCRYPT          = 0x01,
    KMIP_WRAP_MAC_SIGN         = 0x02,
    KMIP_WRAP_ENCRYPT_MAC_SIGN = 0x03,
    KMIP_WRAP_MAC_SIGN_ENCRYPT = 0x04,
    KMIP_WRAP_TR31             = 0x05
  };

  enum revocation_reason_type
  {
    /* KMIP 1.0 */
    UNSPECIFIED            = 0x01,
    KEY_COMPROMISE         = 0x02,
    CA_COMPROMISE          = 0x03,
    AFFILIATION_CHANGED    = 0x04,
    SUSPENDED              = 0x05,
    CESSATION_OF_OPERATION = 0x06,
    PRIVILEDGE_WITHDRAWN   = 0x07,
    REVOCATION_EXTENSIONS  = 0x80000000
  };

  enum secret_data_type
  {
    /* KMIP 1.0 */
    PASSWORD               = 0x01,
    SEED                   = 0x02,
    SECRET_DATA_EXTENSIONS = 0x80000000
  };


#ifdef __cplusplus
}

#endif
#endif // KMIP_KMIP_ENUMS_H
