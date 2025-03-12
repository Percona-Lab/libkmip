/* Copyright (c) 2018 The Johns Hopkins University/Applied Physics Laboratory
 * All Rights Reserved.
 *
 * This file is dual licensed under the terms of the Apache 2.0 License and
 * the BSD 3-Clause License. See the LICENSE file in the root of this
 * repository for more information.
 */

#ifndef KMIP_H
#define KMIP_H

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h> // we have FILE* vars

#include "libkmip_version.h"
#include "kmip_enums.h"
#include "kmip_structs.h"

#ifdef __cplusplus
extern "C"
{
#endif
  /*
  Macros
  */

#define ARRAY_LENGTH(A) (sizeof ((A)) / sizeof ((A)[0]))

#define BUFFER_BYTES_LEFT(A) ((A)->size - ((A)->index - (A)->buffer))

#define CHECK_BUFFER_FULL(A, B) CHECK_BUFFER_SIZE ((A), (B), KMIP_ERROR_BUFFER_FULL)

#define CHECK_BUFFER_SIZE(A, B, C)                                                                                     \
  do                                                                                                                   \
    {                                                                                                                  \
      if (BUFFER_BYTES_LEFT (A) < (B))                                                                                 \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return ((C));                                                                                                \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_RESULT(A, B)                                                                                             \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((B) != KMIP_OK)                                                                                              \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return ((B));                                                                                                \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define HANDLE_FAILURE(A, B)                                                                                           \
  do                                                                                                                   \
    {                                                                                                                  \
      kmip_push_error_frame ((A), __func__, __LINE__);                                                                 \
      return ((B));                                                                                                    \
    }                                                                                                                  \
  while (0)

#define TAG_TYPE(A, B) (((A) << 8) | (uint8)(B))

#define CHECK_TAG_TYPE(A, B, C, D)                                                                                     \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((int32)((B) >> 8) != (int32)(C))                                                                             \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_TAG_MISMATCH);                                                                                  \
        }                                                                                                              \
      else if ((int32)((B) & 0x000000FF) != (int32)(D))                                                                \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_TYPE_MISMATCH);                                                                                 \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_LENGTH(A, B, C)                                                                                          \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((B) != (C))                                                                                                  \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_LENGTH_MISMATCH);                                                                               \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_PADDING(A, B)                                                                                            \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((B) != 0)                                                                                                    \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_PADDING_MISMATCH);                                                                              \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_BOOLEAN(A, B)                                                                                            \
  do                                                                                                                   \
    {                                                                                                                  \
      if (((B) != KMIP_TRUE) && ((B) != KMIP_FALSE))                                                                   \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_BOOLEAN_MISMATCH);                                                                              \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_ENUM(A, B, C)                                                                                            \
  do                                                                                                                   \
    {                                                                                                                  \
      int result = kmip_check_enum_value ((A)->version, (B), (C));                                                     \
      if (result != KMIP_OK)                                                                                           \
        {                                                                                                              \
          kmip_set_enum_error_message ((A), (B), (C), result);                                                         \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (result);                                                                                             \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_NEW_MEMORY(A, B, C, D)                                                                                   \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((B) == NULL)                                                                                                 \
        {                                                                                                              \
          kmip_set_alloc_error_message ((A), (C), (D));                                                                \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_MEMORY_ALLOC_FAILED);                                                                           \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define HANDLE_FAILED_ALLOC(A, B, C)                                                                                   \
  do                                                                                                                   \
    {                                                                                                                  \
      kmip_set_alloc_error_message ((A), (B), (C));                                                                    \
      kmip_push_error_frame ((A), __func__, __LINE__);                                                                 \
      return (KMIP_MEMORY_ALLOC_FAILED);                                                                               \
    }                                                                                                                  \
  while (0)

#define CHECK_ENCODE_ARGS(A, B)                                                                                        \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((A) == NULL)                                                                                                 \
        {                                                                                                              \
          return (KMIP_ARG_INVALID);                                                                                   \
        }                                                                                                              \
      if ((B) == NULL)                                                                                                 \
        {                                                                                                              \
          return (KMIP_OK);                                                                                            \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_DECODE_ARGS(A, B)                                                                                        \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((A) == NULL || (B) == NULL)                                                                                  \
        {                                                                                                              \
          return (KMIP_ARG_INVALID);                                                                                   \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CHECK_KMIP_VERSION(A, B)                                                                                       \
  do                                                                                                                   \
    {                                                                                                                  \
      if ((A)->version < (B))                                                                                          \
        {                                                                                                              \
          kmip_push_error_frame ((A), __func__, __LINE__);                                                             \
          return (KMIP_INVALID_FOR_VERSION);                                                                           \
        }                                                                                                              \
    }                                                                                                                  \
  while (0)

#define CALCULATE_PADDING(A) ((8 - ((A) % 8)) % 8)

  /*
  Miscellaneous Utilities
  */

  size_t          kmip_strnlen_s (const char *, size_t);
  LinkedListItem *kmip_linked_list_pop (LinkedList *);
  void            kmip_linked_list_push (LinkedList *, LinkedListItem *);
  void            kmip_linked_list_enqueue (LinkedList *, LinkedListItem *);

  /*
  Memory Handlers
  */

  void *kmip_calloc (void *, size_t, size_t);
  void *kmip_realloc (void *, void *, size_t);
  void  kmip_free (void *, void *);
  void *kmip_memcpy (void *, void *, const void *, size_t);

  /*
  Enumeration Utilities
  */

  int kmip_get_enum_string_index (enum tag);
  int kmip_check_enum_value (enum kmip_version, enum tag, int);

  /*
  Context Utilities
  */

  void   kmip_clear_errors (KMIP *);
  void   kmip_init (KMIP *, void *, size_t, enum kmip_version);
  void   kmip_init_error_message (KMIP *);
  int    kmip_add_credential (KMIP *, Credential *);
  void   kmip_remove_credentials (KMIP *);
  void   kmip_reset (KMIP *);
  void   kmip_rewind (KMIP *);
  void   kmip_set_buffer (KMIP *, void *, size_t);
  void   kmip_destroy (KMIP *);
  void   kmip_push_error_frame (KMIP *, const char *, const int);
  void   kmip_set_enum_error_message (KMIP *, enum tag, int, int);
  void   kmip_set_alloc_error_message (KMIP *, size_t, const char *);
  void   kmip_set_error_message (KMIP *, const char *);
  int    kmip_is_tag_next (const KMIP *, enum tag);
  int    kmip_is_tag_type_next (const KMIP *, enum tag, enum type);
  size_t kmip_get_num_items_next (KMIP *, enum tag);
  uint32 kmip_peek_tag (KMIP *);
  int    kmip_is_attribute_tag (uint32);

  /*
  Initialization Functions
  */

  void kmip_init_application_specific_information (ApplicationSpecificInformation *);
  void kmip_init_protocol_version (ProtocolVersion *, enum kmip_version);
  void kmip_init_attribute (Attribute *);
  void kmip_init_cryptographic_parameters (CryptographicParameters *);
  void kmip_init_key_block (KeyBlock *);
  void kmip_init_request_header (RequestHeader *);
  void kmip_init_response_header (ResponseHeader *);
  void kmip_init_request_batch_item (RequestBatchItem *);

  /*
  Printing Functions
  */

  void kmip_print_buffer (FILE *, void *, int);
  void kmip_print_stack_trace (FILE *, KMIP *);
  void kmip_print_error_string (FILE *, int);
  void kmip_print_batch_error_continuation_option (FILE *, enum batch_error_continuation_option);
  void kmip_print_operation_enum (FILE *, enum operation);
  void kmip_print_result_status_enum (FILE *, enum result_status);
  void kmip_print_result_reason_enum (FILE *, enum result_reason);
  void kmip_print_object_type_enum (FILE *, enum object_type);
  void kmip_print_key_format_type_enum (FILE *, enum key_format_type);
  void kmip_print_key_compression_type_enum (FILE *, enum key_compression_type);
  void kmip_print_cryptographic_algorithm_enum (FILE *, enum cryptographic_algorithm);
  void kmip_print_name_type_enum (FILE *, enum name_type);
  void kmip_print_attribute_type_enum (FILE *, enum attribute_type);
  void kmip_print_state_enum (FILE *, enum state);
  void kmip_print_block_cipher_mode_enum (FILE *, enum block_cipher_mode);
  void kmip_print_padding_method_enum (FILE *, enum padding_method);
  void kmip_print_hashing_algorithm_enum (FILE *, enum hashing_algorithm);
  void kmip_print_key_role_type_enum (FILE *, enum key_role_type);
  void kmip_print_digital_signature_algorithm_enum (FILE *, enum digital_signature_algorithm);
  void kmip_print_mask_generator_enum (FILE *, enum mask_generator);
  void kmip_print_wrapping_method_enum (FILE *, enum wrapping_method);
  void kmip_print_encoding_option_enum (FILE *, enum encoding_option);
  void kmip_print_key_wrap_type_enum (FILE *, enum key_wrap_type);
  void kmip_print_credential_type_enum (FILE *, enum credential_type);
  void kmip_print_cryptographic_usage_mask_enums (FILE *, int, int32);
  void kmip_print_integer (FILE *, int32);
  void kmip_print_bool (FILE *, int32);
  void kmip_print_text_string (FILE *, int, const char *, TextString *);
  void kmip_print_byte_string (FILE *, int, const char *, ByteString *);
  void kmip_print_date_time (FILE *, int64);
  void kmip_print_protocol_version (FILE *, int, ProtocolVersion *);
  void kmip_print_name (FILE *, int, Name *);
  void kmip_print_nonce (FILE *, int, Nonce *);
  void kmip_print_protection_storage_masks_enum (FILE *, int, int32);
  void kmip_print_protection_storage_masks (FILE *, int, ProtectionStorageMasks *);
  void kmip_print_application_specific_information (FILE *, int, ApplicationSpecificInformation *);
  void kmip_print_cryptographic_parameters (FILE *, int, CryptographicParameters *);
  void kmip_print_encryption_key_information (FILE *, int, EncryptionKeyInformation *);
  void kmip_print_mac_signature_key_information (FILE *, int, MACSignatureKeyInformation *);
  void kmip_print_key_wrapping_data (FILE *, int, KeyWrappingData *);
  void kmip_print_attribute_value (FILE *, int, enum attribute_type, void *);
  void kmip_print_attribute (FILE *, int, Attribute *);
  void kmip_print_attributes (FILE *, int, Attributes *);
  void kmip_print_key_material (FILE *, int, enum key_format_type, void *);
  void kmip_print_key_value (FILE *, int, enum type, enum key_format_type, void *);
  void kmip_print_key_block (FILE *, int, KeyBlock *);
  void kmip_print_symmetric_key (FILE *, int, SymmetricKey *);
  void kmip_print_object (FILE *, int, enum object_type, void *);
  void kmip_print_key_wrapping_specification (FILE *, int, KeyWrappingSpecification *);
  void kmip_print_template_attribute (FILE *, int, TemplateAttribute *);
  void kmip_print_create_request_payload (FILE *, int, CreateRequestPayload *);
  void kmip_print_create_response_payload (FILE *, int, CreateResponsePayload *);
  void kmip_print_get_request_payload (FILE *, int, GetRequestPayload *);
  void kmip_print_get_response_payload (FILE *, int, GetResponsePayload *);
  void kmip_print_destroy_request_payload (FILE *, int, DestroyRequestPayload *);
  void kmip_print_destroy_response_payload (FILE *, int, DestroyResponsePayload *);
  void kmip_print_request_payload (FILE *, int, enum operation, void *);
  void kmip_print_response_payload (FILE *, int, enum operation, void *);
  void kmip_print_username_password_credential (FILE *, int, UsernamePasswordCredential *);
  void kmip_print_device_credential (FILE *, int, DeviceCredential *);
  void kmip_print_attestation_credential (FILE *, int, AttestationCredential *);
  void kmip_print_credential_value (FILE *, int, enum credential_type, void *);
  void kmip_print_credential (FILE *, int, Credential *);
  void kmip_print_authentication (FILE *, int, Authentication *);
  void kmip_print_request_batch_item (FILE *, int, RequestBatchItem *);
  void kmip_print_response_batch_item (FILE *, int, ResponseBatchItem *);
  void kmip_print_request_header (FILE *, int, RequestHeader *);
  void kmip_print_response_header (FILE *, int, ResponseHeader *);
  void kmip_print_request_message (FILE *, RequestMessage *);
  void kmip_print_response_message (FILE *, ResponseMessage *);
  void kmip_print_query_function_enum (FILE *, int, enum query_function);
  void kmip_print_query_functions (FILE *, int, Functions *);
  void kmip_print_operations (FILE *, int, Operations *);
  void kmip_print_object_types (FILE *, int, ObjectTypes *);
  void kmip_print_query_request_payload (FILE *, int, QueryRequestPayload *);
  void kmip_print_query_response_payload (FILE *, int, QueryResponsePayload *);
  void kmip_print_server_information (FILE *, int, ServerInformation *);

  /*
  Freeing Functions
  */

  void kmip_free_buffer (KMIP *, void *, size_t);
  void kmip_free_text_string (KMIP *, TextString *);
  void kmip_free_byte_string (KMIP *, ByteString *);
  void kmip_free_name (KMIP *, Name *);
  void kmip_free_attribute (KMIP *, Attribute *);
  void kmip_free_attributes (KMIP *, Attributes *);
  void kmip_free_template_attribute (KMIP *, TemplateAttribute *);
  void kmip_free_transparent_symmetric_key (KMIP *, TransparentSymmetricKey *);
  void kmip_free_key_material (KMIP *, enum key_format_type, void **);
  void kmip_free_key_value (KMIP *, enum key_format_type, KeyValue *);
  void kmip_free_protection_storage_masks (KMIP *, ProtectionStorageMasks *);
  void kmip_free_application_specific_information (KMIP *, ApplicationSpecificInformation *);
  void kmip_free_cryptographic_parameters (KMIP *, CryptographicParameters *);
  void kmip_free_encryption_key_information (KMIP *, EncryptionKeyInformation *);
  void kmip_free_mac_signature_key_information (KMIP *, MACSignatureKeyInformation *);
  void kmip_free_key_wrapping_data (KMIP *, KeyWrappingData *);
  void kmip_free_key_block (KMIP *, KeyBlock *);
  void kmip_free_symmetric_key (KMIP *, SymmetricKey *);
  void kmip_free_public_key (KMIP *, PublicKey *);
  void kmip_free_private_key (KMIP *, PrivateKey *);
  void kmip_free_key_wrapping_specification (KMIP *, KeyWrappingSpecification *);
  void kmip_free_create_request_payload (KMIP *, CreateRequestPayload *);
  void kmip_free_create_response_payload (KMIP *, CreateResponsePayload *);
  void kmip_free_get_request_payload (KMIP *, GetRequestPayload *);
  void kmip_free_get_response_payload (KMIP *, GetResponsePayload *);
  void kmip_free_activate_request_payload (KMIP *, ActivateRequestPayload *);
  void kmip_free_activate_response_payload (KMIP *, ActivateResponsePayload *);
  void kmip_free_destroy_request_payload (KMIP *, DestroyRequestPayload *);
  void kmip_free_destroy_response_payload (KMIP *, DestroyResponsePayload *);
  void kmip_free_request_batch_item (KMIP *, RequestBatchItem *);
  void kmip_free_response_batch_item (KMIP *, ResponseBatchItem *);
  void kmip_free_nonce (KMIP *, Nonce *);
  void kmip_free_username_password_credential (KMIP *, UsernamePasswordCredential *);
  void kmip_free_device_credential (KMIP *, DeviceCredential *);
  void kmip_free_attestation_credential (KMIP *, AttestationCredential *);
  void kmip_free_credential_value (KMIP *, enum credential_type, void **);
  void kmip_free_credential (KMIP *, Credential *);
  void kmip_free_authentication (KMIP *, Authentication *);
  void kmip_free_request_header (KMIP *, RequestHeader *);
  void kmip_free_response_header (KMIP *, ResponseHeader *);
  void kmip_free_request_message (KMIP *, RequestMessage *);
  void kmip_free_response_message (KMIP *, ResponseMessage *);
  void kmip_free_query_functions (KMIP *ctx, Functions *);
  void kmip_free_query_request_payload (KMIP *, QueryRequestPayload *);
  void kmip_free_query_response_payload (KMIP *, QueryResponsePayload *);
  void kmip_free_operations (KMIP *ctx, Operations *value);
  void kmip_free_objects (KMIP *ctx, ObjectTypes *value);
  void kmip_free_server_information (KMIP *ctx, ServerInformation *value);
  void kmip_free_revoke_request_payload (KMIP *, RevokeRequestPayload *);
  void kmip_free_revoke_response_payload (KMIP *, RevokeResponsePayload *);

  /*
  Copying Functions
  */

  int32                   *kmip_deep_copy_int32 (KMIP *, const int32 *);
  int64                   *kmip_deep_copy_int64 (KMIP *, const int64 *);
  TextString              *kmip_deep_copy_text_string (KMIP *, const TextString *);
  ByteString              *kmip_deep_copy_byte_string (KMIP *, const ByteString *);
  Name                    *kmip_deep_copy_name (KMIP *, const Name *);
  CryptographicParameters *kmip_deep_copy_cryptographic_parameters (KMIP *, const CryptographicParameters *);
  ApplicationSpecificInformation            *
  kmip_deep_copy_application_specific_information (KMIP *, const ApplicationSpecificInformation *);
  Attribute *kmip_deep_copy_attribute (KMIP *, const Attribute *);
  char      *kmip_copy_textstring (char *dest, TextString *src, size_t size);
  void       kmip_copy_objects (int objs[], size_t *objs_size, ObjectTypes *value, unsigned max_objs);
  void       kmip_copy_operations (int ops[], size_t *ops_size, Operations *value, unsigned max_ops);
  void       kmip_copy_query_result (QueryResponse *query_result, QueryResponsePayload *pld);

  /*
  Comparison Functions
  */

  int kmip_compare_text_string (const TextString *, const TextString *);
  int kmip_compare_byte_string (const ByteString *, const ByteString *);
  int kmip_compare_name (const Name *, const Name *);
  int kmip_compare_attribute (const Attribute *, const Attribute *);
  int kmip_compare_attributes (const Attributes *, const Attributes *);
  int kmip_compare_template_attribute (const TemplateAttribute *, const TemplateAttribute *);
  int kmip_compare_protocol_version (const ProtocolVersion *, const ProtocolVersion *);
  int kmip_compare_transparent_symmetric_key (const TransparentSymmetricKey *, const TransparentSymmetricKey *);
  int kmip_compare_key_material (enum key_format_type, void **, void **);
  int kmip_compare_key_value (enum key_format_type, const KeyValue *, const KeyValue *);
  int kmip_compare_protection_storage_masks (const ProtectionStorageMasks *, const ProtectionStorageMasks *);
  int kmip_compare_application_specific_information (const ApplicationSpecificInformation *,
                                                     const ApplicationSpecificInformation *);
  int kmip_compare_cryptographic_parameters (const CryptographicParameters *, const CryptographicParameters *);
  int kmip_compare_encryption_key_information (const EncryptionKeyInformation *, const EncryptionKeyInformation *);
  int kmip_compare_mac_signature_key_information (const MACSignatureKeyInformation *,
                                                  const MACSignatureKeyInformation *);
  int kmip_compare_key_wrapping_data (const KeyWrappingData *, const KeyWrappingData *);
  int kmip_compare_key_block (const KeyBlock *, const KeyBlock *);
  int kmip_compare_symmetric_key (const SymmetricKey *, const SymmetricKey *);
  int kmip_compare_public_key (const PublicKey *, const PublicKey *);
  int kmip_compare_private_key (const PrivateKey *, const PrivateKey *);
  int kmip_compare_key_wrapping_specification (const KeyWrappingSpecification *, const KeyWrappingSpecification *);
  int kmip_compare_create_request_payload (const CreateRequestPayload *, const CreateRequestPayload *);
  int kmip_compare_create_response_payload (const CreateResponsePayload *, const CreateResponsePayload *);
  int kmip_compare_get_request_payload (const GetRequestPayload *, const GetRequestPayload *);
  int kmip_compare_get_response_payload (const GetResponsePayload *, const GetResponsePayload *);
  int kmip_compare_destroy_request_payload (const DestroyRequestPayload *, const DestroyRequestPayload *);
  int kmip_compare_destroy_response_payload (const DestroyResponsePayload *, const DestroyResponsePayload *);
  int kmip_compare_request_batch_item (const RequestBatchItem *, const RequestBatchItem *);
  int kmip_compare_response_batch_item (const ResponseBatchItem *, const ResponseBatchItem *);
  int kmip_compare_nonce (const Nonce *, const Nonce *);
  int kmip_compare_username_password_credential (const UsernamePasswordCredential *,
                                                 const UsernamePasswordCredential *);
  int kmip_compare_device_credential (const DeviceCredential *, const DeviceCredential *);
  int kmip_compare_attestation_credential (const AttestationCredential *, const AttestationCredential *);
  int kmip_compare_credential_value (enum credential_type, void **, void **);
  int kmip_compare_credential (const Credential *, const Credential *);
  int kmip_compare_authentication (const Authentication *, const Authentication *);
  int kmip_compare_request_header (const RequestHeader *, const RequestHeader *);
  int kmip_compare_response_header (const ResponseHeader *, const ResponseHeader *);
  int kmip_compare_request_message (const RequestMessage *, const RequestMessage *);
  int kmip_compare_response_message (const ResponseMessage *, const ResponseMessage *);
  int kmip_compare_query_functions (const Functions *, const Functions *);
  int kmip_compare_operations (const Operations *, const Operations *);
  int kmip_compare_objects (const ObjectTypes *, const ObjectTypes *);
  int kmip_compare_server_information (const ServerInformation *a, const ServerInformation *b);
  int kmip_compare_alternative_endpoints (const AltEndpoints *a, const AltEndpoints *b);
  int kmip_compare_query_request_payload (const QueryRequestPayload *, const QueryRequestPayload *);
  int kmip_compare_query_response_payload (const QueryResponsePayload *, const QueryResponsePayload *);

  /*
  Encoding Functions
  */

  int kmip_encode_int8_be (KMIP *, int8);
  int kmip_encode_int32_be (KMIP *, int32);
  int kmip_encode_int64_be (KMIP *, int64);
  int kmip_encode_integer (KMIP *, enum tag, int32);
  int kmip_encode_long (KMIP *, enum tag, int64);
  int kmip_encode_enum (KMIP *, enum tag, int32);
  int kmip_encode_bool (KMIP *, enum tag, bool32);
  int kmip_encode_text_string (KMIP *, enum tag, const TextString *);
  int kmip_encode_byte_string (KMIP *, enum tag, const ByteString *);
  int kmip_encode_date_time (KMIP *, enum tag, int64);
  int kmip_encode_interval (KMIP *, enum tag, uint32);
  int kmip_encode_length (KMIP *, intptr);
  int kmip_encode_name (KMIP *, const Name *);
  int kmip_encode_attribute_name (KMIP *, enum attribute_type);
  int kmip_encode_attribute_v1 (KMIP *, const Attribute *);
  int kmip_encode_attribute_v2 (KMIP *, const Attribute *);
  int kmip_encode_attribute (KMIP *, const Attribute *);
  int kmip_encode_attributes (KMIP *, const Attributes *);
  int kmip_encode_template_attribute (KMIP *, const TemplateAttribute *);
  int kmip_encode_protocol_version (KMIP *, const ProtocolVersion *);
  int kmip_encode_protection_storage_masks (KMIP *, const ProtectionStorageMasks *);
  int kmip_encode_application_specific_information (KMIP *, const ApplicationSpecificInformation *);
  int kmip_encode_cryptographic_parameters (KMIP *, const CryptographicParameters *);
  int kmip_encode_encryption_key_information (KMIP *, const EncryptionKeyInformation *);
  int kmip_encode_mac_signature_key_information (KMIP *, const MACSignatureKeyInformation *);
  int kmip_encode_key_wrapping_data (KMIP *, const KeyWrappingData *);
  int kmip_encode_transparent_symmetric_key (KMIP *, const TransparentSymmetricKey *);
  int kmip_encode_key_material (KMIP *, enum key_format_type, const void *);
  int kmip_encode_key_value (KMIP *, enum key_format_type, const KeyValue *);
  int kmip_encode_key_block (KMIP *, const KeyBlock *);
  int kmip_encode_symmetric_key (KMIP *, const SymmetricKey *);
  int kmip_encode_public_key (KMIP *, const PublicKey *);
  int kmip_encode_private_key (KMIP *, const PrivateKey *);
  int kmip_encode_key_wrapping_specification (KMIP *, const KeyWrappingSpecification *);
  int kmip_encode_create_request_payload (KMIP *, const CreateRequestPayload *);
  int kmip_encode_create_response_payload (KMIP *, const CreateResponsePayload *);
  int kmip_encode_get_request_payload (KMIP *, const GetRequestPayload *);
  int kmip_encode_get_response_payload (KMIP *, const GetResponsePayload *);
  int kmip_encode_activate_request_payload (KMIP *, const ActivateRequestPayload *);
  int kmip_encode_activate_response_payload (KMIP *, const ActivateResponsePayload *);
  int kmip_encode_destroy_request_payload (KMIP *, const DestroyRequestPayload *);
  int kmip_encode_destroy_response_payload (KMIP *, const DestroyResponsePayload *);
  int kmip_encode_nonce (KMIP *, const Nonce *);
  int kmip_encode_username_password_credential (KMIP *, const UsernamePasswordCredential *);
  int kmip_encode_device_credential (KMIP *, const DeviceCredential *);
  int kmip_encode_attestation_credential (KMIP *, const AttestationCredential *);
  int kmip_encode_credential_value (KMIP *, enum credential_type, void *);
  int kmip_encode_credential (KMIP *, const Credential *);
  int kmip_encode_authentication (KMIP *, const Authentication *);
  int kmip_encode_request_header (KMIP *, const RequestHeader *);
  int kmip_encode_response_header (KMIP *, const ResponseHeader *);
  int kmip_encode_request_batch_item (KMIP *, const RequestBatchItem *);
  int kmip_encode_response_batch_item (KMIP *, const ResponseBatchItem *);
  int kmip_encode_request_message (KMIP *, const RequestMessage *);
  int kmip_encode_response_message (KMIP *, const ResponseMessage *);
  int kmip_encode_query_functions (KMIP *ctx, const Functions *);
  int kmip_encode_query_request_payload (KMIP *, const QueryRequestPayload *);
  int kmip_encode_query_response_payload (KMIP *, const QueryResponsePayload *);
  int kmip_encode_revoke_request_payload (KMIP *, const RevokeRequestPayload *);
  int kmip_encode_revoke_response_payload (KMIP *, const RevokeResponsePayload *);
  int kmip_encode_get_attribute_list_request_payload (KMIP *ctx, const GetAttributeListRequestPayload *value);
  /*
  Decoding Functions
  */

  int kmip_decode_int8_be (KMIP *, void *);
  int kmip_decode_int32_be (KMIP *, void *);
  int kmip_decode_int64_be (KMIP *, void *);
  int kmip_decode_integer (KMIP *, enum tag, int32 *);
  int kmip_decode_long (KMIP *, enum tag, int64 *);
  int kmip_decode_length (KMIP *ctx, uint32 *);
  int kmip_decode_enum (KMIP *, enum tag, void *);
  int kmip_decode_bool (KMIP *, enum tag, bool32 *);
  int kmip_decode_text_string (KMIP *, enum tag, TextString *);
  int kmip_decode_byte_string (KMIP *, enum tag, ByteString *);
  int kmip_decode_date_time (KMIP *, enum tag, int64 *);
  int kmip_decode_interval (KMIP *, enum tag, uint32 *);
  int kmip_decode_name (KMIP *, Name *);
  int kmip_decode_attribute_name (KMIP *, enum attribute_type *);
  int kmip_decode_attribute_v1 (KMIP *, Attribute *);
  int kmip_decode_attribute_v2 (KMIP *, Attribute *);
  int kmip_decode_attribute (KMIP *, Attribute *);
  int kmip_decode_attributes (KMIP *, Attributes *);
  int kmip_decode_template_attribute (KMIP *, TemplateAttribute *);
  int kmip_decode_protocol_version (KMIP *, ProtocolVersion *);
  int kmip_decode_transparent_symmetric_key (KMIP *, TransparentSymmetricKey *);
  int kmip_decode_key_material (KMIP *, enum key_format_type, void **);
  int kmip_decode_key_value (KMIP *, enum key_format_type, KeyValue *);
  int kmip_decode_protection_storage_masks (KMIP *, ProtectionStorageMasks *);
  int kmip_decode_application_specific_information (KMIP *, ApplicationSpecificInformation *);
  int kmip_decode_cryptographic_parameters (KMIP *, CryptographicParameters *);
  int kmip_decode_encryption_key_information (KMIP *, EncryptionKeyInformation *);
  int kmip_decode_mac_signature_key_information (KMIP *, MACSignatureKeyInformation *);
  int kmip_decode_key_wrapping_data (KMIP *, KeyWrappingData *);
  int kmip_decode_key_block (KMIP *, KeyBlock *);
  int kmip_decode_symmetric_key (KMIP *, SymmetricKey *);
  int kmip_decode_public_key (KMIP *, PublicKey *);
  int kmip_decode_private_key (KMIP *, PrivateKey *);
  int kmip_decode_key_wrapping_specification (KMIP *, KeyWrappingSpecification *);
  int kmip_decode_create_request_payload (KMIP *, CreateRequestPayload *);
  int kmip_decode_create_response_payload (KMIP *, CreateResponsePayload *);
  int kmip_decode_get_request_payload (KMIP *, GetRequestPayload *);
  int kmip_decode_get_response_payload (KMIP *, GetResponsePayload *);
  int kmip_decode_activate_request_payload (KMIP *, ActivateRequestPayload *);
  int kmip_decode_activate_response_payload (KMIP *, ActivateResponsePayload *);
  int kmip_decode_destroy_request_payload (KMIP *, DestroyRequestPayload *);
  int kmip_decode_destroy_response_payload (KMIP *, DestroyResponsePayload *);
  int kmip_decode_request_batch_item (KMIP *, RequestBatchItem *);
  int kmip_decode_response_batch_item (KMIP *, ResponseBatchItem *);
  int kmip_decode_nonce (KMIP *, Nonce *);
  int kmip_decode_username_password_credential (KMIP *, UsernamePasswordCredential *);
  int kmip_decode_device_credential (KMIP *, DeviceCredential *);
  int kmip_decode_attestation_credential (KMIP *, AttestationCredential *);
  int kmip_decode_credential_value (KMIP *, enum credential_type, void **);
  int kmip_decode_credential (KMIP *, Credential *);
  int kmip_decode_authentication (KMIP *, Authentication *);
  int kmip_decode_request_header (KMIP *, RequestHeader *);
  int kmip_decode_response_header (KMIP *, ResponseHeader *);
  int kmip_decode_request_message (KMIP *, RequestMessage *);
  int kmip_decode_response_message (KMIP *, ResponseMessage *);
  int kmip_decode_query_functions (KMIP *ctx, Functions *);
  int kmip_decode_operations (KMIP *, Operations *);
  int kmip_decode_object_types (KMIP *, ObjectTypes *);
  int kmip_decode_query_request_payload (KMIP *, QueryRequestPayload *);
  int kmip_decode_query_response_payload (KMIP *, QueryResponsePayload *);
  int kmip_decode_server_information (KMIP *ctx, ServerInformation *);
  int kmip_decode_revoke_request_payload (KMIP *, RevokeRequestPayload *);
  int kmip_decode_revoke_response_payload (KMIP *, RevokeResponsePayload *);
  int kmip_decode_get_attribute_list_response_payload (KMIP *ctx, GetAttributeListResponsePayload *value);
#ifdef __cplusplus
}
#endif

#endif /* KMIP_H */
