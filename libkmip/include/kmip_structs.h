//
// Created by al on 29.09.25.
//

#ifndef KMIP_KMIP_STRUCTS_H
#define KMIP_KMIP_STRUCTS_H
#ifdef __cplusplus
extern "C"
{
#endif

  /*
  Structures
  */

  typedef struct linked_list_item
  {
    struct linked_list_item *next;
    struct linked_list_item *prev;

    void *data;
  } LinkedListItem;

  typedef struct linked_list
  {
    LinkedListItem *head;
    LinkedListItem *tail;

    size_t size;
  } LinkedList;

  typedef struct text_string
  {
    char  *value;
    size_t size;
  } TextString;

  typedef struct byte_string
  {
    uint8 *value;
    size_t size;
  } ByteString;

  typedef struct error_frame
  {
    char function[100];
    int  line;
  } ErrorFrame;

  typedef struct kmip
  {
    /* Encoding buffer */
    uint8 *buffer;
    uint8 *index;
    size_t size;

    /* KMIP message settings */
    enum kmip_version version;
    int               max_message_size;
    LinkedList       *credential_list;

    /* Error handling information */
    char               *error_message;
    size_t              error_message_size;
    /* TODO (ph) Switch the following to a LinkedList. */
    ErrorFrame          errors[20];
    size_t              error_frame_count;
    struct error_frame *frame_index;

    /* Memory management function pointers */
    void *(*calloc_func) (void *state, size_t num, size_t size);
    void *(*realloc_func) (void *state, void *ptr, size_t size);
    void (*free_func) (void *state, void *ptr);
    void *(*memcpy_func) (void *state, void *destination, const void *source, size_t size);
    void *(*memset_func) (void *ptr, int value, size_t size);
    void *state;
  } KMIP;

  typedef struct application_specific_information
  {
    TextString *application_namespace;
    TextString *application_data;
  } ApplicationSpecificInformation;

  typedef struct attribute
  {
    enum attribute_type type;
    int32               index;
    void               *value;
  } Attribute;

  typedef struct attributes
  {
    LinkedList *attribute_list;
  } Attributes;

  typedef struct name
  {
    struct text_string *value;
    enum name_type      type;
  } Name;

  typedef struct template_attribute
  {
    /* TODO (ph) Change these to linked lists */
    Name      *names;
    size_t     name_count;
    Attribute *attributes;
    size_t     attribute_count;
  } TemplateAttribute;

  typedef struct protocol_version
  {
    int32 major;
    int32 minor;
  } ProtocolVersion;

  typedef struct protection_storage_masks
  {
    /* KMIP 2.0 */
    LinkedList *masks;
  } ProtectionStorageMasks;

  typedef struct cryptographic_parameters
  {
    /* KMIP 1.0 */
    enum block_cipher_mode           block_cipher_mode;
    enum padding_method              padding_method;
    enum hashing_algorithm           hashing_algorithm;
    enum key_role_type               key_role_type;
    /* KMIP 1.2 */
    enum digital_signature_algorithm digital_signature_algorithm;
    enum cryptographic_algorithm     cryptographic_algorithm;
    bool32                           random_iv;
    int32                            iv_length;
    int32                            tag_length;
    int32                            fixed_field_length;
    int32                            invocation_field_length;
    int32                            counter_length;
    int32                            initial_counter_value;
    /* KMIP 1.4 */
    int32                            salt_length;
    enum mask_generator              mask_generator;
    enum hashing_algorithm           mask_generator_hashing_algorithm;
    ByteString                      *p_source;
    int32                            trailer_field;
  } CryptographicParameters;

  typedef struct encryption_key_information
  {
    TextString              *unique_identifier;
    CryptographicParameters *cryptographic_parameters;
  } EncryptionKeyInformation;

  typedef struct mac_signature_key_information
  {
    TextString              *unique_identifier;
    CryptographicParameters *cryptographic_parameters;
  } MACSignatureKeyInformation;

  typedef struct key_wrapping_data
  {
    /* KMIP 1.0 */
    enum wrapping_method        wrapping_method;
    EncryptionKeyInformation   *encryption_key_info;
    MACSignatureKeyInformation *mac_signature_key_info;
    ByteString                 *mac_signature;
    ByteString                 *iv_counter_nonce;
    /* KMIP 1.1 */
    enum encoding_option        encoding_option;
  } KeyWrappingData;

  typedef struct transparent_symmetric_key
  {
    ByteString *key;
  } TransparentSymmetricKey;

  typedef struct key_value
  {
    void      *key_material;
    /* TODO (ph) Change this to a linked list */
    Attribute *attributes;
    size_t     attribute_count;
  } KeyValue;

  typedef struct key_block
  {
    enum key_format_type         key_format_type;
    enum key_compression_type    key_compression_type;
    void                        *key_value;
    enum type                    key_value_type;
    enum cryptographic_algorithm cryptographic_algorithm;
    int32                        cryptographic_length;
    KeyWrappingData             *key_wrapping_data;
  } KeyBlock;

  typedef struct symmetric_key
  {
    KeyBlock *key_block;
  } SymmetricKey;

  typedef struct public_key
  {
    KeyBlock *key_block;
  } PublicKey;

  typedef struct private_key
  {
    KeyBlock *key_block;
  } PrivateKey;

  typedef struct key_wrapping_specification
  {
    /* KMIP 1.0 */
    enum wrapping_method        wrapping_method;
    EncryptionKeyInformation   *encryption_key_info;
    MACSignatureKeyInformation *mac_signature_key_info;
    /* TODO (ph) Change this to a linked list */
    TextString                 *attribute_names;
    size_t                      attribute_name_count;
    /* KMIP 1.1 */
    enum encoding_option        encoding_option;
  } KeyWrappingSpecification;

  typedef struct nonce
  {
    ByteString *nonce_id;
    ByteString *nonce_value;
  } Nonce;

  typedef struct revocation_reason
  {
    enum revocation_reason_type reason;
    TextString                 *message;
  } RevocationReason;

  typedef struct secret_data
  {
    enum secret_data_type secret_data_type;
    KeyBlock             *key_block;
  } SecretData;

  /* Operation Payloads */

  typedef struct create_request_payload
  {
    /* KMIP 1.0 */
    enum object_type        object_type;
    TemplateAttribute      *template_attribute;
    /* KMIP 2.0 */
    Attributes             *attributes;
    ProtectionStorageMasks *protection_storage_masks;
  } CreateRequestPayload;

  typedef struct register_request_payload
  {
    /* KMIP 1.0 */
    enum object_type        object_type; // both
    TemplateAttribute      *template_attribute;
    /* KMIP 2.0 */
    Attributes             *attributes;
    ProtectionStorageMasks *protection_storage_masks;
    union
    {
      SymmetricKey symmetric_key; // both 1.0 and 2.0
      SecretData   secret_data;
      PublicKey    public_key;
      PrivateKey   private_key;
    } object; // both 1.0 and 2.0
  } RegisterRequestPayload;

  typedef struct register_response_payload
  {
    /* KMIP 1.0 */
    TextString        *unique_identifier;
    TemplateAttribute *template_attribute;
  } RegisterResponsePayload;

  typedef struct create_response_payload
  {
    /* KMIP 1.0 */
    enum object_type   object_type;
    TextString        *unique_identifier;
    TemplateAttribute *template_attribute;
  } CreateResponsePayload;

  typedef struct get_request_payload
  {
    /* KMIP 1.0 */
    TextString               *unique_identifier;
    enum key_format_type      key_format_type;
    enum key_compression_type key_compression_type;
    KeyWrappingSpecification *key_wrapping_spec;
    /* KMIP 1.4 */
    enum key_wrap_type        key_wrap_type;
  } GetRequestPayload;

  typedef struct get_response_payload
  {
    enum object_type object_type;
    TextString      *unique_identifier;
    void            *object;
  } GetResponsePayload;

  typedef struct get_attribute_request_payload
  {
    /* KMIP 1.0 */
    TextString *unique_identifier;
    TextString *attribute_name;
  } GetAttributeRequestPayload;

  typedef struct get_attribute_response_payload
  {
    TextString *unique_identifier;
    Attribute  *attribute;
    void       *object;
  } GetAttributeResponsePayload;

  typedef struct get_attribute_list_request_payload
  {
    TextString *unique_identifier;
  } GetAttributeListRequestPayload;

  typedef struct get_attribute_list_response_payload
  {
    TextString *unique_identifier;
    TextString *attribute_name;
  } GetAttributeListResponsePayload;

  typedef struct activate_request_payload
  {
    TextString *unique_identifier;
  } ActivateRequestPayload;

  typedef struct activate_response_payload
  {
    TextString *unique_identifier;
  } ActivateResponsePayload;

  typedef struct destroy_request_payload
  {
    TextString *unique_identifier;
  } DestroyRequestPayload;

  typedef struct destroy_response_payload
  {
    TextString *unique_identifier;
  } DestroyResponsePayload;

  typedef struct revoke_request_payload
  {
    TextString       *unique_identifier;
    RevocationReason *revocation_reason;
    // optional time, see spec v 1.0 p 4.19
    int64             compromise_occurence_date;
  } RevokeRequestPayload;

  typedef struct revoke_response_payload
  {
    TextString *unique_identifier;
  } RevokeResponsePayload;

  /* Authentication Structures */

  typedef struct credential
  {
    enum credential_type credential_type;
    void                *credential_value;
  } Credential;

  typedef struct username_password_credential
  {
    TextString *username;
    TextString *password;
  } UsernamePasswordCredential;

  typedef struct device_credential
  {
    TextString *device_serial_number;
    TextString *password;
    TextString *device_identifier;
    TextString *network_identifier;
    TextString *machine_identifier;
    TextString *media_identifier;
  } DeviceCredential;

  typedef struct attestation_credential
  {
    Nonce                *nonce;
    enum attestation_type attestation_type;
    ByteString           *attestation_measurement;
    ByteString           *attestation_assertion;
  } AttestationCredential;

  typedef struct authentication
  {
    /* NOTE (ph) KMIP 1.2+ supports multiple credentials here. */
    /* NOTE (ph) Polymorphism makes this tricky. Omitting for now. */
    /* TODO (ph) Credential structs are constant size, so no problem here. */
    /* TODO (ph) Change this to a linked list */
    Credential *credential;
  } Authentication;

  /* Message Structures */

  typedef struct request_header
  {
    /* KMIP 1.0 */
    ProtocolVersion                     *protocol_version;
    int32                                maximum_response_size;
    bool32                               asynchronous_indicator;
    Authentication                      *authentication;
    enum batch_error_continuation_option batch_error_continuation_option;
    bool32                               batch_order_option;
    int64                                time_stamp;
    int32                                batch_count;
    /* KMIP 1.2 */
    bool32                               attestation_capable_indicator;
    enum attestation_type               *attestation_types;
    size_t                               attestation_type_count;
    /* KMIP 1.4 */
    TextString                          *client_correlation_value;
    TextString                          *server_correlation_value;
  } RequestHeader;

  typedef struct response_header
  {
    /* KMIP 1.0 */
    ProtocolVersion       *protocol_version;
    int64                  time_stamp;
    int32                  batch_count;
    /* KMIP 1.2 */
    Nonce                 *nonce;
    /* TODO (ph) Change this to a linked list */
    enum attestation_type *attestation_types;
    size_t                 attestation_type_count;
    /* KMIP 1.4 */
    TextString            *client_correlation_value;
    TextString            *server_correlation_value;
    /* KMIP 2.0 */
    ByteString            *server_hashed_password;
  } ResponseHeader;

  typedef struct request_batch_item
  {
    /* KMIP 1.0 */
    enum operation operation;
    ByteString    *unique_batch_item_id;
    void          *request_payload;
    /* KMIP 2.0 */
    bool32         ephemeral;
    /* NOTE (ph) Omitting the message extension field for now. */
  } RequestBatchItem;

  typedef struct response_batch_item
  {
    enum operation     operation;
    ByteString        *unique_batch_item_id;
    enum result_status result_status;
    enum result_reason result_reason;
    TextString        *result_message;
    ByteString        *asynchronous_correlation_value;
    void              *response_payload;
    /* NOTE (ph) Omitting the message extension field for now. */
  } ResponseBatchItem;

  typedef struct request_message
  {
    RequestHeader    *request_header;
    /* TODO (ph) Change this to a linked list */
    RequestBatchItem *batch_items;
    size_t            batch_count;
  } RequestMessage;

  typedef struct response_message
  {
    ResponseHeader    *response_header;
    /* TODO (ph) Change this to a linked list */
    ResponseBatchItem *batch_items;
    size_t             batch_count;
  } ResponseMessage;

  typedef struct functions
  {
    LinkedList *function_list;
  } Functions;

  typedef struct operations
  {
    LinkedList *operation_list;
  } Operations;

  typedef struct object_types
  {
    LinkedList *object_list;
  } ObjectTypes;

  typedef struct alternative_endpoints
  {
    LinkedList *endpoint_list;
  } AltEndpoints;

  typedef struct server_information
  {
    TextString   *server_name;
    TextString   *server_serial_number;
    TextString   *server_version;
    TextString   *server_load;
    TextString   *product_name;
    TextString   *build_level;
    TextString   *build_date;
    TextString   *cluster_info;
    AltEndpoints *alternative_failover_endpoints;
    // Vendor-Specific               Any, MAY be repeated
  } ServerInformation;

  /*
  typedef struct application_namespaces
  {
      LinkedList *app_namespace_list;
  } ApplicationNamespaces;
  */

  typedef struct query_request_payload
  {
    Functions *functions;
  } QueryRequestPayload;

  typedef struct query_response_payload
  {
    Operations        *operations;            // Specifies an Operation that is supported by the server.
    ObjectTypes       *objects;               // Specifies a Managed Object Type that is supported
                                              // by the server.
    TextString        *vendor_identification; // SHALL be returned if Query Server
                                              // Information is requested. The Vendor
                                              // Identification SHALL be a text string
                                              // that uniquely identifies the vendor.
    ServerInformation *server_information;    // Contains vendor-specific information possibly
                                              // be of interest to the client.
    // ApplicationNamespaces*  application_namespaces;  // Specifies an
    // Application Namespace supported by the server. Extension Information No,
    // MAY be repeated  // SHALL be returned if Query Extension List or Query
    // Extension Map is requested and supported by the server. Attestation Type
    // No, MAY be repeated  // Specifies an Attestation Type that is supported
    // by the server. RNG Parameters                No, MAY be repeated  //
    // Specifies the RNG that is supported by the server. Profile Information
    // No, MAY be repeated  // Specifies the Profiles that are supported by the
    // server. Validation Information        No, MAY be repeated  // Specifies
    // the validations that are supported by the server. Capability Information
    // No, MAY be repeated  // Specifies the capabilities that are supported by
    // the server. Client Registration Method    No, MAY be repeated  //
    // Specifies a Client Registration Method that is supported by the server.
    // Defaults Information          No                   // Specifies the
    // defaults that the server will use if the client omits them. Protection
    // Storage Masks      Yes                  // Specifies the list of
    // Protection Storage Mask values supported by the server. A server MAY
    // elect to provide an empty list in the Response if it is unable or
    // unwilling to provide this information.
  } QueryResponsePayload;

#define MAX_QUERY_LEN  128
#define MAX_QUERY_OPS  0x40
#define MAX_QUERY_OBJS 0x20

  typedef struct query_response
  {
    size_t operations_size;
    int    operations[MAX_QUERY_OPS];
    size_t objects_size;
    int    objects[MAX_QUERY_OBJS];
    char   vendor_identification[MAX_QUERY_LEN];
    bool32 server_information_valid;
    char   server_name[MAX_QUERY_LEN];
    char   server_serial_number[MAX_QUERY_LEN];
    char   server_version[MAX_QUERY_LEN];
    char   server_load[MAX_QUERY_LEN];
    char   product_name[MAX_QUERY_LEN];
    char   build_level[MAX_QUERY_LEN];
    char   build_date[MAX_QUERY_LEN];
    char   cluster_info[MAX_QUERY_LEN];
  } QueryResponse;


#ifdef __cplusplus
}

#endif
#endif // KMIP_KMIP_STRUCTS_H
