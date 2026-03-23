#include "kmipcore/kmip_errors.hpp"

#include <cstdint>
#include <optional>
#include <sstream>

namespace kmipcore {

  namespace {

    struct KmipReasonInfo {
      const char *name;
      const char *description;
    };

    [[nodiscard]] std::optional<KmipReasonInfo>
        lookup_kmip_reason_info(int code) {
      switch (code) {
        case KMIP_REASON_ITEM_NOT_FOUND:
          return KmipReasonInfo{
              "Item Not Found",
              "No object with the specified Unique Identifier exists."
          };
        case KMIP_REASON_RESPONSE_TOO_LARGE:
          return KmipReasonInfo{
              "Response Too Large", "Maximum Response Size has been exceeded."
          };
        case KMIP_REASON_AUTHENTICATION_NOT_SUCCESSFUL:
          return KmipReasonInfo{
              "Authentication Not Successful", "Authentication did not succeed."
          };
        case KMIP_REASON_INVALID_MESSAGE:
          return KmipReasonInfo{
              "Invalid Message",
              "The request message was not syntactically understood by the "
              "server."
          };
        case KMIP_REASON_OPERATION_NOT_SUPPORTED:
          return KmipReasonInfo{
              "Operation Not Supported",
              "The operation requested by the request message is not supported "
              "by the server."
          };
        case KMIP_REASON_MISSING_DATA:
          return KmipReasonInfo{
              "Missing Data",
              "The operation required additional information in the request, "
              "which was not present."
          };
        case KMIP_REASON_INVALID_FIELD:
          return KmipReasonInfo{
              "Invalid Field",
              "The request is syntactically valid but some non-attribute data "
              "field is invalid."
          };
        case KMIP_REASON_FEATURE_NOT_SUPPORTED:
          return KmipReasonInfo{
              "Feature Not Supported",
              "The operation is supported, but a specific feature requested is "
              "not supported."
          };
        case KMIP_REASON_OPERATION_CANCELED_BY_REQUESTER:
          return KmipReasonInfo{
              "Operation Canceled By Requester",
              "The asynchronous operation was canceled before it completed."
          };
        case KMIP_REASON_CRYPTOGRAPHIC_FAILURE:
          return KmipReasonInfo{
              "Cryptographic Failure", "A cryptographic operation failed."
          };
        case KMIP_REASON_ILLEGAL_OPERATION:
          return KmipReasonInfo{
              "Illegal Operation",
              "The requested operation is not legal in the current context."
          };
        case KMIP_REASON_PERMISSION_DENIED:
          return KmipReasonInfo{
              "Permission Denied",
              "Client is not allowed to perform the specified operation."
          };
        case KMIP_REASON_OBJECT_ARCHIVED:
          return KmipReasonInfo{
              "Object Archived",
              "The object must be recovered from archive before this operation."
          };
        case KMIP_REASON_INDEX_OUT_OF_BOUNDS:
          return KmipReasonInfo{
              "Index Out Of Bounds",
              "An index in the request exceeded valid bounds."
          };
        case KMIP_REASON_APPLICATION_NAMESPACE_NOT_SUPPORTED:
          return KmipReasonInfo{
              "Application Namespace Not Supported",
              "The application namespace is not supported by the server."
          };
        case KMIP_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED:
          return KmipReasonInfo{
              "Key Format Type Not Supported",
              "The server cannot provide the object in the desired Key Format "
              "Type."
          };
        case KMIP_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED:
          return KmipReasonInfo{
              "Key Compression Type Not Supported",
              "The server cannot provide the object in the desired Key "
              "Compression Type."
          };
        case KMIP_REASON_ENCODING_OPTION_FAILURE:
          return KmipReasonInfo{
              "Encoding Option Error", "The requested encoding option failed."
          };
        case KMIP_REASON_KEY_VALUE_NOT_PRESENT:
          return KmipReasonInfo{
              "Key Value Not Present",
              "The key value is not present on the server."
          };
        case KMIP_REASON_ATTESTATION_REQUIRED:
          return KmipReasonInfo{
              "Attestation Required",
              "Attestation is required to complete this request."
          };
        case KMIP_REASON_ATTESTATION_FAILED:
          return KmipReasonInfo{
              "Attestation Failed", "Attestation data validation failed."
          };
        case KMIP_REASON_SENSITIVE:
          return KmipReasonInfo{
              "Sensitive", "Sensitive keys may not be retrieved unwrapped."
          };
        case KMIP_REASON_NOT_EXTRACTABLE:
          return KmipReasonInfo{
              "Not Extractable", "The object is not extractable."
          };
        case KMIP_REASON_OBJECT_ALREADY_EXISTS:
          return KmipReasonInfo{
              "Object Already Exists",
              "An object with the requested identifier already exists."
          };
        case KMIP_REASON_INVALID_TICKET:
          return KmipReasonInfo{"Invalid Ticket", "The ticket was invalid."};
        case KMIP_REASON_USAGE_LIMIT_EXCEEDED:
          return KmipReasonInfo{
              "Usage Limit Exceeded",
              "The usage limit or request count has been exceeded."
          };
        case KMIP_REASON_NUMERIC_RANGE:
          return KmipReasonInfo{
              "Numeric Range",
              "A numeric result is too large or too small for the requested "
              "data type."
          };
        case KMIP_REASON_INVALID_DATA_TYPE:
          return KmipReasonInfo{
              "Invalid Data Type",
              "A data type was invalid for the requested operation."
          };
        case KMIP_REASON_READ_ONLY_ATTRIBUTE:
          return KmipReasonInfo{
              "Read Only Attribute", "Attempted to set a read-only attribute."
          };
        case KMIP_REASON_MULTI_VALUED_ATTRIBUTE:
          return KmipReasonInfo{
              "Multi Valued Attribute",
              "Attempted to set or adjust an attribute that has multiple "
              "values."
          };
        case KMIP_REASON_UNSUPPORTED_ATTRIBUTE:
          return KmipReasonInfo{
              "Unsupported Attribute",
              "Attribute is valid in the specification but unsupported by the "
              "server."
          };
        case KMIP_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND:
          return KmipReasonInfo{
              "Attribute Instance Not Found",
              "A specific attribute instance could not be found."
          };
        case KMIP_REASON_ATTRIBUTE_NOT_FOUND:
          return KmipReasonInfo{
              "Attribute Not Found",
              "A requested attribute does not exist on the object."
          };
        case KMIP_REASON_ATTRIBUTE_READ_ONLY:
          return KmipReasonInfo{
              "Attribute Read Only",
              "Attempted to modify an attribute that is read-only."
          };
        case KMIP_REASON_ATTRIBUTE_SINGLE_VALUED:
          return KmipReasonInfo{
              "Attribute Single Valued",
              "Attempted to provide multiple values for a single-valued "
              "attribute."
          };
        case KMIP_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS:
          return KmipReasonInfo{
              "Bad Cryptographic Parameters",
              "Cryptographic parameters are invalid for the requested "
              "operation."
          };
        case KMIP_REASON_BAD_PASSWORD:
          return KmipReasonInfo{
              "Bad Password", "Provided password is invalid."
          };
        case KMIP_REASON_CODEC_ERROR:
          return KmipReasonInfo{
              "Codec Error",
              "A codec error occurred while processing the request."
          };
        case KMIP_REASON_ILLEGAL_OBJECT_TYPE:
          return KmipReasonInfo{
              "Illegal Object Type",
              "This operation cannot be performed on the specified object type."
          };
        case KMIP_REASON_INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK:
          return KmipReasonInfo{
              "Incompatible Cryptographic Usage Mask",
              "Cryptographic parameters or usage mask are incompatible with "
              "the operation."
          };
        case KMIP_REASON_INTERNAL_SERVER_ERROR:
          return KmipReasonInfo{
              "Internal Server Error",
              "The server had an internal error and could not process the "
              "request."
          };
        case KMIP_REASON_INVALID_ASYNCHRONOUS_CORRELATION_VALUE:
          return KmipReasonInfo{
              "Invalid Asynchronous Correlation Value",
              "No outstanding operation exists for the provided asynchronous "
              "correlation value."
          };
        case KMIP_REASON_INVALID_ATTRIBUTE:
          return KmipReasonInfo{
              "Invalid Attribute",
              "An attribute is invalid for this object and operation."
          };
        case KMIP_REASON_INVALID_ATTRIBUTE_VALUE:
          return KmipReasonInfo{
              "Invalid Attribute Value",
              "The supplied value for an attribute is invalid."
          };
        case KMIP_REASON_INVALID_CORRELATION_VALUE:
          return KmipReasonInfo{
              "Invalid Correlation Value",
              "Correlation value is invalid for this request context."
          };
        case KMIP_REASON_INVALID_CSR:
          return KmipReasonInfo{
              "Invalid CSR", "Certificate Signing Request is invalid."
          };
        case KMIP_REASON_INVALID_OBJECT_TYPE:
          return KmipReasonInfo{
              "Invalid Object Type",
              "The specified object type is invalid for the operation."
          };
        case KMIP_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED:
          return KmipReasonInfo{
              "Key Wrap Type Not Supported",
              "The key wrap type is not supported by the server."
          };
        case KMIP_REASON_MISSING_INITIALIZATION_VECTOR:
          return KmipReasonInfo{
              "Missing Initialization Vector",
              "Initialization vector is required but missing."
          };
        case KMIP_REASON_NON_UNIQUE_NAME_ATTRIBUTE:
          return KmipReasonInfo{
              "Non Unique Name Attribute",
              "The request violates uniqueness constraints on the Name "
              "attribute."
          };
        case KMIP_REASON_OBJECT_DESTROYED:
          return KmipReasonInfo{
              "Object Destroyed",
              "The object exists but has already been destroyed."
          };
        case KMIP_REASON_OBJECT_NOT_FOUND:
          return KmipReasonInfo{
              "Object Not Found", "A requested managed object was not found."
          };
        case KMIP_REASON_NOT_AUTHORISED:
          return KmipReasonInfo{
              "Not Authorised",
              "Client is not authorised for the requested operation."
          };
        case KMIP_REASON_SERVER_LIMIT_EXCEEDED:
          return KmipReasonInfo{
              "Server Limit Exceeded", "A server-side limit has been exceeded."
          };
        case KMIP_REASON_UNKNOWN_ENUMERATION:
          return KmipReasonInfo{
              "Unknown Enumeration",
              "An enumeration value is not known by the server."
          };
        case KMIP_REASON_UNKNOWN_MESSAGE_EXTENSION:
          return KmipReasonInfo{
              "Unknown Message Extension",
              "The server does not support the supplied message extension."
          };
        case KMIP_REASON_UNKNOWN_TAG:
          return KmipReasonInfo{
              "Unknown Tag", "A tag in the request is not known by the server."
          };
        case KMIP_REASON_UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS:
          return KmipReasonInfo{
              "Unsupported Cryptographic Parameters",
              "Cryptographic parameters are valid in spec but unsupported by "
              "server."
          };
        case KMIP_REASON_UNSUPPORTED_PROTOCOL_VERSION:
          return KmipReasonInfo{
              "Unsupported Protocol Version",
              "The operation cannot be performed with the provided protocol "
              "version."
          };
        case KMIP_REASON_WRAPPING_OBJECT_ARCHIVED:
          return KmipReasonInfo{
              "Wrapping Object Archived", "Wrapping object is archived."
          };
        case KMIP_REASON_WRAPPING_OBJECT_DESTROYED:
          return KmipReasonInfo{
              "Wrapping Object Destroyed",
              "Wrapping object exists but is destroyed."
          };
        case KMIP_REASON_WRAPPING_OBJECT_NOT_FOUND:
          return KmipReasonInfo{
              "Wrapping Object Not Found", "Wrapping object does not exist."
          };
        case KMIP_REASON_WRONG_KEY_LIFECYCLE_STATE:
          return KmipReasonInfo{
              "Wrong Key Lifecycle State",
              "Key lifecycle state is invalid for the requested operation."
          };
        case KMIP_REASON_PROTECTION_STORAGE_UNAVAILABLE:
          return KmipReasonInfo{
              "Protection Storage Unavailable",
              "Requested protection storage is unavailable."
          };
        case KMIP_REASON_PKCS11_CODEC_ERROR:
          return KmipReasonInfo{
              "PKCS#11 Codec Error",
              "There is a codec error in PKCS#11 input parameters."
          };
        case KMIP_REASON_PKCS11_INVALID_FUNCTION:
          return KmipReasonInfo{
              "PKCS#11 Invalid Function",
              "The PKCS#11 function is not in the selected interface."
          };
        case KMIP_REASON_PKCS11_INVALID_INTERFACE:
          return KmipReasonInfo{
              "PKCS#11 Invalid Interface",
              "The PKCS#11 interface is unknown or unavailable."
          };
        case KMIP_REASON_PRIVATE_PROTECTION_STORAGE_UNAVAILABLE:
          return KmipReasonInfo{
              "Private Protection Storage Unavailable",
              "Requested private protection storage is unavailable."
          };
        case KMIP_REASON_PUBLIC_PROTECTION_STORAGE_UNAVAILABLE:
          return KmipReasonInfo{
              "Public Protection Storage Unavailable",
              "Requested public protection storage is unavailable."
          };
        case KMIP_REASON_GENERAL_FAILURE:
          return KmipReasonInfo{
              "General Failure",
              "The request failed for a reason outside the other reason codes."
          };
        default:
          return std::nullopt;
      }
    }

    [[nodiscard]] const char *lookup_internal_error_name(int code) {
      switch (code) {
        case KMIP_OK:
          return "OK";
        case KMIP_NOT_IMPLEMENTED:
          return "Not Implemented";
        case KMIP_ERROR_BUFFER_FULL:
          return "Buffer Full";
        case KMIP_ERROR_ATTR_UNSUPPORTED:
          return "Attribute Unsupported";
        case KMIP_TAG_MISMATCH:
          return "Tag Mismatch";
        case KMIP_TYPE_MISMATCH:
          return "Type Mismatch";
        case KMIP_LENGTH_MISMATCH:
          return "Length Mismatch";
        case KMIP_PADDING_MISMATCH:
          return "Padding Mismatch";
        case KMIP_BOOLEAN_MISMATCH:
          return "Boolean Mismatch";
        case KMIP_ENUM_MISMATCH:
          return "Enum Mismatch";
        case KMIP_ENUM_UNSUPPORTED:
          return "Enum Unsupported";
        case KMIP_INVALID_FOR_VERSION:
          return "Invalid For Version";
        case KMIP_MEMORY_ALLOC_FAILED:
          return "Memory Allocation Failed";
        case KMIP_IO_FAILURE:
          return "I/O Failure";
        case KMIP_EXCEED_MAX_MESSAGE_SIZE:
          return "Exceeded Max Message Size";
        case KMIP_MALFORMED_RESPONSE:
          return "Malformed Response";
        case KMIP_OBJECT_MISMATCH:
          return "Object Mismatch";
        case KMIP_ARG_INVALID:
          return "Invalid Argument";
        case KMIP_ERROR_BUFFER_UNDERFULL:
          return "Buffer Underfull";
        case KMIP_INVALID_ENCODING:
          return "Invalid Encoding";
        case KMIP_INVALID_FIELD:
          return "Invalid Field";
        case KMIP_INVALID_LENGTH:
          return "Invalid Length";
        default:
          return nullptr;
      }
    }

    [[nodiscard]] std::string hex_code(int code) {
      std::ostringstream oss;
      oss << "0x" << std::hex << std::uppercase
          << static_cast<std::uint32_t>(code);
      return oss.str();
    }

    [[nodiscard]] std::string kmip_message_for_code(int code) {
      if (const auto info = lookup_kmip_reason_info(code)) {
        return std::string(info->name) + ": " + info->description;
      }

      if (const auto *internal_name = lookup_internal_error_name(code)) {
        return std::string(internal_name);
      }

      if (code == KMIP_STATUS_SUCCESS) {
        return "Success";
      }

      return "Unknown KMIP error code " + hex_code(code);
    }

  }  // namespace

  const std::error_category &kmip_category() noexcept {
    class category_impl : public std::error_category {
    public:
      [[nodiscard]] const char *name() const noexcept override {
        return "kmip";
      }

      [[nodiscard]] std::string message(int code) const override {
        return kmip_message_for_code(code);
      }
    };

    static const category_impl instance;
    return instance;
  }

  std::error_code make_kmip_error_code(int native_error_code) noexcept {
    return {native_error_code, kmip_category()};
  }

  KmipException::KmipException(const std::string &msg)
    : std::system_error(
          make_kmip_error_code(KMIP_REASON_GENERAL_FAILURE), msg
      ) {}

  KmipException::KmipException(int native_error_code, const std::string &msg)
    : std::system_error(make_kmip_error_code(native_error_code), msg) {}

}  // namespace kmipcore
