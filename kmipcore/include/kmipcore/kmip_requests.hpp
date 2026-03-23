#ifndef KMIPCORE_KMIP_REQUESTS_HPP
#define KMIPCORE_KMIP_REQUESTS_HPP

#include "kmipcore/key.hpp"
#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"
#include "kmipcore/kmip_protocol.hpp"

#include <ctime>
#include <memory>
#include <string>
#include <vector>

namespace kmipcore {

  // ---------------------------------------------------------------------------
  // Each Request class IS a RequestBatchItem.
  // Construct one and pass it directly to RequestMessage::addBatchItem().
  // ---------------------------------------------------------------------------


  // ---------------------------------------------------------------------------
  // Template for simple requests that only carry a unique identifier.
  // ---------------------------------------------------------------------------
  /**
   * @brief Generic request carrying only a unique identifier in payload.
   * @tparam OpCode KMIP operation code encoded in the batch item.
   */
  template<int32_t OpCode> class SimpleIdRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a simple request payload with unique identifier.
     * @param unique_id KMIP unique identifier of target object.
     */
    explicit SimpleIdRequest(const std::string &unique_id) {
      setOperation(OpCode);
      auto payload = Element::createStructure(tag::KMIP_TAG_REQUEST_PAYLOAD);
      payload->asStructure()->add(
          Element::createTextString(tag::KMIP_TAG_UNIQUE_IDENTIFIER, unique_id)
      );
      setRequestPayload(payload);
    }
  };

  /** @brief Typed request alias for KMIP Get operation. */
  using GetRequest = SimpleIdRequest<KMIP_OP_GET>;
  /** @brief Typed request alias for KMIP Activate operation. */
  using ActivateRequest = SimpleIdRequest<KMIP_OP_ACTIVATE>;
  /** @brief Typed request alias for KMIP Destroy operation. */
  using DestroyRequest = SimpleIdRequest<KMIP_OP_DESTROY>;
  /** @brief Typed request alias for KMIP Get Attribute List operation. */
  using GetAttributeListRequest = SimpleIdRequest<KMIP_OP_GET_ATTRIBUTE_LIST>;


  /** @brief Request for KMIP Get Attributes operation. */
  class GetAttributesRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds Get Attributes request for selected attribute names.
     * @param unique_id KMIP unique identifier of target object.
     * @param attribute_names Attribute selectors to retrieve.
     *        KMIP 1.x encodes them as Attribute Name text strings; KMIP 2.0
     *        encodes them as Attribute Reference structures.
     * @param legacy_attribute_names_for_v2 When true, forces legacy Attribute
     *        Name text-string encoding even for KMIP 2.0 (interoperability
     *        fallback for non-compliant servers).
     */
    GetAttributesRequest(
        const std::string &unique_id,
        const std::vector<std::string> &attribute_names,
        ProtocolVersion version = {},
        bool legacy_attribute_names_for_v2 = false
    );
  };

  // Constructors for the following classes are defined in kmip_requests.cpp
  // because they rely on internal detail:: helpers.

  /** @brief Request for KMIP Create (symmetric key) operation. */
  class CreateSymmetricKeyRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a create-key request for server-side AES generation.
     * @param name Value for KMIP Name attribute.
     * @param group Value for KMIP Object Group attribute.
     * @param key_bits AES key size in bits (128, 192, 256).
     * @param usage_mask Cryptographic Usage Mask bitset to store with key.
     */
    CreateSymmetricKeyRequest(
        const std::string &name,
        const std::string &group,
        int32_t key_bits,
        cryptographic_usage_mask usage_mask =
            static_cast<cryptographic_usage_mask>(
                KMIP_CRYPTOMASK_ENCRYPT | KMIP_CRYPTOMASK_DECRYPT
            ),
        ProtocolVersion version = {}
    );
  };

  /** @brief Request for KMIP Register (symmetric key) operation. */
  class RegisterSymmetricKeyRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a register request for raw symmetric key bytes.
     * @param name Value for KMIP Name attribute.
     * @param group Value for KMIP Object Group attribute.
     * @param key_value Raw symmetric key payload.
     */
    RegisterSymmetricKeyRequest(
        const std::string &name,
        const std::string &group,
        const std::vector<unsigned char> &key_value,
        ProtocolVersion version = {}
    );
  };

  /** @brief Request for KMIP Register operation using generic key object input.
   */
  class RegisterKeyRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a register request for a key object and common attributes.
     * @param name Value for KMIP Name attribute.
     * @param group Value for KMIP Object Group attribute.
     * @param key Key payload and metadata mapped to protocol object fields.
     */
    RegisterKeyRequest(
        const std::string &name,
        const std::string &group,
        const Key &key,
        ProtocolVersion version = {}
    );
  };

  /** @brief Request for KMIP Register (secret data) operation. */
  class RegisterSecretRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a register request for secret payload bytes.
     * @param name Value for KMIP Name attribute.
     * @param group Value for KMIP Object Group attribute.
     * @param secret Secret payload bytes.
     * @param secret_type KMIP secret_data_type enum value.
     */
    RegisterSecretRequest(
        const std::string &name,
        const std::string &group,
        const std::vector<unsigned char> &secret,
        secret_data_type secret_type,
        ProtocolVersion version = {}
    );
  };

  /** @brief Request for KMIP Locate operation. */
  class LocateRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a locate request by name or group.
     * @param locate_by_group true to filter by Object Group, false by Name.
     * @param name Filter value.
     * @param object_type KMIP object_type to match.
     * @param max_items Maximum number of items requested per locate call.
     * @param offset Locate offset used for paged reads.
     * @param version Protocol version; controls KMIP 2.0 Attributes vs 1.x
     * Attribute format.
     */
    LocateRequest(
        bool locate_by_group,
        const std::string &name,
        object_type obj_type,
        size_t max_items = 0,
        size_t offset = 0,
        ProtocolVersion version = {}
    );
  };

  /** @brief Request for KMIP Revoke operation. */
  class RevokeRequest : public RequestBatchItem {
  public:
    /**
     * @brief Builds a revoke request with reason and optional occurrence time.
     * @param unique_id KMIP unique identifier of target object.
     * @param reason KMIP revocation reason enum value.
     * @param message Human-readable revocation note.
     * @param occurrence_time Incident timestamp, 0 for default deactivation
     * flow.
     */
    RevokeRequest(
        const std::string &unique_id,
        revocation_reason_type reason,
        const std::string &message,
        time_t occurrence_time = 0
    );
  };


}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_REQUESTS_HPP */
