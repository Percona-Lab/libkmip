#ifndef KMIPCORE_KMIP_PROTOCOL_HPP
#define KMIPCORE_KMIP_PROTOCOL_HPP

#include "kmipcore/kmip_basics.hpp"
#include "kmipcore/kmip_enums.hpp"

#include <optional>
#include <string>
#include <utility>
#include <vector>
namespace kmipcore {

  /**
   * @brief KMIP protocol version tuple (wire major.minor).
   *
   * Stores the on-wire major/minor pair directly, mirroring the spec's
   * own notation: @c ProtocolVersion(1,4) for KMIP 1.4,
   * @c ProtocolVersion(2,0) for KMIP 2.0, and so on.
   */
  class ProtocolVersion {
  public:
    /** @brief Constructs the default version: KMIP 1.4. */
    constexpr ProtocolVersion() = default;

    /** @brief Constructs from explicit on-wire major/minor values. */
    constexpr ProtocolVersion(int32_t major, int32_t minor)
      : major_(major), minor_(minor) {}

    /** @brief Returns on-wire major version component. */
    [[nodiscard]] int32_t getMajor() const { return major_; }
    /** @brief Sets on-wire major version component. */
    void setMajor(int32_t major) { major_ = major; }
    /** @brief Returns on-wire minor version component. */
    [[nodiscard]] int32_t getMinor() const { return minor_; }
    /** @brief Sets on-wire minor version component. */
    void setMinor(int32_t minor) { minor_ = minor; }

    /**
     * @brief Returns true when this version is >= the given on-wire
     * major.minor.
     *
     * Example: @c version.is_at_least(2, 0) is true for KMIP 2.0 and later.
     */
    [[nodiscard]] bool
        is_at_least(int32_t major, int32_t minor) const noexcept {
      return major_ > major || (major_ == major && minor_ >= minor);
    }

    /** @brief Encodes version to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes version from TTLV element form. */
    static ProtocolVersion fromElement(std::shared_ptr<Element> element);

  private:
    int32_t major_ = 1;
    int32_t minor_ = 4;
  };

  /** @brief KMIP protocol version 1.4. */
  inline constexpr ProtocolVersion KMIP_VERSION_1_4{1, 4};
  /** @brief KMIP protocol version 2.0. */
  inline constexpr ProtocolVersion KMIP_VERSION_2_0{2, 0};

  /** @brief KMIP request header model. */
  class RequestHeader {
  public:
    /** @brief Creates a header with default protocol fields. */
    RequestHeader() = default;
    /** @brief Returns protocol version. */
    [[nodiscard]] const ProtocolVersion &getProtocolVersion() const {
      return protocolVersion_;
    }
    /** @brief Sets protocol version. */
    void setProtocolVersion(const ProtocolVersion &version) {
      protocolVersion_ = version;
    }
    /** @brief Returns mutable protocol version reference. */
    ProtocolVersion &getProtocolVersion() { return protocolVersion_; }
    /** @brief Returns declared request batch count. */
    [[nodiscard]] int32_t getBatchCount() const { return batchCount_; }
    /** @brief Sets request batch count. */
    void setBatchCount(int32_t batchCount) { batchCount_ = batchCount; }
    /** @brief Returns optional maximum response size limit. */
    [[nodiscard]] std::optional<int32_t> getMaximumResponseSize() const {
      return maximumResponseSize_;
    }
    /** @brief Sets optional maximum response size limit. */
    void setMaximumResponseSize(std::optional<int32_t> maximumResponseSize) {
      maximumResponseSize_ = maximumResponseSize;
    }
    /** @brief Returns optional client timestamp. */
    [[nodiscard]] std::optional<int64_t> getTimeStamp() const {
      return timeStamp_;
    }
    /** @brief Sets optional client timestamp. */
    void setTimeStamp(std::optional<int64_t> timeStamp) {
      timeStamp_ = timeStamp;
    }
    /** @brief Returns optional batch-order processing flag. */
    [[nodiscard]] std::optional<bool> getBatchOrderOption() const {
      return batchOrderOption_;
    }
    /** @brief Sets optional batch-order processing flag. */
    void setBatchOrderOption(std::optional<bool> batchOrderOption) {
      batchOrderOption_ = batchOrderOption;
    }
    /** @brief Returns optional authentication username. */
    [[nodiscard]] const std::optional<std::string> &getUserName() const {
      return userName_;
    }
    /** @brief Sets optional authentication username. */
    void setUserName(const std::optional<std::string> &userName) {
      userName_ = userName;
    }
    /** @brief Returns optional authentication password. */
    [[nodiscard]] const std::optional<std::string> &getPassword() const {
      return password_;
    }
    /** @brief Sets optional authentication password. */
    void setPassword(const std::optional<std::string> &password) {
      password_ = password;
    }
    /** @brief Encodes header to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes header from TTLV element form. */
    static RequestHeader fromElement(std::shared_ptr<Element> element);

  private:
    ProtocolVersion protocolVersion_;
    int32_t batchCount_ = 0;
    std::optional<int32_t> maximumResponseSize_;
    std::optional<int64_t> timeStamp_;
    std::optional<bool> batchOrderOption_;
    std::optional<std::string> userName_;
    std::optional<std::string> password_;
  };

  /** @brief One KMIP operation entry within a request batch. */
  class RequestBatchItem {
  public:
    /** @brief Constructs an empty batch item. */
    RequestBatchItem() = default;
    /** @brief Returns unique batch item identifier. */
    [[nodiscard]] uint32_t getUniqueBatchItemId() const {
      return uniqueBatchItemId_;
    }
    /** @brief Sets unique batch item identifier. */
    void setUniqueBatchItemId(uint32_t id) { uniqueBatchItemId_ = id; }
    /** @brief Returns KMIP operation code for this item. */
    [[nodiscard]] int32_t getOperation() const { return operation_; }
    /** @brief Sets KMIP operation code for this item. */
    void setOperation(int32_t operation) { operation_ = operation; }
    /** @brief Returns request payload element. */
    [[nodiscard]] std::shared_ptr<Element> getRequestPayload() const {
      return requestPayload_;
    }
    /** @brief Sets request payload element. */
    void setRequestPayload(std::shared_ptr<Element> payload) {
      requestPayload_ = std::move(payload);
    }
    /** @brief Encodes batch item to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes batch item from TTLV element form. */
    static RequestBatchItem fromElement(std::shared_ptr<Element> element);

  private:
    uint32_t uniqueBatchItemId_ = 0;
    int32_t operation_ = 0;
    std::shared_ptr<Element> requestPayload_;
  };

  /** @brief Name/value attribute pair used in locate filters. */
  class Attribute {
  public:
    /** @brief Constructs an empty attribute. */
    Attribute() = default;
    /** @brief Constructs an attribute from name/value pair. */
    Attribute(const std::string &name, const std::string &value);

    /** @brief Returns attribute name. */
    [[nodiscard]] std::string getName() const { return name_; }
    /** @brief Sets attribute name. */
    void setName(const std::string &name) { name_ = name; }

    /** @brief Returns attribute value. */
    [[nodiscard]] std::string getValue() const { return value_; }
    /** @brief Sets attribute value. */
    void setValue(const std::string &value) { value_ = value; }

    /** @brief Encodes attribute to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes attribute from TTLV element form. */
    static Attribute fromElement(std::shared_ptr<Element> element);

  private:
    std::string name_;
    std::string value_;
  };

  /** @brief Payload model for KMIP Locate request. */
  class LocateRequestPayload {
  public:
    /** @brief Constructs an empty locate payload. */
    LocateRequestPayload() = default;

    /** @brief Returns requested maximum number of items. */
    [[nodiscard]] int32_t getMaximumItems() const { return maximumItems_; }
    /** @brief Sets requested maximum number of items. */
    void setMaximumItems(int32_t val) { maximumItems_ = val; }

    /** @brief Returns locate pagination offset. */
    [[nodiscard]] int32_t getOffsetItems() const { return offsetItems_; }
    /** @brief Sets locate pagination offset. */
    void setOffsetItems(int32_t val) { offsetItems_ = val; }

    /** @brief Returns locate filter attributes. */
    [[nodiscard]] const std::vector<Attribute> &getAttributes() const {
      return attributes_;
    }
    /** @brief Appends one locate filter attribute. */
    void addAttribute(const Attribute &attr) { attributes_.push_back(attr); }

    /** @brief Encodes locate payload to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes locate payload from TTLV element form. */
    static LocateRequestPayload fromElement(std::shared_ptr<Element> element);

  private:
    int32_t maximumItems_ = 0;
    int32_t offsetItems_ = 0;
    std::vector<Attribute> attributes_;
  };

  /** @brief Payload model for KMIP Locate response. */
  class LocateResponsePayload {
  public:
    /** @brief Constructs an empty locate response payload. */
    LocateResponsePayload() = default;

    /** @brief Returns optional total number of located items. */
    [[nodiscard]] std::optional<int32_t> getLocatedItems() const {
      return locatedItems_;
    }
    /** @brief Sets optional total number of located items. */
    void setLocatedItems(std::optional<int32_t> val) { locatedItems_ = val; }

    /** @brief Returns located unique identifiers. */
    [[nodiscard]] const std::vector<std::string> &getUniqueIdentifiers() const {
      return uniqueIdentifiers_;
    }
    /** @brief Appends one located unique identifier. */
    void addUniqueIdentifier(const std::string &id) {
      uniqueIdentifiers_.push_back(id);
    }

    /** @brief Encodes locate response payload to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes locate response payload from TTLV element form. */
    static LocateResponsePayload fromElement(std::shared_ptr<Element> element);

  private:
    std::optional<int32_t> locatedItems_;
    std::vector<std::string> uniqueIdentifiers_;
  };

  /** @brief Full KMIP request message including header and batch items. */
  class RequestMessage {
  public:
    /** Default maximum response-size hint used in request headers. */
    static constexpr size_t DEFAULT_MAX_RESPONSE_SIZE = KMIP_MAX_MESSAGE_SIZE;

    /** @brief Constructs message with default protocol (KMIP 1.4) and limits.
     */
    RequestMessage();
    /** @brief Constructs message from an explicit @ref ProtocolVersion. */
    explicit RequestMessage(ProtocolVersion version);
    /** @brief Constructs message from an explicit @ref ProtocolVersion and
     * response size hint. */
    RequestMessage(ProtocolVersion version, size_t maxResponseSize);

    /** @brief Returns const request header. */
    [[nodiscard]] const RequestHeader &getHeader() const { return header_; }
    /** @brief Returns mutable request header. */
    RequestHeader &getHeader() { return header_; }
    /** @brief Replaces request header. */
    void setHeader(const RequestHeader &header) { header_ = header; }
    /** @brief Returns const batch item list. */
    [[nodiscard]] const std::vector<RequestBatchItem> &getBatchItems() const {
      return batchItems_;
    }
    /** @brief Returns mutable batch item list. */
    std::vector<RequestBatchItem> &getBatchItems() { return batchItems_; }
    /**
     * @brief Adds one batch item and assigns a unique batch id.
     * @return Assigned batch item id.
     */
    uint32_t add_batch_item(RequestBatchItem item);
    /** @brief Replaces all batch items and updates header batch count. */
    void setBatchItems(const std::vector<RequestBatchItem> &items);
    /** @brief Returns number of batch items in the message. */
    [[nodiscard]] size_t getBatchItemCount() const {
      return batchItems_.size();
    }
    /** @brief Clears all batch items and resets batch id sequence. */
    void clearBatchItems() {
      batchItems_.clear();
      nextBatchItemId_ = 1;
    }


    /** @brief Sets maximum response size hint in request header. */
    void setMaxResponseSize(size_t size);
    /** @brief Returns maximum response size hint from request header. */
    [[nodiscard]] size_t getMaxResponseSize() const;

    /** @brief Serializes complete message to TTLV bytes. */
    [[nodiscard]] std::vector<uint8_t> serialize() const;

    /** @brief Encodes request message to TTLV element tree. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes request message from TTLV element tree. */
    static RequestMessage fromElement(std::shared_ptr<Element> element);

  private:
    RequestHeader header_;
    std::vector<RequestBatchItem> batchItems_;
    uint32_t nextBatchItemId_ = 1;
  };
  /** @brief KMIP response header model. */
  class ResponseHeader {
  public:
    /** @brief Constructs an empty response header. */
    ResponseHeader() = default;
    /** @brief Returns protocol version returned by server. */
    [[nodiscard]] const ProtocolVersion &getProtocolVersion() const {
      return protocolVersion_;
    }
    /** @brief Returns mutable protocol version. */
    ProtocolVersion &getProtocolVersion() { return protocolVersion_; }
    /** @brief Sets protocol version. */
    void setProtocolVersion(const ProtocolVersion &version) {
      protocolVersion_ = version;
    }
    /** @brief Returns server timestamp. */
    [[nodiscard]] int64_t getTimeStamp() const { return timeStamp_; }
    /** @brief Sets server timestamp. */
    void setTimeStamp(int64_t timeStamp) { timeStamp_ = timeStamp; }
    /** @brief Returns number of response batch items. */
    [[nodiscard]] int32_t getBatchCount() const { return batchCount_; }
    /** @brief Sets number of response batch items. */
    void setBatchCount(int32_t batchCount) { batchCount_ = batchCount; }
    /** @brief Encodes header to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes header from TTLV element form. */
    static ResponseHeader fromElement(std::shared_ptr<Element> element);

  private:
    ProtocolVersion protocolVersion_;
    int64_t timeStamp_ = 0;
    int32_t batchCount_ = 0;
  };

  /** @brief One KMIP operation entry within a response batch. */
  class ResponseBatchItem {
  public:
    /** @brief Constructs an empty response batch item. */
    ResponseBatchItem() = default;
    /** @brief Returns unique batch item id correlating to request item. */
    [[nodiscard]] uint32_t getUniqueBatchItemId() const {
      return uniqueBatchItemId_;
    }
    /** @brief Sets unique batch item id correlating to request item. */
    void setUniqueBatchItemId(uint32_t id) { uniqueBatchItemId_ = id; }
    /** @brief Returns operation code executed by server. */
    [[nodiscard]] int32_t getOperation() const { return operation_; }
    /** @brief Sets operation code executed by server. */
    void setOperation(int32_t operation) { operation_ = operation; }
    /** @brief Returns operation result status. */
    [[nodiscard]] int32_t getResultStatus() const { return resultStatus_; }
    /** @brief Sets operation result status. */
    void setResultStatus(int32_t status) { resultStatus_ = status; }
    /** @brief Returns optional result reason enum value. */
    [[nodiscard]] std::optional<int32_t> getResultReason() const {
      return resultReason_;
    }
    /** @brief Sets optional result reason enum value. */
    void setResultReason(std::optional<int32_t> reason) {
      resultReason_ = reason;
    }
    /** @brief Returns optional result message text. */
    [[nodiscard]] const std::optional<std::string> &getResultMessage() const {
      return resultMessage_;
    }
    /** @brief Sets optional result message text. */
    void setResultMessage(const std::optional<std::string> &message) {
      resultMessage_ = message;
    }
    /** @brief Returns operation-specific response payload. */
    [[nodiscard]] std::shared_ptr<Element> getResponsePayload() const {
      return responsePayload_;
    }
    /** @brief Sets operation-specific response payload. */
    void setResponsePayload(std::shared_ptr<Element> payload) {
      responsePayload_ = std::move(payload);
    }
    /** @brief Encodes response batch item to TTLV element form. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes response batch item from TTLV element form. */
    static ResponseBatchItem fromElement(std::shared_ptr<Element> element);

  private:
    uint32_t uniqueBatchItemId_ = 0;
    int32_t operation_ = 0;
    int32_t resultStatus_ = 0;
    std::optional<int32_t> resultReason_;
    std::optional<std::string> resultMessage_;
    std::shared_ptr<Element> responsePayload_;
  };

  /** @brief Full KMIP response message including header and batch items. */
  class ResponseMessage {
  public:
    /** @brief Constructs an empty response message. */
    ResponseMessage() = default;
    /** @brief Returns const response header. */
    [[nodiscard]] const ResponseHeader &getHeader() const { return header_; }
    /** @brief Returns mutable response header. */
    ResponseHeader &getHeader() { return header_; }
    /** @brief Replaces response header. */
    void setHeader(const ResponseHeader &header) { header_ = header; }
    /** @brief Returns const response batch items. */
    [[nodiscard]] const std::vector<ResponseBatchItem> &getBatchItems() const {
      return batchItems_;
    }
    /** @brief Returns mutable response batch items. */
    std::vector<ResponseBatchItem> &getBatchItems() { return batchItems_; }
    /** @brief Appends one response batch item. */
    void add_batch_item(const ResponseBatchItem &item) {
      batchItems_.push_back(item);
    }
    /** @brief Encodes response message to TTLV element tree. */
    [[nodiscard]] std::shared_ptr<Element> toElement() const;
    /** @brief Decodes response message from TTLV element tree. */
    static ResponseMessage fromElement(std::shared_ptr<Element> element);

  private:
    ResponseHeader header_;
    std::vector<ResponseBatchItem> batchItems_;
  };
}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_PROTOCOL_HPP */
