#ifndef KMIPCORE_RESPONSE_PARSER_HPP
#define KMIPCORE_RESPONSE_PARSER_HPP

#include "kmipcore/kmip_protocol.hpp"
#include "kmipcore/kmip_responses.hpp"

#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace kmipcore {

  /** @brief Compact status summary for one KMIP response batch item. */
  struct OperationResult {
    /** Operation code reported by the response item. */
    int32_t operation = 0;
    /** KMIP result_status code. */
    KmipResultStatusCode resultStatus = 0;
    /** KMIP result_reason code when available. */
    KmipResultReasonCode resultReason = 0;
    /** Human-readable result message when available. */
    std::string resultMessage;
  };

  /** Parses KMIP response batch items and decodes typed operation-specific
   * items. */
  class ResponseParser {
  public:
    /**
     * @brief Creates a parser for one encoded KMIP response message.
     * @param responseBytes Raw TTLV response payload.
     */
    explicit ResponseParser(std::span<const uint8_t> responseBytes);

    /**
     * @brief Creates a parser that also holds operation hints from the request.
     *
     * Some KMIP servers (e.g. pyKMIP) omit the Operation field from response
     * Batch Items, particularly in failure responses.  Supplying the original
     * @p request lets the parser map each response item back to the operation
     * that was requested, so that error messages remain informative.
     *
     * @param responseBytes Raw TTLV response payload.
     * @param request       The request whose response is being parsed.
     */
    ResponseParser(
        std::span<const uint8_t> responseBytes, const RequestMessage &request
    );
    /** @brief Default destructor. */
    ~ResponseParser() = default;
    ResponseParser(const ResponseParser &) = delete;
    ResponseParser(ResponseParser &&) = delete;
    ResponseParser &operator=(const ResponseParser &) = delete;
    ResponseParser &operator=(ResponseParser &&) = delete;

    /** @brief Returns number of batch items in the parsed response. */
    [[nodiscard]] size_t getBatchItemCount();
    /**
     * @brief Returns whether a batch item completed with KMIP_STATUS_SUCCESS.
     * @param itemIdx Zero-based batch item index.
     */
    [[nodiscard]] bool isSuccess(int itemIdx);

    /**
     * @brief Returns operation status fields for one batch item.
     * @param itemIdx Zero-based batch item index.
     */
    [[nodiscard]] OperationResult getOperationResult(int itemIdx);
    /**
     * @brief Returns operation status fields by unique batch item id.
     * @param batchItemId Request/response correlation id.
     */
    [[nodiscard]] OperationResult
        getOperationResultByBatchItemId(uint32_t batchItemId);

    /**
     * @brief Returns typed response object by index after success check.
     * @tparam TypedResponseBatchItem One of kmip_responses typed wrappers.
     * @param itemIdx Zero-based batch item index.
     * @throws KmipException if item is not successful or payload is invalid.
     */
    template<typename TypedResponseBatchItem>
    [[nodiscard]] TypedResponseBatchItem getResponse(int itemIdx) {
      const auto &item = getResponseItem(itemIdx);
      ensureSuccess(item);
      return TypedResponseBatchItem::fromBatchItem(item);
    }

    /**
     * @brief Returns typed response object by unique batch id after success
     * check.
     * @tparam TypedResponseBatchItem One of kmip_responses typed wrappers.
     * @param batchItemId Request/response correlation id.
     * @throws KmipException if item is not successful or payload is invalid.
     */
    template<typename TypedResponseBatchItem>
    [[nodiscard]] TypedResponseBatchItem
        getResponseByBatchItemId(uint32_t batchItemId) {
      const auto &item = getResponseItemByBatchItemId(batchItemId);
      ensureSuccess(item, batchItemId);
      return TypedResponseBatchItem::fromBatchItem(item);
    }

  private:
    void parseResponse();

    void ensureParsed() {
      if (!isParsed_) {
        parseResponse();
      }
    }

    [[nodiscard]] const ResponseBatchItem &getResponseItem(int itemIdx);
    [[nodiscard]] const ResponseBatchItem &
        getResponseItemByBatchItemId(uint32_t batchItemId);

    /** Returns the operation code to report for @p item.
     *  When the server omits the Operation field, falls back to the hint
     *  stored for the requested batch item id (populated from the request). */
    [[nodiscard]] int32_t effectiveOperation(
        const ResponseBatchItem &item,
        std::optional<uint32_t> requestedBatchItemId = std::nullopt
    ) const;

    void ensureSuccess(
        const ResponseBatchItem &item,
        std::optional<uint32_t> requestedBatchItemId = std::nullopt
    );

    static std::string formatOperationResult(
        const ResponseBatchItem &value, int32_t operation
    );
    static const char *operationToString(int32_t operation);
    static const char *resultStatusToString(int32_t status);

    std::vector<uint8_t> responseBytes_;
    ResponseMessage responseMessage_{};
    bool isParsed_ = false;
    /** Maps uniqueBatchItemId → operation code extracted from the request. */
    std::unordered_map<uint32_t, int32_t> operationHints_;
    /** Maps uniqueBatchItemId → 0-based position in the request batch.
     *  Used as a positional fallback when the server does not echo batch item
     *  IDs in its responses (e.g. pyKMIP multi-batch responses). */
    std::unordered_map<uint32_t, size_t> batchItemPositions_;
  };

}  // namespace kmipcore

#endif /* KMIPCORE_RESPONSE_PARSER_HPP */
