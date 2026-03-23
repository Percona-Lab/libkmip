#include "kmipcore/response_parser.hpp"

#include "kmipcore/kmip_errors.hpp"

#include <sstream>

namespace kmipcore {

  namespace {
    [[nodiscard]] KmipResultReasonCode
        get_result_reason_or_default(const ResponseBatchItem &item) {
      return item.getResultReason().value_or(KMIP_REASON_GENERAL_FAILURE);
    }
  }  // namespace

  ResponseParser::ResponseParser(std::span<const uint8_t> responseBytes)
    : responseBytes_(responseBytes.begin(), responseBytes.end()) {}

  ResponseParser::ResponseParser(
      std::span<const uint8_t> responseBytes, const RequestMessage &request
  )
    : responseBytes_(responseBytes.begin(), responseBytes.end()) {
    size_t pos = 0;
    for (const auto &item : request.getBatchItems()) {
      const uint32_t id = item.getUniqueBatchItemId();
      operationHints_[id] = item.getOperation();
      batchItemPositions_[id] = pos++;
    }
  }

  int32_t ResponseParser::effectiveOperation(
      const ResponseBatchItem &item,
      std::optional<uint32_t> requestedBatchItemId
  ) const {
    const int32_t op = item.getOperation();
    if (op != 0) {
      return op;
    }
    // Response didn't include Operation – first try the echoed batch item id.
    const auto it = operationHints_.find(item.getUniqueBatchItemId());
    if (it != operationHints_.end()) {
      return it->second;
    }

    // Some servers omit both Operation and Unique Batch Item Id. In that case
    // fall back to the batch item id requested by the caller.
    if (requestedBatchItemId.has_value()) {
      const auto requested_it = operationHints_.find(*requestedBatchItemId);
      if (requested_it != operationHints_.end()) {
        return requested_it->second;
      }
    }

    return 0;
  }

  size_t ResponseParser::getBatchItemCount() {
    ensureParsed();
    return responseMessage_.getBatchItems().size();
  }

  bool ResponseParser::isSuccess(int itemIdx) {
    return getResponseItem(itemIdx).getResultStatus() == KMIP_STATUS_SUCCESS;
  }

  OperationResult ResponseParser::getOperationResult(int itemIdx) {
    const auto &item = getResponseItem(itemIdx);
    return OperationResult{
        effectiveOperation(item),
        item.getResultStatus(),
        get_result_reason_or_default(item),
        item.getResultMessage().value_or("")
    };
  }

  OperationResult
      ResponseParser::getOperationResultByBatchItemId(uint32_t batchItemId) {
    const auto &item = getResponseItemByBatchItemId(batchItemId);
    return OperationResult{
        effectiveOperation(item, batchItemId),
        item.getResultStatus(),
        get_result_reason_or_default(item),
        item.getResultMessage().value_or("")
    };
  }

  void ResponseParser::parseResponse() {
    if (responseBytes_.empty()) {
      throw KmipException("Empty response from the server.");
    }

    size_t offset = 0;
    auto root = Element::deserialize(
        std::span<const uint8_t>(responseBytes_.data(), responseBytes_.size()),
        offset
    );  // NOLINT(cppcoreguidelines-pro-bounds-pointer-arithmetic)
    if (offset != responseBytes_.size()) {
      throw KmipException("Trailing bytes found after KMIP response message.");
    }

    responseMessage_ = ResponseMessage::fromElement(root);
    isParsed_ = true;
  }

  const ResponseBatchItem &ResponseParser::getResponseItem(int itemIdx) {
    ensureParsed();

    const auto &items = responseMessage_.getBatchItems();
    if (items.empty()) {
      throw KmipException("No response batch items from the server.");
    }
    if (itemIdx < 0 || static_cast<size_t>(itemIdx) >= items.size()) {
      throw KmipException("Response batch item index is out of range.");
    }

    return items[static_cast<size_t>(itemIdx)];
  }

  const ResponseBatchItem &
      ResponseParser::getResponseItemByBatchItemId(uint32_t batchItemId) {
    ensureParsed();

    const auto &items = responseMessage_.getBatchItems();

    // Primary: match by the echoed Unique Batch Item Id.
    for (const auto &item : items) {
      if (item.getUniqueBatchItemId() == batchItemId) {
        return item;
      }
    }

    // Fallback: some servers (e.g. pyKMIP in multi-batch mode) do not echo
    // batch item IDs back.  Use the 0-based position in the request batch
    // (stored at construction time) to locate the correct response item.
    if (!batchItemPositions_.empty()) {
      const auto it = batchItemPositions_.find(batchItemId);
      if (it != batchItemPositions_.end()) {
        const size_t pos = it->second;
        if (pos < items.size()) {
          return items[pos];
        }
      }
    }

    throw KmipException("Response batch item id was not found.");
  }

  void ResponseParser::ensureSuccess(
      const ResponseBatchItem &item,
      std::optional<uint32_t> requestedBatchItemId
  ) {
    if (item.getResultStatus() != KMIP_STATUS_SUCCESS) {
      const KmipResultReasonCode reason = get_result_reason_or_default(item);
      throw KmipException(
          reason,
          formatOperationResult(
              item, effectiveOperation(item, requestedBatchItemId)
          )
      );
    }
  }

  std::string ResponseParser::formatOperationResult(
      const ResponseBatchItem &value, int32_t operation
  ) {
    OperationResult result = {
        operation,
        value.getResultStatus(),
        get_result_reason_or_default(value),
        value.getResultMessage().value_or("")
    };

    std::ostringstream stream;
    stream << "Message: " << result.resultMessage
           << "\nOperation: " << operationToString(result.operation)
           << "; Result status: " << resultStatusToString(result.resultStatus)
           << "; Result reason: "
           << kmip_category().message(result.resultReason) << " ("
           << result.resultReason << ")";
    return stream.str();
  }

  const char *ResponseParser::operationToString(int32_t operation) {
    return kmipcore::operation_to_string(operation);
  }

  const char *ResponseParser::resultStatusToString(int32_t status) {
    switch (status) {
      case KMIP_STATUS_SUCCESS:
        return "Success";
      case KMIP_STATUS_OPERATION_FAILED:
        return "Operation Failed";
      case KMIP_STATUS_OPERATION_PENDING:
        return "Operation Pending";
      case KMIP_STATUS_OPERATION_UNDONE:
        return "Operation Undone";
      default:
        return "Unknown";
    }
  }

}  // namespace kmipcore
