#ifndef KMIPCORE_KMIP_LOGGER_HPP
#define KMIPCORE_KMIP_LOGGER_HPP

#include <string>
#include <string_view>

namespace kmipcore {

  /** @brief Log severity levels used by KMIP protocol logging. */
  enum class LogLevel { Debug, Info, Warning, Error };

  /** @brief Structured log record emitted by KMIP components. */
  struct LogRecord {
    LogLevel level = LogLevel::Debug;
    std::string component;
    std::string event;
    std::string message;
  };

  /** @brief Converts a log level enum to uppercase text label. */
  [[nodiscard]] inline std::string_view to_string(LogLevel level) {
    switch (level) {
      case LogLevel::Debug:
        return "DEBUG";
      case LogLevel::Info:
        return "INFO";
      case LogLevel::Warning:
        return "WARNING";
      case LogLevel::Error:
        return "ERROR";
      default:
        return "UNKNOWN";
    }
  }

  /** @brief Abstract logger sink interface used by kmipcore/kmipclient. */
  class Logger {
  public:
    /** @brief Virtual destructor for interface-safe cleanup. */
    virtual ~Logger() = default;

    /** @brief Returns whether a record at @p level should be emitted. */
    [[nodiscard]] virtual bool shouldLog(LogLevel level) const = 0;
    /** @brief Emits one log record. */
    virtual void log(const LogRecord &record) = 0;
  };

  /** @brief Logger implementation that drops all records. */
  class NullLogger final : public Logger {
  public:
    /** @brief Always returns false because logging is disabled. */
    [[nodiscard]] bool shouldLog(LogLevel) const override { return false; }
    /** @brief No-op sink implementation. */
    void log(const LogRecord &) override {}
  };

}  // namespace kmipcore

#endif /* KMIPCORE_KMIP_LOGGER_HPP */
