//
// Created by al on 09.04.25.
//

#ifndef LOGGER_HPP
#define LOGGER_HPP
#include <string>
class Logger
{
public:
  Logger ()                                     = default;
  virtual ~Logger ()                            = default;
  Logger (const Logger &other)                  = delete;
  Logger &operator= (const Logger &other)       = delete;
  Logger (Logger &&other)                       = delete;
  Logger      &operator= (Logger &&other)       = delete;
  virtual void log (int level, std::string msg) = 0;
};
#endif // LOGGER_HPP
