/* Copyright (c) 2025 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef KMIP_LOGGER_HPP
#define KMIP_LOGGER_HPP

#include <string>

namespace kmipclient
{
enum LogLevel
{
  TRACE = 0,
  DEBUG,
  INFO,
  WARNING,
  ERROR,
  SEVERE
};
/**
 * Interface for logger
 */
class Logger
{
public:
  Logger ()                                               = default;
  virtual ~Logger ()                                      = default;
  Logger (const Logger &other)                            = delete;
  Logger &operator= (const Logger &other)                 = delete;
  Logger (Logger &&other)                                 = delete;
  Logger      &operator= (Logger &&other)                 = delete;
  virtual void log (LogLevel level, std::string_view msg) = 0;
};
}
#endif // KMIP_LOGGER_HPP
