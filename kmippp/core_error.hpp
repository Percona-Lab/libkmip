/* Copyright (c) 2022 Percona LLC and/or its affiliates. All rights reserved.

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
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef KMIPPP_CORE_ERROR_HPP
#define KMIPPP_CORE_ERROR_HPP

#include <stdexcept>
#include <string>

namespace kmippp {

class core_error : public std::runtime_error {
 public:
  explicit core_error(const char *message) : std::runtime_error{message} {}
  explicit core_error(const std::string &message) : std::runtime_error{message} {}

  [[noreturn]] static void raise_with_error_string(
      const std::string &prefix = std::string());
};

}  // namespace kmippp

#endif
