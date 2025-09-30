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

#ifndef KMIP_EXCEPTIONS_HPP
#define KMIP_EXCEPTIONS_HPP

#include <exception>
#include <string>

namespace kmipclient
{

class ErrorException : public std::exception
{
public:
  explicit ErrorException (int code, std::string msg) : message (std::move (msg)) { kmip_code = code; };
  explicit ErrorException (std::string msg) : message (std::move (msg)) { kmip_code = -1; };
  [[nodiscard]] const char *
  what () const noexcept override
  {
    return message.c_str ();
  };
  [[nodiscard]] int
  code () const
  {
    return kmip_code;
  };

private:
  std::string message;
  int         kmip_code;
};

}
#endif // KMIP_EXCEPTIONS_HPP
