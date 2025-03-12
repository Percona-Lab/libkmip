//
// Created by al on 25.03.25.
//

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
  virtual const char *
  what ()
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
