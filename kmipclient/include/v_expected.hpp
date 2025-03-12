//
// Created by al on 18.03.25.
//
#ifndef MY_EXPECTED_HPP
#define MY_EXPECTED_HPP

#if __cplusplus < 202302L // Check if the C++ standard is less than C++23
#include <functional>
#include <optional>
#include <stdexcept>
#include <utility>

namespace ve
{

template <typename T, typename E> class expected
{
private:
  std::optional<T> value_;
  std::optional<E> error_;

public:
  expected () = default;

  expected (const T &val) : value_ (val) {}
  expected (T &&val) : value_ (std::move (val)) {}

  expected (const E &err) : error_ (err) {}
  expected (E &&err) : error_ (std::move (err)) {}

  expected (const expected &other) = default;
  expected (expected &&other)      = default;

  expected &operator= (const expected &other) = default;
  expected &operator= (expected &&other)      = default;

  [[nodiscard]] bool
  has_value () const
  {
    return value_.has_value ();
  }

  [[nodiscard]] bool
  has_error () const
  {
    return error_.has_value ();
  }

  [[nodiscard]] const T &
  value () const
  {
    if (!has_value ())
      {
        throw std::bad_optional_access (); // Or a custom exception
      }
    return *value_;
  }

  [[nodiscard]] T &
  value ()
  {
    if (!has_value ())
      {
        throw std::bad_optional_access (); // Or a custom exception
      }
    return *value_;
  }

  [[nodiscard]] const E &
  error () const
  {
    if (!has_error ())
      {
        throw std::logic_error ("Accessing error of an expected that holds a value");
      }
    return *error_;
  }

  [[nodiscard]] E &
  error ()
  {
    if (!has_error ())
      {
        throw std::logic_error ("Accessing error of an expected that holds a value");
      }
    return *error_;
  }

  template <typename F>
  [[nodiscard]] auto
  and_then (F func) const
  {
    if (has_value ())
      {
        return func (value ());
      }
    else
      {
        return expected<std::invoke_result_t<F, const T &>, E> (error ());
      }
  }

  template <typename F>
  [[nodiscard]] auto
  or_else (F func) const
  {
    if (has_error ())
      {
        return func (error ());
      }
    else
      {
        return expected<T, std::invoke_result_t<F, const E &> > (value ());
      }
  }

  template <typename U>
  [[nodiscard]] expected<U, E>
  transform (auto func) const
  {
    if (has_value ())
      {
        return expected<U, E> (func (value ()));
      }
    else
      {
        return expected<U, E> (error ());
      }
  }

  template <typename F>
  [[nodiscard]] auto
  transform_error (F func) const -> expected<T, std::invoke_result_t<F, const E &> >
  {
    if (has_error ())
      {
        return expected<T, std::invoke_result_t<F, const E &> > (std::invoke (func, error ()));
      }
    else
      {
        return expected<T, std::invoke_result_t<F, const E &> > (value ());
      }
  }

  // Add more functionalities as needed, like `value_or`, implicit conversions, etc.
};

} // namespace ve

#else // C++23 or later
#include <functional>
#include <optional>
#include <stdexcept>
#include <utility>

namespace ve
{

template <typename T, typename E> class expected
{
private:
  std::optional<T> value_;
  std::optional<E> error_;

public:
  expected () = default;

  expected (const T &val) : value_ (val) {}
  expected (T &&val) : value_ (std::move (val)) {}

  expected (const E &err) : error_ (err) {}
  expected (E &&err) : error_ (std::move (err)) {}

  expected (const expected &other) = default;
  expected (expected &&other)      = default;

  expected &operator= (const expected &other) = default;
  expected &operator= (expected &&other)      = default;

  [[nodiscard]] bool
  has_value () const
  {
    return value_.has_value ();
  }

  [[nodiscard]] bool
  has_error () const
  {
    return error_.has_value ();
  }

  [[nodiscard]] const T &
  value () const
  {
    if (!has_value ())
      {
        throw std::bad_optional_access (); // Or a custom exception
      }
    return *value_;
  }

  [[nodiscard]] T &
  value ()
  {
    if (!has_value ())
      {
        throw std::bad_optional_access (); // Or a custom exception
      }
    return *value_;
  }

  [[nodiscard]] const E &
  error () const
  {
    if (!has_error ())
      {
        throw std::logic_error ("Accessing error of an expected that holds a value");
      }
    return *error_;
  }

  [[nodiscard]] E &
  error ()
  {
    if (!has_error ())
      {
        throw std::logic_error ("Accessing error of an expected that holds a value");
      }
    return *error_;
  }

  template <typename F>
  [[nodiscard]] auto
  and_then (F func) const
  {
    if (has_value ())
      {
        return func (value ());
      }
    else
      {
        return expected<std::invoke_result_t<F, const T &>, E> (error ());
      }
  }

  template <typename F>
  [[nodiscard]] auto
  or_else (F func) const
  {
    if (has_error ())
      {
        return func (error ());
      }
    else
      {
        return expected<T, std::invoke_result_t<F, const E &> > (value ());
      }
  }

  template <typename U>
  [[nodiscard]] expected<U, E>
  transform (auto func) const
  {
    if (has_value ())
      {
        return expected<U, E> (func (value ()));
      }
    else
      {
        return expected<U, E> (error ());
      }
  }

  template <typename F>
  [[nodiscard]] auto
  transform_error (F func) const -> expected<T, std::invoke_result_t<F, const E &> >
  {
    if (has_error ())
      {
        return expected<T, std::invoke_result_t<F, const E &> > (std::invoke (func, error ()));
      }
    else
      {
        return expected<T, std::invoke_result_t<F, const E &> > (value ());
      }
  }

  // Add more functionalities as needed, like `value_or`, implicit conversions, etc.
};

} // namespace ve

#endif // __cplusplus < 202302L

#endif // MY_EXPECTED_HPP