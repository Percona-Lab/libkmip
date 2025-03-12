//
// Created by al on 01.04.25.
//

#ifndef KEY_HPP
#define KEY_HPP
#include <utility>

#include "include/v_expected.hpp"
#include "kmip_data_types.hpp"

namespace kmipclient
{

class KeyFactory;

// TODO: should I expose kmip.h types here in the public interface?

enum KeyType
{
  KEY_TYPE_PRIVATE_KEY,
  KEY_TYPE_PUBLIC_KEY,
  KEY_TYPE_SYMMETRIC_KEY,
  KEY_TYPE_CERTIFICATE,
  KEY_TYPE_OTHER
};

enum KeyAlgorithm
{
  KEY_ALGORITHM_AES,
  KEY_ALGORITHM_RSA,
  KEY_ALGORITHM_EC,
};

class Key
{
  friend class KeyFactory;

public:
  explicit Key (key_t value, KeyType type, KeyAlgorithm algo, attributes_t attributes)
      : key_value (std::move (value)), key_attributes (std::move (attributes)), key_type (type),
        cryptographic_algorithm (algo) {};

  const key_t &
  value ()
  {
    return key_value;
  };
  const attributes_t &
  attributes ()
  {
    return key_attributes;
  };

  KeyType
  type () const
  {
    return key_type;
  };
  KeyAlgorithm
  algorithm () const
  {
    return cryptographic_algorithm;
  };

  static ve::expected<Key, Error> aes_from_hex (std::string hex);
  static ve::expected<Key, Error> aes_from_base64 (std::string hex);
  /**
   *  Reads a PEM-formatted string, decides what type of key it has
   *  (X.509 certificate, public key, private key) and creates the
   *  Key instance from it.
   * @param pem PEM-formatted string
   * @return Key of corresponding type
   */
  static ve::expected<Key, Error> from_PEM (std::string pem);

private:
  key_t        key_value;
  attributes_t key_attributes;
  KeyType      key_type;
  KeyAlgorithm cryptographic_algorithm;
};
}

#endif // KEY_HPP
