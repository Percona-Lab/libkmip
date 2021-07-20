

//struct SSL_CTX; // SSL
//struct SSL; // SSL
//struct BIO; // SSL
//struct KMIP; // KMIP

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
extern "C" {
#include "kmip.h"
}

#include <memory>
#include <cstdint>
#include <vector>
#include <string>

namespace kmippp {
  
  class context {
    public:

      using key_t = std::vector<unsigned char>;
      using id_t = std::string;
      using ids_t = std::vector<std::string>;
      using name_t = std::string;

      context(std::string server_address, std::string server_port, std::string client_cert_fn, std::string client_key_fn, std::string ca_cert_fn);
      ~context();

      context(context &&) noexcept = default;
      context(context const&) = delete;

      context& operator=(context&&) noexcept = default;
      context& operator=(context const&) = delete;

      // KMIP::create operation, generates a new AES symmetric key on the server
      id_t op_create(name_t name, name_t group);

      // KMIP::register operation, stores an existing symmetric key on the server
      id_t op_register(name_t name, name_t group, key_t k);

      // KMIP::get operation, retrieve a symmetric key by id
      key_t op_get(id_t id);

      // KMIP::get_attribute operation, retrieve the name of a symmetric key by id
      name_t op_get_name_attr(id_t id);

      // KMIP::locate operation, retrieve symmetric keys by name
      // note: name can be empty, and will retrieve all keys
      ids_t op_locate(name_t name);

      ids_t op_locate_by_group(name_t group);

      // KMIP::locate operation, retrieve all symmetric keys
      // note: name can be empty, and will retrieve all keys
      ids_t op_all();

    private:
      SSL_CTX *ctx_ = nullptr;
      BIO* bio_;
      KMIP kmip_context;
      uint8_t* encoding;
  };

}
