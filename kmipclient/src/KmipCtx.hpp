//
// Created by al on 21.03.25.
//

#ifndef KMIPCTX_HPP
#define KMIPCTX_HPP

#include "kmip.h"
#include <format>

#include <cstring>
#include <string>

namespace kmipclient
{

class KmipCtx
{
public:
  /**
   * Initializes KMIP context with default version 1.4
   */
  KmipCtx () : KmipCtx (KMIP_1_4) {};
  /**
   * Initializes KMIP context with version
   */
  explicit KmipCtx (enum kmip_version version)
  {
    kmip_init (&m_ctx, nullptr, 0, version);
    alloc_buffer ();
  };
  /**
   * Destroys KMIP context
   */
  ~KmipCtx ()
  {
    free_buffer ();
    kmip_destroy (&m_ctx);
  };
  /**
   * get raw KMIP ctx pointer
   * @return raw KMIP ctx pointer
   */
  // no copy, no move
  KmipCtx (const KmipCtx &other)                = delete;
  KmipCtx (KmipCtx &&other) noexcept            = delete;
  KmipCtx &operator= (const KmipCtx &other)     = delete;
  KmipCtx &operator= (KmipCtx &&other) noexcept = delete;

  KMIP                     *get ();
  void                      increase_buffer ();
  void                      alloc_buffer ();
  void                      alloc_buffer (size_t buf_size);
  void                      free_buffer ();
  void                      set_buffer (uint8_t *buf, size_t buffer_total_size);
  [[nodiscard]] std::string get_errors () const;

  template <typename T>
  [[nodiscard]] T *
  allocate ()
  {
    return static_cast<T *> (m_ctx.calloc_func (m_ctx.state, 1, sizeof (T)));
  }

  void free (void *p) const;

  TextString *from_string (const std::string &str);

private:
  int       buffer_blocks     = 1;
  const int buffer_block_size = 1024;
  KMIP      m_ctx{};
};

inline KMIP *
KmipCtx::get ()
{
  return &m_ctx;
};

void inline KmipCtx::free (void *p) const { m_ctx.free_func (m_ctx.state, p); }

void inline KmipCtx::increase_buffer ()
{
  uint8 *encoding = m_ctx.buffer;

  kmip_reset (&m_ctx);
  m_ctx.free_func (m_ctx.state, encoding);

  buffer_blocks += 1;
  int buffer_total_size = buffer_blocks * buffer_block_size;

  encoding = static_cast<uint8_t *> (m_ctx.calloc_func (m_ctx.state, buffer_blocks, buffer_block_size));
  if (encoding == nullptr)
    {
      kmip_destroy (&m_ctx);
      throw std::bad_alloc ();
    }

  kmip_set_buffer (&m_ctx, encoding, buffer_total_size);
}

void inline KmipCtx::alloc_buffer (size_t buf_size)
{
  auto *buffer = static_cast<uint8_t *> (m_ctx.calloc_func (m_ctx.state, 1, buf_size));
  if (buffer == nullptr)
    {
      kmip_destroy (&m_ctx);
      throw std::bad_alloc ();
    }
  m_ctx.memset_func (buffer, 0, buf_size);
  kmip_set_buffer (&m_ctx, buffer, buf_size);
}

void inline KmipCtx::alloc_buffer ()
{
  int   buffer_total_size = buffer_blocks * buffer_block_size;
  auto *buffer            = static_cast<uint8_t *> (m_ctx.calloc_func (m_ctx.state, buffer_blocks, buffer_block_size));
  if (buffer == nullptr)
    {
      kmip_destroy (&m_ctx);
      throw std::bad_alloc ();
    }
  m_ctx.memset_func (buffer, 0, buffer_total_size);
  kmip_set_buffer (&m_ctx, buffer, buffer_total_size);
}

void inline KmipCtx::free_buffer ()
{
  kmip_free_buffer (&m_ctx, m_ctx.buffer, m_ctx.size);
  kmip_set_buffer (&m_ctx, nullptr, 0);
  buffer_blocks = 1;
}

void inline KmipCtx::set_buffer (uint8_t *buf, size_t buffer_total_size)
{
  free_buffer ();
  kmip_set_buffer (&m_ctx, buf, buffer_total_size);
}

std::string inline KmipCtx::get_errors () const
{
  std::string errors;
  ErrorFrame *index = m_ctx.frame_index;
  do
    {
      errors.append (std::format ("- %s @ line: %d\n", index->function, index->line));
    }
  while (index-- != m_ctx.errors);

  return errors;
}

inline TextString *
KmipCtx::from_string (const std::string &str)
{
  auto res   = allocate<TextString> ();
  res->size  = str.size ();
  res->value = static_cast<char *> (m_ctx.calloc_func (m_ctx.state, 1, res->size));
  strncpy (res->value, str.c_str (), res->size);
  return res;
}

};

#endif // KMIPCTX_HPP
