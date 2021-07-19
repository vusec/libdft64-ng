#ifndef LIBDFT_TAG_TRAITS_H
#define LIBDFT_TAG_TRAITS_H

#include <string>
#include "config.h"

template <typename T> struct tag_traits {};
template <typename T> T tag_combine(T const &lhs, T const &rhs);
template <typename T> std::string tag_sprint(T const &tag);
template <typename T> T tag_alloc(ptroff_t offset);

template <typename T> unsigned int tag_to_id(T const &tag) {
  return (unsigned int) tag;
}

template <typename T> bool tag_is_empty(T const &tag) {
  return tag == tag_traits<T>::cleared_val;
}

/********************************************************
 uint8_t tags
 ********************************************************/
typedef uint8_t libdft_tag_uint8;

template <> struct tag_traits<unsigned char> {
  typedef uint8_t type;
  static const uint8_t cleared_val = 0;
  static const uint8_t file_len_val = 1;
};

template <> uint8_t tag_combine(uint8_t const &lhs, uint8_t const &rhs);
template <> std::string tag_sprint(uint8_t const &tag);
template <> uint8_t tag_alloc<uint8_t>(ptroff_t offset);
// template <> uint8_t tag_get<uint8_t>(uint8_t);

/********************************************************
tag set tags
********************************************************/
#include "./bdd_tag.h"

typedef lb_type libdft_bdd_tag;

template <> struct tag_traits<lb_type> {
  typedef lb_type type;
  static lb_type cleared_val;
  static lb_type file_len_val;
};

template <> lb_type tag_combine(lb_type const &lhs, lb_type const &rhs);
// template <> void tag_combine_inplace(lb_type &lhs, lb_type const &rhs);
template <> std::string tag_sprint(lb_type const &tag);
template <> lb_type tag_alloc<lb_type>(ptroff_t offset);

std::vector<tag_seg> tag_get(lb_type);

/********************************************************
small set tags
********************************************************/
typedef struct SmallSet
{
  /*
   * Values at the end of the 32-bit range are always left
   * up for grabs for FULL, etc. This is regardless of the
   * particular configuration used.
   */
  static const ptroff_t EMPTY = 0;
  static const ptroff_t LEN = ((1UL<<32)-1);
  static const ptroff_t FULL = LEN-1;
  static const unsigned MAX_TAGS = LIBDFT_TAG_SSET_MAX;

  ptroff_t tags[MAX_TAGS];
} sset_tag_t;

template <>
struct tag_traits<sset_tag_t>
{
  typedef sset_tag_t type;
  static const sset_tag_t cleared_val;
  static const sset_tag_t file_len_val;
  static const sset_tag_t full_val;
};

template <>
sset_tag_t tag_combine(sset_tag_t const &lhs, sset_tag_t const &rhs);
template <>
std::string tag_sprint(sset_tag_t const &tag);
template <>
sset_tag_t tag_alloc<sset_tag_t>(ptroff_t offset);

inline unsigned int tag_to_id(sset_tag_t const &tag)
{
  return (unsigned int) tag.tags[0];
}

inline bool tag_is_empty(sset_tag_t const &tag)
{
  return tag.tags[0] == sset_tag_t::EMPTY;
}

inline bool tag_is_full(sset_tag_t const &tag)
{
  return tag.tags[0] == sset_tag_t::FULL;
}

inline bool tag_hasn(sset_tag_t const &tag, unsigned int n)
{
  return n < sset_tag_t::MAX_TAGS && tag.tags[n] != sset_tag_t::EMPTY;
}

inline ptroff_t tag_getn(sset_tag_t const &tag, unsigned int n)
{
  return tag.tags[n];
}

inline void tag_setn(sset_tag_t &tag, unsigned int n, ptroff_t &val)
{
  tag.tags[n] = val;
}

typedef sset_tag_t libdft_sset_tag;

/********************************************************
configured tag type
********************************************************/
typedef LIBDFT_TAG_TYPE tag_t;

#endif /* LIBDFT_TAG_TRAITS_H */
