#include "pin.H"
#include "tag_traits.h"
#include <string.h>

/********************************************************
 uint8_t tags
 ********************************************************/
template <> uint8_t tag_combine(uint8_t const &lhs, uint8_t const &rhs) {
  return lhs | rhs;
}

template <> std::string tag_sprint(uint8_t const &tag) {
  std::stringstream ss;
  ss << tag;
  return ss.str();
}

template <> uint8_t tag_alloc<uint8_t>(ptroff_t offset) {
  return offset > 0;
}

/********************************************************
tag set tags
********************************************************/

BDDTag bdd_tag;
lb_type tag_traits<lb_type>::cleared_val = 0;
lb_type tag_traits<lb_type>::file_len_val = BDD_LEN_LB;

template <> lb_type tag_combine(lb_type const &lhs, lb_type const &rhs) {
  return bdd_tag.combine(lhs, rhs);
}

template <> std::string tag_sprint(lb_type const &tag) {
  return bdd_tag.to_string(tag);
}

template <> lb_type tag_alloc<lb_type>(ptroff_t offset) {
  return bdd_tag.insert(offset);
}

std::vector<tag_seg> tag_get(lb_type t) { return bdd_tag.find(t); }
/********************************************************
small set tags
********************************************************/

const sset_tag_t tag_traits<sset_tag_t>::cleared_val = {};
const sset_tag_t tag_traits<sset_tag_t>::file_len_val = { .tags = { sset_tag_t::LEN } };
const sset_tag_t tag_traits<sset_tag_t>::full_val =  { .tags = { sset_tag_t::FULL } };

template <>
sset_tag_t tag_combine(sset_tag_t const &lhs, sset_tag_t const &rhs)
{
  if (tag_is_empty(lhs))
    return rhs;
  if (tag_is_empty(rhs))
    return lhs;
  if (tag_is_full(lhs) || tag_is_full(rhs))
    return tag_traits<sset_tag_t>::full_val;

  sset_tag_t tag = lhs;
  unsigned l, r;
  ptroff_t rval, lval;
  for (r = 0; tag_hasn(rhs, r); r++)
  {
    rval = tag_getn(rhs, r);
    lval = sset_tag_t::EMPTY;
    for (l = 0; tag_hasn(tag, l); l++)
    {
      lval = tag_getn(tag, l);
      if (lval == rval)
        break;
    }
    if (l >= sset_tag_t::MAX_TAGS)
      return tag_traits<sset_tag_t>::full_val;
    if (lval != rval)
      tag_setn(tag, l, rval);
  }

  return tag;
}

template <>
std::string tag_sprint(sset_tag_t const &tag)
{
  if (tag_is_empty(tag))
    return "{}";
  else if (tag_is_full(tag))
    return "FULL";

  std::stringstream ss;
  ss << "{";
  ss << tag_getn(tag, 0);
  for (int i = 1; tag_hasn(tag, i); i++)
  {
    ss << ", ";
    ss << tag_getn(tag, i);
  }
  ss << "}";

  return ss.str();
}

template <>
sset_tag_t tag_alloc<sset_tag_t>(ptroff_t offset)
{
  sset_tag_t tag = tag_traits<sset_tag_t>::cleared_val;
  ptroff_t val = (ptroff_t)offset;
  tag_setn(tag, 0, val);
  return tag;
}
