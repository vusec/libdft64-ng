#include "pin.H"
#include "tag_traits.h"
#include "tagmap.h"
#include <string.h>

static bool tag_trait_sprint_decimal = false;
void tag_trait_set_print_decimal(bool b) { tag_trait_sprint_decimal = b; }

void tag_sprint_ptroff(std::stringstream &ss, ptroff_t const &v) {
  if (v == sset_tag_t::LEN) {
    ss << "LEN";
    return;
  }
  if (tag_trait_sprint_decimal) {
    if (tag_is_file_offset(v)) ss << "+" << std::dec << v;
    else ss << std::dec << (uint64_t) tag_to_ptr(v);
    return;
  }
  ss << std::hex << std::setfill('0');
#ifdef LIBDFT_TAG_PTR
  extern void* tag_to_ptr(ptroff_t);
  extern bool tag_is_file_offset(ptroff_t);
  if (tag_is_file_offset(v))
    ss << "+0x" << std::setw(8) << v;
  else
    ss << "0x" << std::setw(12) << (uint64_t) tag_to_ptr(v);
#else
  ss << "+0x" << std::setw(8) << v;
#endif
}

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
    return "[]";
  else if (tag_is_full(tag))
    return "\"FULL\"";

  std::stringstream ss;
  ss << "[";
  tag_sprint_ptroff(ss, tag_getn(tag, 0));
  for (int i = 1; tag_hasn(tag, i); i++)
  {
    ss << ", ";
    tag_sprint_ptroff(ss, tag_getn(tag, i));
  }
  ss << "]";

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

/********************************************************
tag arrays (q => 8 bytes, n => n bytes)
********************************************************/

bool tagqarr_is_empty(tagqarr_t const &tarr)
{
  for (size_t i = 0; i < tarr.TAGQARR_LEN; i++) {
    if (!tag_is_empty(tarr.tags[i])) return false;
  }
  return true;
}

// Only checks the bottom 4 bytes of the tagqarr_t (rather than all 8)
bool tagdarr_is_empty(tagqarr_t const &tarr)
{
  for (size_t i = 0; i < tarr.TAGDARR_LEN; i++) {
    if (!tag_is_empty(tarr.tags[i])) return false;
  }
  return true;
}

std::string tagqarr_sprint(tagqarr_t const &tarr)
{
  std::stringstream ss;
  tag_t t = tarr.tags[0];
  ss << "[" << tag_sprint(t);
  for (size_t i = 1; i < tarr.TAGQARR_LEN; i++) ss << ", " << tag_sprint(tarr.tags[i]);
  ss << "]";

  return ss.str();
}

// Only logs the bottom 4 bytes of the tagqarr_t (rather than all 8)
std::string tagdarr_sprint(tagqarr_t const &tarr)
{
  std::stringstream ss;
  tag_t t = tarr.tags[0];
  ss << "[" << tag_sprint(t);
  for (size_t i = 1; i < tarr.TAGDARR_LEN; i++) ss << ", " << tag_sprint(tarr.tags[i]);
  ss << "]";

  return ss.str();
}

std::string tagn_sprint(ADDRINT addr, size_t len)
{
  std::string s = "[" + tag_sprint(tagmap_getb(addr));
  for (size_t i = 1; i < len; i++)
    s += ", " + tag_sprint(tagmap_getb(addr + i));
  s += "]";
  return s;
}