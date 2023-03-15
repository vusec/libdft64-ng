// Modified from https://github.com/joaomlneto/procmap
#ifndef PROCMAP_MEMORY_MAP
#define PROCMAP_MEMORY_MAP

#include "memory_segment.h"

namespace procmap {

class memory_map : private std::vector<memory_segment> {
 public:
  memory_map();
  void print();
  void print_json(std::string application_corepath);

  //allowed methods from std::vector
  using vector::operator[];
  using vector::begin;
  using vector::end;

};

}  // namespace procmap

#endif  // PROCMAP_MEMORY_MAP
