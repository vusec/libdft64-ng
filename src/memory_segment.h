// Modified from https://github.com/joaomlneto/procmap
#ifndef PROCMAP_MEMORY_SEGMENT
#define PROCMAP_MEMORY_SEGMENT

#include <stdlib.h>
#include <string>
#include <vector>
#include <unistd.h>
#include "debug.h"

#define DIEIF(expr, msg) \
  do {\
    if (expr) {\
      LOG_ERR(msg);\
    }\
  } while (0)

namespace procmap {

class memory_segment {
  void*         _startAddress;
  void*         _endAddress;
  unsigned long _offset;
  unsigned int  _deviceMajor;
  unsigned int  _deviceMinor;
  ino_t         _inode;
  unsigned char _permissions;
	std::string   _name;

 public:
  memory_segment(char *unparsed_line);
  // getters
  void* startAddress();
  void* endAddress();
  bool contains_addr(void * addr);
  std::string name();
  size_t length();
  dev_t device();
  // getters for the permissions bitmask
  bool isReadable();
  bool isWriteable();
  bool isExecutable();
  bool isShared();
  bool isPrivate();
  // other functions
  bool isBindable();
  bool isAnonymous();
  bool isHeap();
  bool isStack();
  void print();
};

}  // namespace procmap

#endif  // PROCMAP_MEMORY_SEGMENT
