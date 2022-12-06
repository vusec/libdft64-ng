// Modified from https://github.com/joaomlneto/procmap
#include "memory_segment.h"

namespace procmap {

memory_segment::memory_segment(char *line) {
  int name_start = 0, name_end = 0;
  unsigned long addr_start, addr_end;
  char perms_str[8];
  //LOG_OUT("line: %s", line);

  // parse string
  int ret = sscanf(line, "%lx-%lx %7s %lx %x:%x %lu %n%*[^\n]%n",
                     &addr_start, &addr_end, perms_str, &_offset,
                     &_deviceMajor, &_deviceMinor, &_inode,
                     &name_start, &name_end);
  if (ret < 7) {
    LOG_ERR("%s:%d: Error parsing. Expected >=7 but got %d. Line: %s",
        __FILE__, __LINE__, ret, line);
    return; // ¯\_(ツ)_/¯
  }

  // convert addresses
  _startAddress = reinterpret_cast<void*>(addr_start);
  _endAddress = reinterpret_cast<void*>(addr_end);

  // copy permissions
  _permissions = 0U;
  if (strchr(perms_str, 'r'))
    _permissions |= 1U << 0;
  if (strchr(perms_str, 'w'))
    _permissions |= 1U << 1;
  if (strchr(perms_str, 'x'))
    _permissions |= 1U << 2;
  if (strchr(perms_str, 's'))
    _permissions |= 1U << 3;
  if (strchr(perms_str, 'p'))
    _permissions |= 1U << 4;

  // copy name
  if (name_end > name_start) {
    line[name_end] = '\0';
    _name.assign(&line[name_start]);
  }
}

void* memory_segment::startAddress() {
  return _startAddress;
}

void* memory_segment::endAddress() {
  return _endAddress;
}

std::string memory_segment::name() {
  return _name;
}

size_t memory_segment::length() {
  return ((char*)_endAddress) - ((char*)_startAddress);
}

dev_t memory_segment::device() {
  return makedev(_deviceMajor, _deviceMinor);
}

bool memory_segment::isReadable() {
  return (_permissions & 1U) != 0;
}

bool memory_segment::isWriteable() {
  return (_permissions & 2U) != 0;
}

bool memory_segment::isExecutable() {
  return (_permissions & 4U) != 0;
}

bool memory_segment::isShared() {
  return (_permissions & 8U) != 0;
}

bool memory_segment::isPrivate() {
  return (_permissions & 16U) != 0;
}

void memory_segment::print() {
  char info[1024];
  snprintf(info, sizeof(info),
           "[%18p-%18p] (%5lu pages) [off=%7lu] [dev=%u:%u] [inode=%8lu] %c%c%c%c '%s'",
           _startAddress, _endAddress,
           length() / sysconf(_SC_PAGESIZE),
           _offset,
           _deviceMajor, _deviceMinor,
           _inode,
           (isPrivate() ?    'P' : 'S'),
           (isExecutable() ? 'X' : '-'),
           (isWriteable() ?  'W' : '-'),
           (isReadable() ?   'R' : '-'),
           _name.c_str());
  LOG_OUT("%s\n", info);
}

bool memory_segment::isBindable() {
  return name() != "[vsyscall]";
}

bool memory_segment::isHeap() {
  return name() == "[heap]";
}

bool memory_segment::isStack() {
  return name() == "[stack]";
}

bool memory_segment::isAnonymous() {
  return name().length() == 0;
}

}  // namespace procmap
