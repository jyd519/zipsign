/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/. */

#include "zipsign/file.hpp"
#include "zipsign/ftruncate.h"
#include "openssl++/exception.hpp"
#include <stdexcept>
#if defined(_WIN32)
#include <windows.h>
#include <io.h>
#include <vector>
#else
#endif

#include <sys/stat.h>
#include <sys/types.h>

#ifdef _WIN32
static std::wstring Utf8ToUtf16(const std::string& str) {
  std::wstring convertedString;
  int requiredSize = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, 0, 0);
  if (requiredSize > 0) {
    std::vector<wchar_t> buffer(requiredSize);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &buffer[0], requiredSize);
    convertedString.assign(buffer.begin(), buffer.end() - 1);
  }
  return convertedString;
}
#endif

namespace zipsign {

FILE* xfopen(const char* filename, const char* mode) {
#ifdef _WIN32
  auto wpath = Utf8ToUtf16(filename);
  auto wmode = Utf8ToUtf16(mode);
  return _wfopen(wpath.c_str(), wmode.c_str());
#else
  return fopen(filename, mode);
#endif
}

void File::remove(std::string const& filename) {
#ifdef _WIN32
  _wunlink(Utf8ToUtf16(filename).c_str());
#else
  unlink(filename.c_str());
#endif
}

File::File(std::string const& name, std::string const& mode) {
  file = xfopen(name.c_str(), mode.c_str());
  if (nullptr == file) {
    throw openssl::FileNotFoundException(name);
  }
}

File::~File() {
  fclose(file);
}

void File::seek(long offset, int whence) {
  int rc = fseek(file, offset, whence);
  if (0 != rc) {
    throw std::runtime_error("fseek failed");
  }
}

long File::tell() {
  return ftell(file);
}

void File::write(void const* buffer, size_t count) {
  size_t written = fwrite(buffer, 1, count, file);
  if (written != count) {
    throw std::runtime_error("write failed");
  }
}

size_t File::read(void* buffer, size_t count, bool check) {
  size_t result = fread(buffer, 1, count, file);
  if ((check) && (result != count)) {
    throw std::runtime_error("read failed");
  }

  return result;
}

#if defined(_WIN32)
int ftruncate(const int fd, const int64_t size) {
  return _chsize(fd, size);
}
#endif

void File::truncate(long offset) {
  int rc = ftruncate(fileno(file), offset);
  if (0 != rc) {
    throw std::runtime_error("truncate failed");
  }
}

}
