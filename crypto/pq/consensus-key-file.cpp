/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
#include "consensus-key-file.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <array>
#include <cerrno>
#include <cstdio>
#include <string>

namespace tos::pq {
namespace {

constexpr std::size_t seed_bytes = 32;

// Closes on every path out, including the ones that throw nothing and return early.
class Descriptor {
 public:
  explicit Descriptor(int fd) noexcept : fd_(fd) {
  }
  ~Descriptor() {
    if (fd_ >= 0) {
      ::close(fd_);
    }
  }
  Descriptor(const Descriptor&) = delete;
  Descriptor& operator=(const Descriptor&) = delete;
  int get() const noexcept {
    return fd_;
  }
  bool valid() const noexcept {
    return fd_ >= 0;
  }

 private:
  int fd_;
};

// A buffer that is wiped when it goes out of scope, however it goes out of scope.
class SeedBuffer {
 public:
  ~SeedBuffer() {
    OPENSSL_cleanse(bytes.data(), bytes.size());
  }
  std::array<unsigned char, seed_bytes> bytes{};
};

std::string parent_directory(std::string_view path) {
  const auto slash = path.find_last_of('/');
  if (slash == std::string_view::npos) {
    return ".";
  }
  if (slash == 0) {
    return "/";
  }
  return std::string(path.substr(0, slash));
}

// Anyone who can write the directory can replace the key in it, so the directory is part
// of what protects the key and is checked with it.
bool directory_is_private(std::string_view path) noexcept {
  struct stat st {};
  if (::stat(parent_directory(path).c_str(), &st) != 0) {
    return false;
  }
  return (st.st_mode & (S_IWGRP | S_IWOTH)) == 0;
}

}  // namespace

const char* describe(ConsensusKeyFileError error) noexcept {
  switch (error) {
    case ConsensusKeyFileError::cannot_open:
      return "the consensus key file cannot be opened, or is a symbolic link";
    case ConsensusKeyFileError::not_a_regular_file:
      return "the consensus key path is not a regular file";
    case ConsensusKeyFileError::wrong_owner:
      return "the consensus key file is owned by another user";
    case ConsensusKeyFileError::readable_by_others:
      return "the consensus key file is readable or writable by group or others";
    case ConsensusKeyFileError::directory_writable:
      return "the directory holding the consensus key is writable by group or others";
    case ConsensusKeyFileError::wrong_size:
      return "the consensus key file is not a 32-byte seed";
    case ConsensusKeyFileError::read_failed:
      return "the consensus key file could not be read to its end";
    case ConsensusKeyFileError::derivation_failed:
      return "no key could be derived from the consensus seed";
    case ConsensusKeyFileError::already_exists:
      return "a consensus key is already there; remove it deliberately to replace it";
    case ConsensusKeyFileError::write_failed:
      return "the consensus key could not be written";
  }
  return "the consensus key file was refused";
}

std::variant<ValidatorPQKeyStore, ConsensusKeyFileError> load_consensus_key(
    std::string_view path) noexcept {
  const std::string name(path);
  Descriptor fd(::open(name.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
  if (!fd.valid()) {
    return ConsensusKeyFileError::cannot_open;
  }
  struct stat st {};
  if (::fstat(fd.get(), &st) != 0) {
    return ConsensusKeyFileError::cannot_open;
  }
  if (!S_ISREG(st.st_mode)) {
    return ConsensusKeyFileError::not_a_regular_file;
  }
  if (st.st_uid != ::geteuid()) {
    return ConsensusKeyFileError::wrong_owner;
  }
  if ((st.st_mode & 077) != 0) {
    return ConsensusKeyFileError::readable_by_others;
  }
  if (!directory_is_private(path)) {
    return ConsensusKeyFileError::directory_writable;
  }
  if (st.st_size != static_cast<off_t>(seed_bytes)) {
    return ConsensusKeyFileError::wrong_size;
  }

  SeedBuffer seed;
  std::size_t read_so_far = 0;
  while (read_so_far < seed.bytes.size()) {
    const auto n = ::read(fd.get(), seed.bytes.data() + read_so_far, seed.bytes.size() - read_so_far);
    if (n < 0 && errno == EINTR) {
      continue;
    }
    if (n <= 0) {
      return ConsensusKeyFileError::read_failed;
    }
    read_so_far += static_cast<std::size_t>(n);
  }

  auto store = ValidatorPQKeyStore::from_seed(
      std::string_view(reinterpret_cast<const char*>(seed.bytes.data()), seed.bytes.size()));
  if (!store.has_value()) {
    return ConsensusKeyFileError::derivation_failed;
  }
  // The seed buffer is wiped by its destructor here; what survives is the signer, whose
  // own destructor wipes the expanded secret.
  return std::move(*store);
}

std::variant<ConsensusPQKey, ConsensusKeyFileError> create_consensus_key(
    std::string_view path) noexcept {
  const std::string name(path);
  struct stat existing {};
  if (::lstat(name.c_str(), &existing) == 0) {
    return ConsensusKeyFileError::already_exists;
  }
  if (!directory_is_private(path)) {
    return ConsensusKeyFileError::directory_writable;
  }

  SeedBuffer seed;
  if (RAND_priv_bytes(seed.bytes.data(), static_cast<int>(seed.bytes.size())) != 1) {
    return ConsensusKeyFileError::write_failed;
  }
  auto store = ValidatorPQKeyStore::from_seed(
      std::string_view(reinterpret_cast<const char*>(seed.bytes.data()), seed.bytes.size()));
  if (!store.has_value()) {
    return ConsensusKeyFileError::derivation_failed;
  }

  // Written under a name of its own and renamed into place, so a key that is there is a
  // whole one: an interrupted write leaves the temporary behind rather than a half key
  // the node would refuse on every later start.
  const std::string temporary = name + ".new";
  {
    Descriptor fd(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (!fd.valid()) {
      return ConsensusKeyFileError::write_failed;
    }
    std::size_t written = 0;
    while (written < seed.bytes.size()) {
      const auto n = ::write(fd.get(), seed.bytes.data() + written, seed.bytes.size() - written);
      if (n < 0 && errno == EINTR) {
        continue;
      }
      if (n <= 0) {
        ::unlink(temporary.c_str());
        return ConsensusKeyFileError::write_failed;
      }
      written += static_cast<std::size_t>(n);
    }
    if (::fsync(fd.get()) != 0) {
      ::unlink(temporary.c_str());
      return ConsensusKeyFileError::write_failed;
    }
  }
  if (::rename(temporary.c_str(), name.c_str()) != 0) {
    ::unlink(temporary.c_str());
    return ConsensusKeyFileError::write_failed;
  }
  // The rename itself has to reach the disk, or a crash leaves the directory pointing at
  // a name that is no longer there.
  {
    Descriptor dir(::open(parent_directory(path).c_str(), O_RDONLY | O_CLOEXEC));
    if (dir.valid()) {
      ::fsync(dir.get());
    }
  }
  return store->consensus_key();
}

}  // namespace tos::pq
