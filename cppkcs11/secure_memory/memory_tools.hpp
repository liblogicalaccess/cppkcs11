#pragma once

#include <cassert>
#include <cstddef>
#include <memory>
#include <string>
#include <vector>

namespace cppkcs
{

/**
 * To avoid memset() removal by the compiler.
 */
void secure_bzero(void *ptr, size_t size);

/**
 * Securely bzero a std::string.
 * @param str
 */
void secure_bzero(std::string &str);

/**
 * Lock the memory, preventing the pages in the address range
 * starting at `addr` from being swapped to disk.
 *
 * On Linux this is a wrapper around mlock().
 *
 * Attempting to lock nullptr / range of size 0 is a fatal error.
 */
void lock_memory(const void *addr, size_t len);

/**
 * Unlock memory previously locked by lock_memory().
 *
 * On Linux, this is a wrapper around munlock().
 *
 * Attempting to unlock nullptr / range of size 0 is a noop.
 */
void unlock_memory(const void *addr, size_t len);

/**
 * Portable function to retrieve the underlying OS page size.
 */
size_t get_page_size();

/**
 * The SecureMemoryLockedBuffer is an abstraction providing a memory buffer
 * with a few guarantees that are useful when handling sensitive data.
 *
 * Guarantees:
 *   + Zeroing of memory when the SecureMemoryLockedBuffer is destroyed.
 *   + Memory locking of pages hosting the memory for the buffer. This
 *     makes sure that memory pages wont be swapped to disk.
 *
 * Implementation notes:
 *   + We have to be certain that the address range we lock are full pages,
 *   that is we have to prevent any other allocation for sharing a page with
 *   the secured-memory provided by the SecureMemoryLockerBuffer. This is
 * because
 *   a single call to munlock() will cancel multiple call to mlock(). Therefore,
 *   each SecureMemoryLockerBuffer MUST NOT share pages.
 *   + To do so we request more memory than required, then take a pointer
 * aligned
 *   to the system page size. We then lock the range starting from that pointer
 *   to (pointer + user size + XXX) that end at a page boundary.
 */
struct SecureMemoryLockedBuffer
{
    /**
     * Construct a secure and locked memory buffer with at least
     * user_buffer_size bytes available for usage.
     */
    explicit SecureMemoryLockedBuffer(size_t user_buffer_size);

    SecureMemoryLockedBuffer(const SecureMemoryLockedBuffer &);
    SecureMemoryLockedBuffer &operator=(const SecureMemoryLockedBuffer &);

    ~SecureMemoryLockedBuffer();

    size_t size() const
    {
        return locked_size_;
    }

    uint8_t *data()
    {
        return locked_ptr_;
    }

    const uint8_t *data() const
    {
        return locked_ptr_;
    }

    bool operator==(const SecureMemoryLockedBuffer &o) const;

  private:
    void allocate_raw(size_t user_buffer_size);
    void configure_lock(size_t user_buffer_size);

    // The size of the allocation, as requested from malloc().
    size_t raw_allocated_size_{0};

    // The raw pointer returned by malloc()
    std::unique_ptr<uint8_t> raw_allocated_ptr_{nullptr};

    // The size of the locked region.
    size_t locked_size_{0};

    // The start of the locked region.
    // locked_ptr_ + locked_size_ must always end at page boundary.
    uint8_t *locked_ptr_{nullptr};
};
}
