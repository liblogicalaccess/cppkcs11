#include "cppkcs11/secure_memory/memory_tools.hpp"
#include <iostream>
#include <memory>
#include <cstring>
#if __linux__
#include <sys/mman.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

namespace cppkcs
{

void secure_bzero(void *ptr, size_t size)
{
    volatile uint8_t *byte = static_cast<volatile uint8_t *>(ptr);
    while (size--)
    {
        *byte = 0;
        byte++;
    }
}

void secure_bzero(std::string &str)
{
    // Resize to capacity to clear (mostly) everything.
    str.resize(str.capacity());
    if (!str.empty())
    {
        secure_bzero(&str[0], str.size());
    }
}

void lock_memory(const void *addr, size_t len)
{
    if (addr == nullptr || len == 0)
        abort();
#ifdef __linux__
    int ret;
    ret = mlock(addr, len);
    if (ret != 0)
    {
        std::cerr << "Memory locking issue..." << std::endl;
        abort();
    }
#else
    if (VirtualLock((void *)addr, len) == 0)
    {
        std::cerr << "Memory locking issue..." << std::endl;
        abort();
    }
#endif
}

void unlock_memory(const void *addr, size_t len)
{
    if (addr == nullptr || len == 0)
        return;
#ifdef __linux__
    int ret;
    ret = munlock(addr, len);
    if (ret != 0)
    {
        std::cerr << "Memory unlocking issue..." << std::endl;
        abort();
    }
#else
    if (VirtualUnlock((void *)addr, len) == 0)
    {
        std::cerr << "Memory unlocking issue..." << std::endl;
        abort();
    }
#endif
}

size_t get_page_size()
{
#ifdef __linux__
    return static_cast<size_t>(getpagesize());
#else
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    return si.dwPageSize;
#endif
}

SecureMemoryLockedBuffer::SecureMemoryLockedBuffer(size_t user_buffer_size)
{
    if (user_buffer_size)
    {
        allocate_raw(user_buffer_size);
        configure_lock(user_buffer_size);
    }
}

SecureMemoryLockedBuffer::SecureMemoryLockedBuffer(const SecureMemoryLockedBuffer &o)
{
    if (o.size())
    {
        allocate_raw(o.size());
        configure_lock(o.size());

        std::memcpy(locked_ptr_, o.data(), o.size());
    }
}

SecureMemoryLockedBuffer::~SecureMemoryLockedBuffer()
{
    secure_bzero(raw_allocated_ptr_.get(), raw_allocated_size_);
    unlock_memory(locked_ptr_, locked_size_);
}

void SecureMemoryLockedBuffer::allocate_raw(size_t user_buffer_size)
{
    const auto page_size = static_cast<size_t>(get_page_size());

    // We want a raw buffer of size: page_size + buffer_size + XXX == multiple of page
    // size. This will make sure we can align to page_size and end the user buffer
    // on a page boundary.
    raw_allocated_size_ = page_size + user_buffer_size;
    // How many bytes to reach next page boundary.
    size_t to_next_page = page_size - (raw_allocated_size_ % page_size);

    // We want to allocate full pages.
    raw_allocated_size_ += to_next_page;
    assert((raw_allocated_size_ % page_size) == 0);

    raw_allocated_ptr_.reset(static_cast<uint8_t *>(malloc(raw_allocated_size_)));
    if (!raw_allocated_ptr_)
        throw std::runtime_error("Cannot create MemoryLockedBuffer. Allocation failed.");
}

void SecureMemoryLockedBuffer::configure_lock(size_t user_buffer_size)
{
    const auto page_size = static_cast<size_t>(get_page_size());

    locked_ptr_             = raw_allocated_ptr_.get();
    auto raw_allocated_size = raw_allocated_size_;

    // Align the memory locked pointer to page_size.
    // Make sure we have enough space for our data.
    locked_ptr_ = static_cast<uint8_t *>(
        std::align(page_size, user_buffer_size, reinterpret_cast<void *&>(locked_ptr_),
                   raw_allocated_size));
    if (!locked_ptr_)
        throw std::runtime_error("Cannot create MemoryLockedBuffer. Alignment failed.");

    locked_size_ = user_buffer_size;
    lock_memory(locked_ptr_, locked_size_);

    // Sanity checks
    assert(locked_ptr_ >= raw_allocated_ptr_.get());
    assert(locked_ptr_ + locked_size_ <= raw_allocated_ptr_.get() + raw_allocated_size_);
}

bool SecureMemoryLockedBuffer::operator==(const SecureMemoryLockedBuffer &o) const
{
    if (o.size() != size())
        return false;
    return std::memcmp(o.locked_ptr_, locked_ptr_, size()) == 0;
}

SecureMemoryLockedBuffer &SecureMemoryLockedBuffer::
operator=(const SecureMemoryLockedBuffer &o)
{
    SecureMemoryLockedBuffer new_buffer(o);

    using std::swap;
    swap(new_buffer.raw_allocated_size_, raw_allocated_size_);
    swap(new_buffer.raw_allocated_ptr_, raw_allocated_ptr_);

    swap(new_buffer.locked_size_, locked_size_);
    swap(new_buffer.locked_ptr_, locked_ptr_);

    return *this;
}
}
