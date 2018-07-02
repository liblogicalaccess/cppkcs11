#pragma once

#include <vector>
#include <cppkcs11/object.hpp>
#include "cppkcs11/cppkcs_fwd.hpp"

namespace cppkcs
{
/**
 * A service to perform operation against PKCS Objects.
 *
 * The service provide high level and general purpose operations
 * against objects.
 *
 * Objects returned by the service MUST NEVER outlive the Session that
 * was used to construct the ObjectService instance,
 * otherwise it will result in dangling references.
 */
class ObjectService
{
  public:
    /**
     * Construct an ObjectService operating using
     * the Session provided by the caller.
     *
     * The session MUST outlive the service.
     */
    explicit ObjectService(Session &session);

    /**
     * Attempt to destroy every objects.
     */
    void destroy_all();

    /**
     * Destroy a single object.
     *
     * The function takes "ownership" of the Object: the caller
     * has to std::move() it.
     *
     * This provide clean semantic because it prevent the caller to use
     * the object after calling destroy().
     * One potential issue: If the call fails, the object has still be moved...
     */
    void destroy(Object &&obj);

    /**
     * Find objects whose attributes match the Attributes passed as parameters.
     */
    std::vector<Object>
    find_objects(const std::vector<std::reference_wrapper<IAttribute>> &);

    /**
     * Return a list of objects matching the criteria of attributes
     * passed as variadic parameters.
     */
    template <typename... Attributes>
    std::vector<Object> find_objects(Attributes &&... attrs)
    {
        return find_objects({attrs...});
    }

    Object create_object(const std::vector<std::reference_wrapper<IAttribute>> &);

    template <typename... Attributes>
    Object create_object(Attributes &&... attrs)
    {
        return create_object({attrs...});
    }

  private:
    Session &session_;
};
}
