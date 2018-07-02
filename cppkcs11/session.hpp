#pragma once

#include "cppkcs11/cppkcs_fwd.hpp"
#include "cppkcs11/native_pkcs.hpp"
#include "cppkcs11/object.hpp"
#include <string>
#include <vector>

namespace cppkcs
{

/**
 * A PKCS11 Session.
 *
 *
 * This object is RAII aware and will attempt to close
 * the session when it gets destroyed.
 *
 * Note that Trustway Proteccio (ATOS / BULL) does not
 * support notifications (pApplication & Notify parameter).
 */
class Session
{
  public:
    /**
     * Create a session object from a native handle.
     * @param native_handle
     */
    explicit Session(CK_SESSION_HANDLE native_handle, CK_SLOT_ID slot_id);
    ~Session();

    // A session is not copyable.
    Session(const Session &) = delete;
    Session &operator=(const Session &) = delete;

    // Session is movable.
    Session(Session &&o) noexcept;
    Session &operator=(Session &&o) = delete;

    /**
     * Retrieve the native PKCS handle.
     *
     * This may be useful to perform some operation with the session
     * directly.
     */
    CK_SESSION_HANDLE native_handle() const;

    /**
     * Attempt to authenticate the user.
     *
     * The session will be logged as CKU_USER. It is not possible, for
     * the Atos netHSM to authenticate as Security Officer w/o smartcard.
     * @param password
     */
    void login(const SecureString &password);

    /**
     * Logout the session.
     */
    void logout();

  private:
    /**
     * The "native" PKCS session handle.
     *
     * We assume that it cannot be 0. todo: check with spec or something.
     */
    CK_SESSION_HANDLE handle_;

    /**
     * The slotID against which the session was opened.
     * Informational only.
     */
    CK_SLOT_ID slot_id_;
};
}
