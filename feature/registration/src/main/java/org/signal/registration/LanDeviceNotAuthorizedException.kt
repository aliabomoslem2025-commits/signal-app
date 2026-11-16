package org.signal.registration

/**
 * Generic for both unknown phone numbers and unauthorized devices:
 * no account enumeration through different UI error messages.
 */
class LanDeviceNotAuthorizedException : SecurityException("Device is not authorized for this phone number")
