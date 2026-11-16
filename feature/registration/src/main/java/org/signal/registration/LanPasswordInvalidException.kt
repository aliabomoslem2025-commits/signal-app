package org.signal.registration

/** A signed-in enrolled handset still needs its user's memorized second factor. */
class LanPasswordInvalidException : SecurityException("Password verification was unsuccessful")
