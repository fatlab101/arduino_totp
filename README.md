The Time-based One-Time Password algorithm (TOTP) is an algorithm that computes a one-time password from a shared secret key and the current time. It has been adopted as Internet Engineering Task Force[1] standard RFC 6238,[1] is the cornerstone of Initiative For Open Authentication (OATH), and is used in a number of two-factor authentication systems. 

TOTP is an example of a hash-based message authentication code (HMAC). It combines a secret key with the current timestamp using a cryptographic hash function to generate a one-time password. Because network latency and out-of-sync clocks can result in the password recipient having to try a range of possible times to authenticate against, the timestamp typically increases in 30-second intervals, which thus cuts the potential search space.

...

- Wikipedia August 2018

For arduino_totp:

Stored inputs:

1. A Base32 encoded pass phrase of up to 30 chars ie. ASCII chars in range {A-Za-z2-7} you can include spaces, tabs and '-' which are ignored. The alphabet is Base32 as defined in RFC 4648.
This is converted to a byte string using a base32 decoder - resulting in the stored secret key.
2.  A time step interval in seconds to be used default = 30 seconds

The following TOTP choices are fixed:

  The cryptographic hash method used is SHA-1
  The token length output is fixed at 6
  
