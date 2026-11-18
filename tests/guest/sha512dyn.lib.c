/* The SHA-512 transform alone, in a shared library: a guest that loads one translates its code a
 * page at a time, which is the path `sha512lib` in the static fixture never takes. */

#define SHA512_SYM "sha512_rounds"
#include "sha512asm.h"
