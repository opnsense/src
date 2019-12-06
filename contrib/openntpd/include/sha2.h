/*
 * Public domain
 * sha2.h compatibility shim
 */

#include "sha2_openbsd.h"

#define SHA512_CTX SHA2_CTX
#define SHA512_Init(ctx) SHA512Init(ctx)
#define SHA512_Update(ctx, buf, len) SHA512Update(ctx, (void *)buf, len)
#define SHA512_Final(digest, ctx) SHA512Final(digest, ctx)
