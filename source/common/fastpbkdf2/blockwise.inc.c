/*
 * cifra - embedded cryptography library
 * Written in 2014 by Joseph Birr-Pixton <jpixton@gmail.com>
 *
 * To the extent possible under law, the author(s) have dedicated all
 * copyright and related and neighboring rights to this software to the
 * public domain worldwide. This software is distributed without any
 * warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication
 * along with this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#ifndef BLOCKWISE_INC_C
#define BLOCKWISE_INC_C

#include <string.h>
#include <assert.h>

typedef void (*cf_blockwise_in_fn)(void *ctx, const uint8_t *data);

__device__ void cf_blockwise_accumulate(uint8_t *partial, std::size_t *npartial, std::size_t nblock,
                             const void *inp, std::size_t nbytes,
                             cf_blockwise_in_fn process,
                             void *ctx)
{
  const uint8_t *bufin = reinterpret_cast<const uint8_t *>(inp);
  assert(partial && *npartial < nblock);
  assert(inp || !nbytes);
  assert(process && ctx);

  /* If we have partial data, copy in to buffer. */
  if (*npartial && nbytes)
  {
    std::size_t space = nblock - *npartial;
    std::size_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If that gives us a full block, process it. */
    if (*npartial == nblock)
    {
      process(ctx, partial);
      *npartial = 0;
    }
  }

  /* now nbytes < nblock or *npartial == 0. */

  /* If we have a full block of data, process it directly. */
  while (nbytes >= nblock)
  {
    /* Partial buffer must be empty, or we're ignoring extant data */
    assert(*npartial == 0);

    process(ctx, bufin);
    bufin += nblock;
    nbytes -= nblock;
  }

  /* Finally, if we have remaining data, buffer it. */
  while (nbytes)
  {
    std::size_t space = nblock - *npartial;
    std::size_t taken = MIN(space, nbytes);

    memcpy(partial + *npartial, bufin, taken);

    bufin += taken;
    nbytes -= taken;
    *npartial += taken;

    /* If we started with *npartial, we must have copied it
     * in first. */
    assert(*npartial < nblock);
  }
}

__device__ void cf_blockwise_acc_byte(uint8_t *partial, std::size_t *npartial,
                           std::size_t nblock,
                           uint8_t byte, std::size_t nbytes,
                           cf_blockwise_in_fn process,
                           void *ctx)
{
  /* only memset the whole of the block once */
  int filled = 0;

  while (nbytes)
  {
    std::size_t start = *npartial;
    std::size_t count = MIN(nbytes, nblock - start);

    if (!filled)
      memset(partial + start, byte, count);

    if (start == 0 && count == nblock)
      filled = 1;

    if (start + count == nblock)
    {
      process(ctx, partial);
      *npartial = 0;
    } else {
      *npartial += count;
    }

    nbytes -= count;
  }
}

__device__ static void cf_blockwise_acc_pad(uint8_t *partial, std::size_t *npartial,
                                 std::size_t nblock,
                                 uint8_t fbyte, uint8_t mbyte, uint8_t lbyte,
                                 std::size_t nbytes,
                                 cf_blockwise_in_fn process,
                                 void *ctx)
{

  switch (nbytes)
  {
    case 0: break;
    case 1: fbyte ^= lbyte;
            cf_blockwise_accumulate(partial, npartial, nblock, &fbyte, 1, process, ctx);
            break;
    case 2:
            cf_blockwise_accumulate(partial, npartial, nblock, &fbyte, 1, process, ctx);
            cf_blockwise_accumulate(partial, npartial, nblock, &lbyte, 1, process, ctx);
            break;
    default:
            cf_blockwise_accumulate(partial, npartial, nblock, &fbyte, 1, process, ctx);

            /* If the middle and last bytes differ, then process the last byte separately.
             * Otherwise, just extend the middle block size. */
            if (lbyte != mbyte)
            {
              cf_blockwise_acc_byte(partial, npartial, nblock, mbyte, nbytes - 2, process, ctx);
              cf_blockwise_accumulate(partial, npartial, nblock, &lbyte, 1, process, ctx);
            } else {
              cf_blockwise_acc_byte(partial, npartial, nblock, mbyte, nbytes - 1, process, ctx);
            }

            break;
  }
}

#endif
