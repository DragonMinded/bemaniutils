#include <stdio.h>
#include <stdint.h>

#define FLAG_COPY 1
#define FLAG_BACKREF 0

extern "C"
{
    int decompress(uint8_t *indata, unsigned int inlen, uint8_t *outdata, unsigned int outlen)
    {
        // First, let's assume a worst case compression which in theory is just a copy.
        // The math is basically 9 bytes used for every 8 bytes. So, the minimum output
        // buffer we need is (inlen * 8/9). If we have an outlen smaller than that, we
        // are hosed.
        if (outlen < ((inlen * 8) / 9))
        {
            // We cannot decompress, we will run out of room!
            return -1;
        }

        // Now, let's enter a loop where we read control bytes and act on them.
        unsigned int inloc = 0;
        unsigned int outloc = 0;
        bool eof = false;
        while (inloc < inlen && !eof)
        {
            if (inloc >= inlen)
            {
                // We failed to decompress, we overran the input buffer.
                return -2;
            }

            uint8_t flags = indata[inloc++];
            for (unsigned int flagpos = 0; flagpos < 8; flagpos++)
            {
                if (((flags >> flagpos) & 1) == FLAG_COPY)
                {
                    // Copy a byte, move on
                    if (inloc >= inlen)
                    {
                        // We failed to decompress, we overran the input buffer.
                        return -2;
                    }
                    if (outloc >= outlen)
                    {
                        // We overwrote our output buffer, we probably corrupted memory somewhere.
                        return -3;
                    }
                    outdata[outloc++] = indata[inloc++];
                }
                else
                {
                    // Backref copy
                    if (inloc >= (inlen - 1))
                    {
                        // We failed to decompress, we overran the input buffer.
                        return -2;
                    }
                    uint8_t hi = indata[inloc++];
                    uint8_t lo = indata[inloc++];

                    unsigned int copy_len = (lo & 0xF) + 3;
                    unsigned int copy_pos = (hi << 4) | (lo >> 4);

                    if (copy_pos == 0)
                    {
                        // This is the end of a file.
                        eof = true;
                        break;
                    }

                    // Copy backref a byte at a time. This is because a backref can stick
                    // out into as-of-yet uncopied data in order to reference what we're
                    // about to write.
                    for (unsigned int backref_copy_amt = 0; backref_copy_amt < copy_len; backref_copy_amt++)
                    {
                        if (outloc >= outlen)
                        {
                            // We overwrote our output buffer, we probably corrupted memory somewhere.
                            return -3;
                        }

                        if (((int)outloc - (int)copy_pos) < 0)
                        {
                            outdata[outloc++] = 0;
                        }
                        else
                        {
                            outdata[outloc] = outdata[outloc - copy_pos];
                            outloc++;
                        }
                    }
                }
            }
        }

        // Update the outlen with the actual data length.
        return outloc;
    }
}
