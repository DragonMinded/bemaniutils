#include <stdio.h>
#include <stdint.h>
#include <algorithm>
#include <unordered_map>
#include <list>

#define FLAG_COPY 1
#define FLAG_BACKREF 0

#define MAX_BACKREF ((unsigned int)18)
#define RING_LEN 0x1000

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

                    unsigned int hi = indata[inloc++];
                    unsigned int lo = indata[inloc++];

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
                    if (outloc + copy_len > outlen)
                    {
                        // We overwrote our output buffer, we probably corrupted memory somewhere.
                        return -3;
                    }

                    int backref_start_loc = (int)outloc - (int)copy_pos;
                    for (int backref_copy_pos = backref_start_loc; backref_copy_pos < backref_start_loc + (int)copy_len; backref_copy_pos++)
                    {
                        if (backref_copy_pos < 0)
                        {
                            outdata[outloc++] = 0;
                        }
                        else
                        {
                            outdata[outloc++] = outdata[backref_copy_pos];
                        }
                    }
                }
            }
        }

        // Update the outlen with the actual data length.
        return outloc;
    }

    int compress(uint8_t *indata, unsigned int inlen, uint8_t *outdata, unsigned int outlen)
    {
        uint32_t key = 0;
        std::unordered_map<uint32_t, std::list<unsigned int>> starts;
        bool eof = false;
        unsigned int outloc = 0;
        unsigned int inloc = 0;

        while (!eof)
        {
            if (outloc >= outlen)
            {
                // We overwrote our output buffer, we probably corrupted memory somewhere.
                return -3;
            }

            // Add a spot for the flag byte, we'll fill this in later.
            unsigned int flagsloc = outloc;
            outdata[outloc++] = 0;

            for (unsigned int flagpos = 0; flagpos < 8; flagpos++)
            {
                if (inloc == inlen)
                {
                    if (outloc > (outlen - 2))
                    {
                        // We overwrote our output buffer, we probably corrupted memory somewhere.
                        return -3;
                    }

                    // We hit the end of compressable data and we are mid flag byte.
                    // Set the particular flag bit to a backref and point at the current
                    // byte to signify end of file.
                    outdata[flagsloc] |= (FLAG_BACKREF << flagpos);

                    // Add the backref itself.
                    outdata[outloc++] = 0;
                    outdata[outloc++] = 0;

                    // Bail out of the loop, we're done!
                    eof = true;
                    break;
                }
                else if (inloc < 3 || inloc >= (inlen - 3))
                {
                    if (outloc >= outlen)
                    {
                        // We overwrote our output buffer, we probably corrupted memory somewhere.
                        return -3;
                    }

                    // We either don't have enough data written to backref, or we
                    // don't have enough data in the stream that could be made into
                    // a backref. Set the particular flag bit to a copy and then
                    // output that byte to the compressed stream.
                    outdata[flagsloc] |= (FLAG_COPY << flagpos);

                    // Update our key to reflect this byte coming out as long as we aren't
                    // in the first two bytes (we wouldn't have a 3 byte prefix in the key yet).
                    key = ((key << 8) | indata[inloc]) & 0xFFFFFF;
                    if (inloc >= 2)
                    {
                        starts[key].push_back(inloc - 2);
                    }

                    // Output this byte specifically
                    outdata[outloc++] = indata[inloc++];
                }
                else
                {
                    // Figure out the maximum backref amount we can reference.
                    unsigned int backref_amount = std::min(inlen - inloc, MAX_BACKREF);
                    unsigned int earliest_backref = std::max(0, (int)inloc - (RING_LEN - 1));
                    uint32_t search_key = (indata[inloc] << 16) | (indata[inloc + 1] << 8) | (indata[inloc + 2]);

                    // Prune anything that we can't backref.
                    starts[search_key].remove_if([earliest_backref](auto val)
                    {
                        return val < earliest_backref;
                    });

                    if (starts[search_key].size() == 0)
                    {
                        if (outloc >= outlen)
                        {
                            // We overwrote our output buffer, we probably corrupted memory somewhere.
                            return -3;
                        }

                        // We couldn't find a previous data in range of a backref.
                        outdata[flagsloc] |= (FLAG_COPY << flagpos);

                        // Update our key to reflect this byte coming out.
                        key = ((key << 8) | indata[inloc]) & 0xFFFFFF;
                        starts[key].push_back(inloc - 2);

                        // Output this byte specifically
                        outdata[outloc++] = indata[inloc++];
                    }
                    else
                    {
                        int best_backref = -1;
                        unsigned int best_length = 1;

                        for (auto possible_backref = starts[search_key].begin(); possible_backref != starts[search_key].end(); possible_backref++)
                        {
                            // If the current best length isn't a match on this chunk, then we shouldn't even consider it
                            // since the other chunk is already a better match.
                            if (indata[(*possible_backref) + (best_length - 1)] != indata[inloc + (best_length - 1)])
                            {
                                continue;
                            }

                            // We already know that the first three match so we don't need to check those;
                            unsigned int current_length;
                            for (current_length = 3; current_length < backref_amount; current_length++)
                            {
                                if (indata[(*possible_backref) + current_length] != indata[inloc + current_length])
                                {
                                    // This value doesn't match, so the current length is the longest prefix
                                    // for this possible backref.
                                    break;
                                }
                            }

                            // We found a better match
                            if (best_length < current_length)
                            {
                                best_length = current_length;
                                best_backref = (inloc - *possible_backref) & 0xFFF;
                            }
                            else if (best_length == backref_amount)
                            {
                                // We found an ideal length, no need to keep searching.
                                break;
                            }
                        }

                        if (best_backref <= 0)
                        {
                            // Double check, since we know we should have found a backref.
                            return -2;
                        }

                        if (outloc > (outlen - 2))
                        {
                            // We overwrote our output buffer, we probably corrupted memory somewhere.
                            return -3;
                        }

                        // We got a valid backref, so let's record it as well as the start positions
                        // for each of the bytes we compressed.
                        outdata[flagsloc] |= (FLAG_BACKREF << flagpos);

                        // Add the backref itself.
                        outdata[outloc++] = (best_backref >> 4) & 0xFF;
                        outdata[outloc++] = ((best_backref & 0xF) << 4) | ((best_length - 3) & 0xF);

                        // Record the keys for each byte;
                        for (unsigned int i = 0; i < best_length; i++)
                        {
                            key = ((key << 8) | indata[inloc]) & 0xFFFFFF;
                            starts[key].push_back(inloc - 2);
                            inloc++;
                        }
                    }
                }
            }
        }

        return outloc;
    }
}
