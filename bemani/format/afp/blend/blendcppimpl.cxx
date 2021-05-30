#include <stdio.h>
#include <math.h>
#include <pthread.h>
#include <list>

#define MIN_THREAD_WORK 10

extern "C"
{
    typedef struct intcolor {
        unsigned char r;
        unsigned char g;
        unsigned char b;
        unsigned char a;
    } intcolor_t;

    typedef struct floatcolor {
        float r;
        float g;
        float b;
        float a;
    } floatcolor_t;

    typedef struct point {
        float x;
        float y;

        struct point add(struct point other) {
            return (struct point){
                x + other.x,
                y + other.y,
            };
        };
    } point_t;

    typedef struct matrix {
        float a;
        float b;
        float c;
        float d;
        float tx;
        float ty;

        point_t multiply_point(point_t point) {
            return (point_t){
                (a * point.x) + (c * point.y) + tx,
                (b * point.x) + (d * point.y) + ty,
            };
        }
    } matrix_t;

    typedef struct work {
        intcolor_t *imgdata;
        unsigned char *maskdata;
        unsigned int imgwidth;
        unsigned int minx;
        unsigned int maxx;
        unsigned int miny;
        unsigned int maxy;
        intcolor_t *texdata;
        unsigned int texwidth;
        unsigned int texheight;
        matrix_t inverse;
        floatcolor_t add_color;
        floatcolor_t mult_color;
        int blendfunc;
        pthread_t *thread;
        int enable_aa;
    } work_t;

    inline unsigned char clamp(float color) {
        return fmin(fmax(0.0, roundf(color)), 255.0);
    }

    intcolor_t blend_normal(
        intcolor_t dest,
        intcolor_t src
    ) {
        // "Normal" blend mode, which is just alpha blending. Various games use the DX
        // equation Src * As + Dst * (1 - As). We premultiply Dst by Ad as well, since
        // we are blitting onto a destination that could have transparency. Once we are
        // done, we divide out the premultiplied Ad in order to put the pixes back to
        // their full blended values since we are not setting the destination alpha to 1.0.
        // This enables partial transparent backgrounds to work properly.

        // Short circuit for speed.
        if (src.a == 0) {
            return dest;
        }
        if (src.a == 255) {
            return src;
        }

        // Calculate alpha blending.
        float srcpercent = src.a / 255.0;
        float destpercent = dest.a / 255.0;
        float srcremainder = 1.0 - srcpercent;
        float new_alpha = fmin(fmax(0.0, srcpercent + destpercent * srcremainder), 1.0);
        return (intcolor_t){
            clamp(((dest.r * destpercent * srcremainder) + (src.r * srcpercent)) / new_alpha),
            clamp(((dest.g * destpercent * srcremainder) + (src.g * srcpercent)) / new_alpha),
            clamp(((dest.b * destpercent * srcremainder) + (src.b * srcpercent)) / new_alpha),
            clamp(255 * new_alpha)
        };
    }

    intcolor_t blend_addition(
        intcolor_t dest,
        intcolor_t src
    ) {
        // "Addition" blend mode, which is used for fog/clouds/etc. Various games use the DX
        // equation Src * As + Dst * 1. It appears jubeat does not premultiply the source
        // by its alpha component.

        // Short circuit for speed.
        if (src.a == 0) {
            return dest;
        }

        // Calculate final color blending.
        float srcpercent = src.a / 255.0;
        return (intcolor_t){
            clamp(dest.r + (src.r * srcpercent)),
            clamp(dest.g + (src.g * srcpercent)),
            clamp(dest.b + (src.b * srcpercent)),
            // Additive blending doesn't actually make sense on semi-transparent destinations,
            // as that implies that the semi-transparent pixel will be later displayed on top
            // of something else. That doesn't work since additive blending needs to non-linearly
            // mix with the destination. So, in reality, we should be doing what subtractive
            // blending does and keeping the destination alpha (which should always be 255),
            // but if somebody renders an animation with additive blending meant to go over a
            // background onto a transparent or semi-transparent background this will make the
            // resulting graphic look more correct.
            clamp(dest.a + (255 * srcpercent)),
        };
    }

    intcolor_t blend_subtraction(
        intcolor_t dest,
        intcolor_t src
    ) {
        // "Subtraction" blend mode, used for darkening an image. Various games use the DX
        // equation Dst * 1 - Src * As. It appears jubeat does not premultiply the source
        // by its alpha component much like the "additive" blend above..

        // Short circuit for speed.
        if (src.a == 0) {
            return dest;
        }

        // Calculate final color blending.
        float srcpercent = src.a / 255.0;
        return (intcolor_t){
            clamp(dest.r - (src.r * srcpercent)),
            clamp(dest.g - (src.g * srcpercent)),
            clamp(dest.b - (src.b * srcpercent)),
            dest.a,
        };
    }

    intcolor_t blend_multiply(
        intcolor_t dest,
        intcolor_t src
    ) {
        // "Multiply" blend mode, used for darkening an image. Various games use the DX
        // equation Src * 0 + Dst * Src. It appears jubeat uses the alternative formula
        // Src * Dst + Dst * (1 - As) which reduces to the first equation as long as the
        // source alpha is always 255.

        // Calculate final color blending.
        return (intcolor_t){
            clamp(255 * ((dest.r / 255.0) * (src.r / 255.0))),
            clamp(255 * ((dest.g / 255.0) * (src.g / 255.0))),
            clamp(255 * ((dest.b / 255.0) * (src.b / 255.0))),
            dest.a,
        };
    }

    intcolor_t blend_mask_create(
        intcolor_t dest,
        intcolor_t src
    ) {
        // Mask creating just allows a pixel to be drawn if the source image has a nonzero
        // alpha, according to the SWF spec.
        if (src.a != 0) {
            return (intcolor_t){255, 0, 0, 255};
        } else {
            return (intcolor_t){0, 0, 0, 0};
        }
    }

    intcolor_t blend_mask_combine(
        intcolor_t dest,
        intcolor_t src
    ) {
        // Mask blending just takes the source and destination and ands them together, making
        // a final mask that is the intersection of the original mask and the new mask. The
        // reason we even have a color component to this is for debugging visibility.
        if (dest.a != 0 && src.a != 0) {
            return (intcolor_t){255, 0, 0, 255};
        } else {
            return (intcolor_t){0, 0, 0, 0};
        }
    }

    intcolor_t blend_point(
        floatcolor_t add_color,
        floatcolor_t mult_color,
        intcolor_t src_color,
        intcolor_t dest_color,
        int blendfunc
    ) {
        // Calculate multiplicative and additive colors against the source.
        src_color = (intcolor_t){
            clamp((src_color.r * mult_color.r) + (255 * add_color.r)),
            clamp((src_color.g * mult_color.g) + (255 * add_color.g)),
            clamp((src_color.b * mult_color.b) + (255 * add_color.b)),
            clamp((src_color.a * mult_color.a) + (255 * add_color.a)),
        };

        if (blendfunc == 3) {
            return blend_multiply(dest_color, src_color);
        }
        // TODO: blend mode 4, which is "screen" blending according to SWF references. I've only seen this
        // in Jubeat and it implements it using OpenGL equation Src * (1 - Dst) + Dst * 1.
        // TODO: blend mode 5, which is "lighten" blending according to SWF references. Jubeat does not
        // premultiply by alpha, but the GL/DX equation is max(Src * As, Dst * 1).
        // TODO: blend mode 6, which is "darken" blending according to SWF references. Jubeat does not
        // premultiply by alpha, but the GL/DX equation is min(Src * As, Dst * 1).
        // TODO: blend mode 10, which is "invert" according to SWF references. The only game I could find
        // that implemented this had equation Src * (1 - Dst) + Dst * (1 - As).
        // TODO: blend mode 13, which is "overlay" according to SWF references. The equation seems to be
        // Src * Dst + Dst * Src but Jubeat thinks it should be Src * Dst + Dst * (1 - As).
        if (blendfunc == 8) {
            return blend_addition(dest_color, src_color);
        }
        if (blendfunc == 9 || blendfunc == 70) {
            return blend_subtraction(dest_color, src_color);
        }
        if (blendfunc == 256) {
            return blend_mask_combine(dest_color, src_color);
        }
        if (blendfunc == 257) {
            return blend_mask_create(dest_color, src_color);
        }
        // TODO: blend mode 75, which is not in the SWF spec and appears to have the equation
        // Src * (1 - Dst) + Dst * (1 - Src).
        return blend_normal(dest_color, src_color);
    }

    void chunk_composite_fast(work_t *work) {
        for (unsigned int imgy = work->miny; imgy < work->maxy; imgy++) {
            for (unsigned int imgx = work->minx; imgx < work->maxx; imgx++) {
                // Determine offset.
                unsigned int imgoff = imgx + (imgy * work->imgwidth);

                // If we are masked off, don't do any other calculations.
                if (work->maskdata != NULL && work->maskdata[imgoff] == 0) {
                    // This pixel is masked off!
                    continue;
                }

                // Blend for simple anti-aliasing.
                if (work->enable_aa) {
                    // Calculate what texture pixel data goes here.
                    int r = 0;
                    int g = 0;
                    int b = 0;
                    int a = 0;
                    int count = 0;

                    float xswing = fabs(0.5 / work->inverse.a);
                    float yswing = fabs(0.5 / work->inverse.d);

                    for (float addy = 0.5 - yswing; addy <= 0.5 + yswing; addy += yswing / 2.0) {
                        for (float addx = 0.5 - xswing; addx <= 0.5 + xswing; addx += xswing / 2.0) {
                            point_t texloc = work->inverse.multiply_point((point_t){(float)imgx + addx, (float)imgy + addy});
                            int aax = texloc.x;
                            int aay = texloc.y;

                            // If we're out of bounds, don't update.
                            if (aax < 0 or aay < 0 or aax >= (int)work->texwidth or aay >= (int)work->texheight) {
                                continue;
                            }

                            // Grab the values to average, for SSAA.
                            unsigned int texoff = aax + (aay * work->texwidth);
                            r += work->texdata[texoff].r;
                            g += work->texdata[texoff].g;
                            b += work->texdata[texoff].b;
                            a += work->texdata[texoff].a;
                            count ++;
                        }
                    }

                    if (count == 0) {
                        // None of the samples existed in-bounds.
                        continue;
                    }

                    // Average the pixels.
                    intcolor_t average = (intcolor_t){
                        (unsigned char)(r / count),
                        (unsigned char)(g / count),
                        (unsigned char)(b / count),
                        (unsigned char)(a / count),
                    };

                    // Blend it.
                    work->imgdata[imgoff] = blend_point(work->add_color, work->mult_color, average, work->imgdata[imgoff], work->blendfunc);
                } else {
                    // Grab the center of the pixel to get the color.
                    point_t texloc = work->inverse.multiply_point((point_t){(float)imgx + (float)0.5, (float)imgy + (float)0.5});
                    int texx = texloc.x;
                    int texy = texloc.y;

                    // If we're out of bounds, don't update.
                    if (texx < 0 or texy < 0 or texx >= (int)work->texwidth or texy >= (int)work->texheight) {
                        continue;
                    }

                    // Blend it.
                    unsigned int texoff = texx + (texy * work->texwidth);
                    work->imgdata[imgoff] = blend_point(work->add_color, work->mult_color, work->texdata[texoff], work->imgdata[imgoff], work->blendfunc);
                }
            }
        }
    }

    void *chunk_composite_worker(void *arg) {
        work_t *work = (work_t *)arg;
        chunk_composite_fast(work);
        return NULL;
    }

    int affine_composite_fast(
        unsigned char *imgbytes,
        unsigned char *maskbytes,
        unsigned int imgwidth,
        unsigned int imgheight,
        unsigned int minx,
        unsigned int maxx,
        unsigned int miny,
        unsigned int maxy,
        floatcolor_t add_color,
        floatcolor_t mult_color,
        matrix_t inverse,
        int blendfunc,
        unsigned char *texbytes,
        unsigned int texwidth,
        unsigned int texheight,
        unsigned int threads,
        unsigned int enable_aa
    ) {
        // Cast to a usable type.
        intcolor_t *imgdata = (intcolor_t *)imgbytes;
        intcolor_t *texdata = (intcolor_t *)texbytes;

        if (threads == 1 || (maxy - miny) < (MIN_THREAD_WORK * 2)) {
            // Just create a local work structure so we can call the common function.
            work_t work;
            work.imgdata = imgdata;
            work.maskdata = maskbytes;
            work.imgwidth = imgwidth;
            work.minx = minx;
            work.maxx = maxx;
            work.miny = miny;
            work.maxy = maxy;
            work.texdata = texdata;
            work.texwidth = texwidth;
            work.texheight = texheight;
            work.inverse = inverse;
            work.add_color = add_color;
            work.mult_color = mult_color;
            work.blendfunc = blendfunc;
            work.enable_aa = enable_aa;

            chunk_composite_fast(&work);
        } else {
            std::list<work_t *> workers;
            work_t *mywork = NULL;
            unsigned int imgy = miny;
            unsigned int step = (maxy - miny) / threads;
            if (step < MIN_THREAD_WORK) {
                step = MIN_THREAD_WORK;
            }

            for (unsigned int worker = 0; worker < threads; worker++) {
                // We are slightly different if this is the last worker, because
                // its going to this thread. Make sure it consumes the rest of the
                // work, as well as not getting a pthread. Make sure each thread
                // has a minimum amount of work so we don't waste pthread overhead
                // starting and stopping it. Because of this, make sure that the
                // last chunk we create is always our own.
                unsigned int me = 0;
                if (worker == (threads - 1) || (imgy + step) >= maxy) {
                    me = 1;
                }

                // Create storage for this worker.
                pthread_t *thread = me ? NULL : (pthread_t *)malloc(sizeof(pthread_t));
                work_t *work = (work_t *)malloc(sizeof(work_t));

                // Pass to it all of the params it needs.
                work->imgdata = imgdata;
                work->maskdata = maskbytes;
                work->imgwidth = imgwidth;
                work->minx = minx;
                work->maxx = maxx;
                work->miny = imgy;
                work->maxy = me ? maxy : imgy + step;
                work->texdata = texdata;
                work->texwidth = texwidth;
                work->texheight = texheight;
                work->inverse = inverse;
                work->add_color = add_color;
                work->mult_color = mult_color;
                work->blendfunc = blendfunc;
                work->thread = thread;
                work->enable_aa = enable_aa;

                if (me)
                {
                    // This is the row for this thread.
                    mywork = work;

                    // Always exit here, we might not have actually scheduled
                    // the maximum permitted threads.
                    break;
                }
                else
                {
                    // Kick off the thread.
                    pthread_create(thread, NULL, chunk_composite_worker, work);

                    // Save the row so we can access it for scheduling.
                    workers.push_back(work);

                    // The next chunk of work is the next step.
                    imgy += step;
                }
            }

            // Now, run my own work.
            chunk_composite_fast(mywork);

            // Join on all threads once they're finished.
            std::list<work_t *>::iterator work = workers.begin();

            while(work != workers.end()) {
                // Join the thread.
                pthread_join(*((*work)->thread), NULL);

                // Free the memory we allocated.
                free((*work)->thread);
                free((*work));

                // Remove it from our bookkeeping.
                work = workers.erase(work);
            }

            // Free the memory we allocated.
            free(mywork);
        }

        return 0;
    }
}
