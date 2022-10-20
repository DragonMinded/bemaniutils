#include <stdio.h>
#include <math.h>
#include <pthread.h>
#include <list>

#define MIN_THREAD_WORK 10

#define AA_MODE_NONE 0
#define AA_MODE_UNSCALED_SSAA_ONLY 1
#define AA_MODE_SSAA_ONLY 2
#define AA_MODE_SSAA_OR_BILINEAR 3

extern "C"
{
    typedef struct intcolor {
        unsigned char r;
        unsigned char g;
        unsigned char b;
        unsigned char a;
    } intcolor_t;

    typedef struct floatcolor {
        double r;
        double g;
        double b;
        double a;
    } floatcolor_t;

    typedef struct hslcolor {
        double h;
        double s;
        double l;
    } hslcolor_t;

    typedef struct point {
        double x;
        double y;
        double z;

        struct point add(struct point other) {
            return (struct point){
                x + other.x,
                y + other.y,
                z + other.z,
            };
        };
    } point_t;

    typedef struct matrix {
        double a11;
        double a12;
        double a13;
        double a21;
        double a22;
        double a23;
        double a31;
        double a32;
        double a33;
        double a41;
        double a42;
        double a43;

        point_t multiply_point(point_t point) {
            return (point_t){
                (a11 * point.x) + (a21 * point.y) + (a31 * point.z) + a41,
                (a12 * point.x) + (a22 * point.y) + (a32 * point.z) + a42,
                (a13 * point.x) + (a23 * point.y) + (a33 * point.z) + a43,
            };
        }
    } matrix_t;

    typedef struct work {
        intcolor_t *imgdata;
        unsigned char *maskdata;
        unsigned int imgwidth;
        unsigned int imgheight;
        unsigned int minx;
        unsigned int maxx;
        unsigned int miny;
        unsigned int maxy;
        intcolor_t *texdata;
        unsigned int texwidth;
        unsigned int texheight;
        double xscale;
        double yscale;
        matrix_t inverse;
        int use_perspective;
        floatcolor_t add_color;
        floatcolor_t mult_color;
        hslcolor_t hsl_shift;
        int blendfunc;
        pthread_t *thread;
        int aa_mode;
    } work_t;

    inline unsigned char clamp(double color) {
        return fmin(fmax(0.0, roundf(color)), 255.0);
    }

    inline unsigned int min(unsigned int x, unsigned int y) {
        return x < y ? x : y;
    }

    inline unsigned int max(unsigned int x, unsigned int y) {
        return x > y ? x : y;
    }

    void rgb_to_hsl(int r, int g, int b, double *h, double *s, double *l) {
        int cmax = max(max(r, g), b);
        int cmin = min(min(r, g), b);
        double sum = (double)(cmin + cmax);

        // First, calculate luminance, which is the sum divided by 2. We
        // also need to scale down by 255 since RGB values are integers!
        *l = sum / (2.0 * 255.0);
        if (cmax == cmin) {
            // No point in calculating anything else, its just luminance.
            *h = 0.0;
            *s = 0.0;
            return;
        }

        // Second, calculate saturation.
        double delta = (double)(cmax - cmin);
        if (*l <= 0.5) {
            // 255 scaling appears on both sides, so no need to handle it.
            *s = delta / sum;
        } else {
            // We need to remember to scale by 255 here, so let's factor it out.
            *s = delta / ((2.0 * 255) - sum);
        }

        // Finaly, calculate hue. This can theoretically go above 1.0 or below
        // 0.0 and most equations show it being clamped, but we need to clamp
        // again when converting back so don't bother wasting time.
        if (r == cmax) {
            *h = ((double)(g - b) / 6.0) / delta;
        } else if (g == cmax) {
            *h = (1.0 / 3.0) + ((double)(b - r) / 6.0) / delta;
        } else {
            *h = (2.0 / 3.0) + ((double)(r - g) / 6.0) / delta;
        }
    }

    inline double hue_to_rgb(double v1, double v2, double vh) {
        // Clamp hue value to 0.0/1.0, respecting the fact that 361 degrees is
        // equivalent to 1 degree, and negative 1 degree is equivalent to 359.
        if (vh < 0.0) {
            vh += 1.0;
        }
        if (vh >= 1.0) {
            vh -= 1.0;
        }

        // Split back into 3 quadrants since RGB isn't linear with in these,
        // there's a step function where at some point the slope goes from positive
        // to negative non-continuously.
        if ((6.0 * vh) < 1.0) {
            return v1 + ((v2 - v1) * 6.0 * vh);
        }
        if ((2.0 * vh) < 1.0) {
            return v2;
        }
        if ((3.0 * vh) < 2.0) {
            return v1 + ((v2 - v1) * ((2.0 / 3.0) - vh) * 6.0);
        }

        return v1;
    }

    void hsl_to_rgb(double h, double s, double l, unsigned char *r, unsigned char *g, unsigned char *b) {
        // Clamp hue value to 0.0/1.0, respecting the fact that 361 degrees is
        // equivalent to 1 degree, and negative 1 degree is equivalent to 359.
        while (h < 0.0) {
            h += 1.0;
        }
        while (h >= 1.0) {
            h -= 1.0;
        }
        s = fmin(fmax(s, 0.0), 1.0);
        l = fmin(fmax(l, 0.0), 1.0);

        if (s == 0.0) {
            *r = *g = *b = (int)(l * 255.0);
        } else {
            double v2 = (l < 0.5) ? (l * (1.0 + s)) : ((l + s) - (l * s));
            double v1 = (2.0 * l) - v2;

            *r = (unsigned char)(255.0 * hue_to_rgb(v1, v2, h + (1.0 / 3.0)));
            *g = (unsigned char)(255.0 * hue_to_rgb(v1, v2, h));
            *b = (unsigned char)(255.0 * hue_to_rgb(v1, v2, h - (1.0 / 3.0)));
        }
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
        double srcpercent = src.a / 255.0;
        double destpercent = dest.a / 255.0;
        double srcremainder = 1.0 - srcpercent;
        double new_alpha = fmin(fmax(0.0, srcpercent + destpercent * srcremainder), 1.0);
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
        double srcpercent = src.a / 255.0;
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
        double srcpercent = src.a / 255.0;
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
        double src_alpha = src.a / 255.0;
        double src_remainder = 1.0 - src_alpha;
        return (intcolor_t){
            clamp((255 * ((dest.r / 255.0) * (src.r / 255.0) * src_alpha)) + (dest.r * src_remainder)),
            clamp((255 * ((dest.g / 255.0) * (src.g / 255.0) * src_alpha)) + (dest.g * src_remainder)),
            clamp((255 * ((dest.b / 255.0) * (src.b / 255.0) * src_alpha)) + (dest.b * src_remainder)),
            dest.a,
        };
    }

    intcolor_t blend_overlay(
        intcolor_t dest,
        intcolor_t src
    ) {
        // "Overlay" blend mode. Various games use the DX equation Src * Dst + Dst * Src. It appears that
        // jubeat uses the alternative formula Src * Dst + Dst * (1 - As).

        // Calculate final color blending.
        return (intcolor_t){
            clamp((255 * (2.0 * (dest.r / 255.0) * (src.r / 255.0)))),
            clamp((255 * (2.0 * (dest.g / 255.0) * (src.g / 255.0)))),
            clamp((255 * (2.0 * (dest.b / 255.0) * (src.b / 255.0)))),
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
        hslcolor_t hsl_shift,
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

        // Add in hsl shift if there is anything to do.
        if (hsl_shift.h != 0.0 || hsl_shift.s != 0.0 || hsl_shift.l != 0.0) {
            hslcolor_t hslcolor;
            rgb_to_hsl(
                src_color.r,
                src_color.g,
                src_color.b,
                &hslcolor.h,
                &hslcolor.s,
                &hslcolor.l
            );

            hslcolor.h += hsl_shift.h;
            hslcolor.s += hsl_shift.s;
            hslcolor.l += hsl_shift.l;

            hsl_to_rgb(
                hslcolor.h,
                hslcolor.s,
                hslcolor.l,
                &src_color.r,
                &src_color.g,
                &src_color.b
            );
        }

        if (blendfunc == 3) {
            return blend_multiply(dest_color, src_color);
        }
        // TODO: blend mode 4, which is "screen" blending according to SWF references. I've only seen this
        // in Jubeat and it implements it using OpenGL equation Src * (1 - Dst) + Dst * 1.
        // TODO: blend mode 5, which is "lighten" blending according to SWF references. Jubeat does not
        // premultiply by alpha, but the GL/DX equation is max(Src * As, Dst * 1).
        // TODO: blend mode 6, which is "darken" blending according to SWF references. Jubeat does not
        // premultiply by alpha, but the GL/DX equation is min(Src * As, Dst * 1).
        if (blendfunc == 8) {
            return blend_addition(dest_color, src_color);
        }
        if (blendfunc == 9 || blendfunc == 70) {
            return blend_subtraction(dest_color, src_color);
        }
        // TODO: blend mode 10, which is "invert" according to SWF references. The only game I could find
        // that implemented this had equation Src * (1 - Dst) + Dst * (1 - As).
        if (blendfunc == 13) {
            return blend_overlay(dest_color, src_color);
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
        // Regardless of AA work, calculate the transform matrix for determining the stride for AA pixel lookups, since it
        // costs us almost nothing. Essentially what we're doing here is calculating the scale, clamping it at 1.0 as the
        // minimum and then setting the AA sample swing accordingly. This has the effect of anti-aliasing scaled up images
        // a bit softer than would otherwise be achieved.
        double xswing;
        double yswing;

        if (work->aa_mode == AA_MODE_UNSCALED_SSAA_ONLY) {
            xswing = 0.5;
            yswing = 0.5;
        } else {
            xswing = 0.5 * fmax(1.0, work->xscale);
            yswing = 0.5 * fmax(1.0, work->yscale);
        }

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
                if (work->aa_mode != AA_MODE_NONE) {
                    // Calculate what texture pixel data goes here.
                    int r = 0;
                    int g = 0;
                    int b = 0;
                    int a = 0;
                    int count = 0;
                    int denom = 0;

                    // First, figure out if we can use bilinear resampling. Bilinear seems to look
                    // awful on perspective transforms, so disable it for all of them.
                    int bilinear = 0;
                    if (work->aa_mode == AA_MODE_SSAA_OR_BILINEAR && work->xscale >= 1.0 && work->yscale >= 1.0) {
                        point_t aaloc = work->inverse.multiply_point((point_t){(double)(imgx + 0.5), (double)(imgy + 0.5)});
                        int aax = aaloc.x;
                        int aay = aaloc.y;

                        if (!(aax <= 0 || aay <= 0 || aax >= ((int)work->texwidth - 1) || aay >= ((int)work->texheight - 1))) {
                            bilinear = 1;
                        }
                    }

                    // Now perform the desired AA operation.
                    intcolor_t average;
                    if (bilinear) {
                        // Calculate the pixel we're after, and what percentage into the pixel we are.
                        int aax;
                        int aay;
                        double aaxrem;
                        double aayrem;

                        if (work->use_perspective) {
                            // We don't check for negative here, because we already checked it above and wouldn't
                            // have enabled bilinear interpoliation.
                            point_t texloc = work->inverse.multiply_point((point_t){(double)(imgx + 0.5), (double)(imgy + 0.5)});
                            double fx = texloc.x / texloc.z;
                            double fy = texloc.y / texloc.z;
                            aax = fx;
                            aay = fy;
                            aaxrem = fx - (double)aax;
                            aayrem = fy - (double)aay;
                        } else {
                            point_t texloc = work->inverse.multiply_point((point_t){(double)(imgx + 0.5), (double)(imgy + 0.5)});
                            aax = texloc.x;
                            aay = texloc.y;
                            aaxrem = texloc.x - (double)aax;
                            aayrem = texloc.y - (double)aay;
                        }

                        // Find the four pixels that we can interpolate from. The first number is the x, and second is y.
                        unsigned int tex00 = aax + (aay * work->texwidth);
                        unsigned int tex10 = tex00 + 1;
                        unsigned int tex01 = aax + ((aay + 1) * work->texwidth);
                        unsigned int tex11 = tex01 + 1;

                        // Calculate various scaling factors based on alpha and percentage.
                        double tex00percent = work->texdata[tex00].a / 255.0;
                        double tex10percent = work->texdata[tex10].a / 255.0;
                        double tex01percent = work->texdata[tex01].a / 255.0;
                        double tex11percent = work->texdata[tex11].a / 255.0;

                        double y0percent = (tex00percent * (1.0 - aaxrem)) + (tex10percent * aaxrem);
                        double y1percent = (tex01percent * (1.0 - aaxrem)) + (tex11percent * aaxrem);
                        double finalpercent = (y0percent * (1.0 - aayrem)) + (y1percent * aayrem);

                        if (finalpercent <= 0.0) {
                            // This pixel would be blank, so we avoid dividing by zero.
                            average = (intcolor_t){
                                255,
                                255,
                                255,
                                0,
                            };
                        } else {
                            // Interpolate in the X direction on both Y axis.
                            double y0r = ((work->texdata[tex00].r * tex00percent * (1.0 - aaxrem)) + (work->texdata[tex10].r * tex10percent * aaxrem));
                            double y0g = ((work->texdata[tex00].g * tex00percent * (1.0 - aaxrem)) + (work->texdata[tex10].g * tex10percent * aaxrem));
                            double y0b = ((work->texdata[tex00].b * tex00percent * (1.0 - aaxrem)) + (work->texdata[tex10].b * tex10percent * aaxrem));


                            double y1r = ((work->texdata[tex01].r * tex01percent * (1.0 - aaxrem)) + (work->texdata[tex11].r * tex11percent * aaxrem));
                            double y1g = ((work->texdata[tex01].g * tex01percent * (1.0 - aaxrem)) + (work->texdata[tex11].g * tex11percent * aaxrem));
                            double y1b = ((work->texdata[tex01].b * tex01percent * (1.0 - aaxrem)) + (work->texdata[tex11].b * tex11percent * aaxrem));

                            // Now interpolate the Y direction to get the final pixel value.
                            average = (intcolor_t){
                                (unsigned char)(((y0r * (1.0 - aayrem)) + (y1r * aayrem)) / finalpercent),
                                (unsigned char)(((y0g * (1.0 - aayrem)) + (y1g * aayrem)) / finalpercent),
                                (unsigned char)(((y0b * (1.0 - aayrem)) + (y1b * aayrem)) / finalpercent),
                                (unsigned char)(finalpercent * 255),
                            };
                        }
                    } else {
                        for (double addy = 0.5 - yswing; addy <= 0.5 + yswing; addy += yswing / 2.0) {
                            for (double addx = 0.5 - xswing; addx <= 0.5 + xswing; addx += xswing / 2.0) {
                                int aax = -1;
                                int aay = -1;

                                double xloc = (double)imgx + addx;
                                double yloc = (double)imgy + addy;
                                if (xloc < 0.0 || yloc < 0.0 || xloc >= (double)work->imgwidth || yloc >= (double)work->imgheight) {
                                    continue;
                                }

                                if (work->use_perspective) {
                                    point_t texloc = work->inverse.multiply_point((point_t){xloc, yloc});
                                    if (texloc.z > 0.0) {
                                        aax = texloc.x / texloc.z;
                                        aay = texloc.y / texloc.z;
                                    }
                                } else {
                                    point_t texloc = work->inverse.multiply_point((point_t){xloc, yloc});
                                    aax = texloc.x;
                                    aay = texloc.y;
                                }

                                // If we're out of bounds, don't update. Factor this in, however, so we can get partial
                                // transparency to the pixel that is already there.
                                denom ++;
                                if (aax < 0 || aay < 0 || aax >= (int)work->texwidth || aay >= (int)work->texheight) {
                                    continue;
                                }

                                // Grab the values to average, for SSAA. Make sure to factor in alpha as a poor-man's
                                // blend to ensure that partial transparency pixel values don't unnecessarily factor
                                // into average calculations.
                                unsigned int texoff = aax + (aay * work->texwidth);

                                // If this is a fully transparent pixel, the below formulas work out to adding nothing
                                // so we should skip this altogether.
                                if (work->texdata[texoff].a == 0) {
                                    continue;
                                }

                                double apercent = work->texdata[texoff].a / 255.0;
                                r += (int)(work->texdata[texoff].r * apercent);
                                g += (int)(work->texdata[texoff].g * apercent);
                                b += (int)(work->texdata[texoff].b * apercent);
                                a += work->texdata[texoff].a;
                                count ++;
                            }
                        }

                        if (count == 0) {
                            // None of the samples existed in-bounds.
                            continue;
                        }

                        // Average the pixels. Make sure to divide out the alpha in preparation for blending.
                        unsigned char alpha = (unsigned char)(a / denom);

                        if (alpha == 0) {
                            // Samples existed in bounds, but with zero alpha.
                            average = (intcolor_t){
                                255,
                                255,
                                255,
                                0,
                            };
                        } else {
                            // Samples existed in bounds, with some alpha component, un-premultiply it.
                            double apercent = alpha / 255.0;
                            average = (intcolor_t){
                                (unsigned char)((r / denom) / apercent),
                                (unsigned char)((g / denom) / apercent),
                                (unsigned char)((b / denom) / apercent),
                                alpha,
                            };
                        }
                    }

                    // Blend it.
                    work->imgdata[imgoff] = blend_point(work->add_color, work->mult_color, work->hsl_shift, average, work->imgdata[imgoff], work->blendfunc);
                } else {
                    // Grab the center of the pixel to get the color.
                    int texx = -1;
                    int texy = -1;

                    if (work->use_perspective) {
                        point_t texloc = work->inverse.multiply_point((point_t){(double)imgx + (double)0.5, (double)imgy + (double)0.5});
                        if (texloc.z > 0.0) {
                            texx = texloc.x / texloc.z;
                            texy = texloc.y / texloc.z;
                        }
                    } else {
                        point_t texloc = work->inverse.multiply_point((point_t){(double)imgx + (double)0.5, (double)imgy + (double)0.5});
                        texx = texloc.x;
                        texy = texloc.y;
                    }

                    // If we're out of bounds, don't update.
                    if (texx < 0 || texy < 0 || texx >= (int)work->texwidth || texy >= (int)work->texheight) {
                        continue;
                    }

                    // Blend it.
                    unsigned int texoff = texx + (texy * work->texwidth);
                    work->imgdata[imgoff] = blend_point(work->add_color, work->mult_color, work->hsl_shift, work->texdata[texoff], work->imgdata[imgoff], work->blendfunc);
                }
            }
        }
    }

    void *chunk_composite_worker(void *arg) {
        work_t *work = (work_t *)arg;
        chunk_composite_fast(work);
        return NULL;
    }

    int composite_fast(
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
        hslcolor_t hsl_shift,
        double xscale,
        double yscale,
        matrix_t inverse,
        int use_perspective,
        int blendfunc,
        unsigned char *texbytes,
        unsigned int texwidth,
        unsigned int texheight,
        unsigned int threads,
        unsigned int aa_mode
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
            work.imgheight = imgheight;
            work.minx = minx;
            work.maxx = maxx;
            work.miny = miny;
            work.maxy = maxy;
            work.texdata = texdata;
            work.texwidth = texwidth;
            work.texheight = texheight;
            work.xscale = xscale;
            work.yscale = yscale;
            work.inverse = inverse;
            work.add_color = add_color;
            work.mult_color = mult_color;
            work.hsl_shift = hsl_shift;
            work.blendfunc = blendfunc;
            work.aa_mode = aa_mode;
            work.use_perspective = use_perspective;

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
                work->imgheight = imgheight;
                work->minx = minx;
                work->maxx = maxx;
                work->miny = imgy;
                work->maxy = me ? maxy : imgy + step;
                work->texdata = texdata;
                work->texwidth = texwidth;
                work->texheight = texheight;
                work->xscale = xscale;
                work->yscale = yscale;
                work->inverse = inverse;
                work->add_color = add_color;
                work->mult_color = mult_color;
                work->hsl_shift = hsl_shift;
                work->blendfunc = blendfunc;
                work->thread = thread;
                work->aa_mode = aa_mode;
                work->use_perspective = use_perspective;

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
