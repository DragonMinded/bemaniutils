#include <stdio.h>
#include <math.h>

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
        float srcremaineder = 1.0 - srcpercent;
        float new_alpha = (srcpercent + destpercent * srcremaineder);
        return (intcolor_t){
            clamp(((dest.r * destpercent * srcremaineder) + (src.r * srcpercent)) / new_alpha),
            clamp(((dest.g * destpercent * srcremaineder) + (src.g * srcpercent)) / new_alpha),
            clamp(((dest.b * destpercent * srcremaineder) + (src.b * srcpercent)) / new_alpha),
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
            dest.a,
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

    intcolor_t blend_point(
        intcolor_t add_color,
        floatcolor_t mult_color,
        intcolor_t src_color,
        intcolor_t dest_color,
        int blendfunc
    ) {
        // Calculate multiplicative and additive colors against the source.
        src_color = (intcolor_t){
            clamp((src_color.r * mult_color.r) + add_color.r),
            clamp((src_color.g * mult_color.g) + add_color.g),
            clamp((src_color.b * mult_color.b) + add_color.b),
            clamp((src_color.a * mult_color.a) + add_color.a),
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
        // TODO: blend mode 75, which is not in the SWF spec and appears to have the equation
        // Src * (1 - Dst) + Dst * (1 - Src).
        return blend_normal(dest_color, src_color);
    }

    int affine_composite_fast(
        unsigned char *imgbytes,
        unsigned int imgwidth,
        unsigned int imgheight,
        unsigned int minx,
        unsigned int maxx,
        unsigned int miny,
        unsigned int maxy,
        intcolor_t add_color,
        floatcolor_t mult_color,
        matrix_t inverse,
        point_t origin,
        int blendfunc,
        unsigned char *texbytes,
        unsigned int texwidth,
        unsigned int texheight,
        int single_threaded
    ) {
        // Cast to a usable type.
        intcolor_t *imgdata = (intcolor_t *)imgbytes;
        intcolor_t *texdata = (intcolor_t *)texbytes;

        for (unsigned int imgy = miny; imgy < maxy; imgy++) {
            for (unsigned int imgx = minx; imgx < maxx; imgx++) {
                // Determine offset.
                unsigned int imgoff = imgx + (imgy * imgwidth);

                // Calculate what texture pixel data goes here.
                point_t texloc = inverse.multiply_point((point_t){(float)imgx, (float)imgy}).add(origin);
                int texx = roundf(texloc.x);
                int texy = roundf(texloc.y);

                // If we're out of bounds, don't update.
                if (texx < 0 or texy < 0 or texx >= (int)texwidth or texy >= (int)texheight) {
                    continue;
                }

                // Blend it.
                unsigned int texoff = texx + (texy * texwidth);
                imgdata[imgoff] = blend_point(add_color, mult_color, texdata[texoff], imgdata[imgoff], blendfunc);
            }
        }

        return 0;
    }
}
