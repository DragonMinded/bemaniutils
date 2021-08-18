# AFP Animation Format

As far back as I can see, Konami has used an animation format that I refer to as
AFP in virtually all of their games. Basically, if it runs on a PC, it probably
has a variant of AFP running on it. This also goes for several of their commercial
PC titles, some console titles and mobile titles as well. The name "AFP" comes
from the library that implements most of the format but I have no idea what this
actually stands for. In very old PC-based arcade games such as The\*BishiBashi the
library code makes references to Flash. If it encounters a plain SWF file it returns
an error stating that old data is not supported and encouraging the artist to
convert the data to the "new" format. Many other similarities between SWF and AFP
are present including a legacy bytecode table that is identical to Flash, a tag ID
to string function that matches Flash exactly up to the point where Konami started
adding their own, and the fact that the core engine works identically down to the
affine transformations, additive and multiplicative colors, tag system, blending
modes, masking and a whole host of other things.

At some point, most of the old SWF code was removed from the project. A modern
AFP library is almost unrecognizeable from a classic one, save for some basic
code that parses the still-supported tags. The legacy SWF bytecode parser has
been removed completely, support for recognizing vanilla SWF tags has been removed,
and support for bytecode that is interactive in nature has been removed leaving
only the shell of a bytecode engine that can update properties for effects such
as applying masks, setting objects visible or invisible and rewinding/advancing
individual sprites on the main canvas. While Konami appears to have put a decent
effort into making all of their format changes purely additive, if one was to
try to render an animation from an older game inside a newer game's engine it
would not be a surprise if the resulting graphics were subtly wrong.

The AFP file format itself is not an all-encompassing container. It superficially
resembles a SWF file but has an entirely different header and different ways of
encoding the tags and optional features of the format. Curiously, one cannot decode
a chunk of AFP data without the corresponding BSI data which is simply a list of
locations to byteswap as well as the length to byteswap. This appears to be a
rudimentary way of hiding plain strings in the AFP data itself so that they can't
be found in a hex editor. The byteswap instructions are trivial as well as reversible.
Along with AFP data, one would need shape structures as well as textures. These are
not found inside the AFP data but are instead inside a parent container. For older
games this is a TXP2 file which contains special sections for texture sheets,
individual textures, shapes, fonts, AFP data and BSI data. For newer games this is
a standard Konami IFS file where the AFP data is found in the `afp/` folder, the
BSI data is found in the `afp/bsi/` folder, the shapes are found in the `geo/`
folder and the textures are found in the `tex/` folder. Aside from container format
differences the underlying files are identically parsed and have equivalent
meanings regardless of where one unpacks them from.

The basic concept of how an animation is stored and represented is fairly simple.
Each animation has a specified number of frames and there is a lookup table in
the AFP header specifying which tags should be acted upon for each frame. To play
an animation, one must act upon each tag for a frame and then display or save the
resulting image. Tags have actions such as defining a shape or sprite for later
use, requests to place a previously defined shape or sprite on the canvas,
requests to update the properties of a previously placed object on the canvas,
requests to delete a previously placed object from the canvas and arbitrary
bytecode to execute as part of the frame's processing. Placed objects on the
canvas each have an associated additive and multiplicative color to apply to them
before blending, a blending mode such as normal, additive or subtractive, an
affine or perspective transform matrix used to determine how to position the
object and finally either a bounding box for a solid color rectangle, a reference
to a texture or a list of child objects to treat as a single sprite. Objects are
placed onto their own depth planes and rendered from lowest plane to highest plane
one by one until the final frame has been constructed.

# Tags

Since tags are the heart of the format (as they are in SWF files), I go into a bit
more detail about the crucial ones here. In the older versions of the format
vanilla SWF tags could also be used but they are documented elsewhere online and
in practice have never been seen inside an AFP animation.

## AP2 Shape Tag

The shape tag defines a shape (either a reference to a texture quad or a solid
color rectangle) and assigns it an internal ID for later use. Both texture quads
and solid rectangles are represented by the same shape structure which contains
the shape's bounding rectangle, UV vertex points and draw parameters (such as whether
this shape is a rectangle or a quad in the first place). If the shape is a texture
quad the structure will also include a string reference to the name of the texture
itself. The UV coordinates and bounding rectangle are always identical to the size
of the referenced texture in the case of texture quad shapes and appear to be in
the format simply to pass forward to a graphics card. Acting upon a shape tag means
adding the shape to an internal library of objects that can be placed on the canvas.

## AP2 Image Tag

This appears to be functionally identical to a shape, save for missing all of the
graphics card coordinates. Instead of pointing at a shape structure, image tags point
directly at a texture itself. Acting upon an image tag means adding the image to an
internal library of objects that can be placed on the canvas in a similar manner to
a shape.

## AP2 Sprite Tag

The sprite tag defines a sprite, which in SWF and AFP nomenclature just means an
embedded animation complete with its own list of frames and tags. In reality, the root
animation itself can be seen as a sprite tag, and in fact the format allows importing
another animation as a sprite to be placed on the canvas just like an image or shape.
Sprites are handy because they allow an animator to define things like characters with
their own shapes, transform and move the objects that make up those characters, and then
later place the character on the canvas just like a shape or image. As you might expect,
since a sprite is just a set of tags to act upon each frame, sprites can include their
own child sprites indefinitely. Acting upon a sprite tag means adding the sprite to
an internal library of objects that can be placed on the canvas.

## AP2 Place Object Tag

The place object tag is the meat of the format. Place object tags specify a placed
object ID to refer later to the placed object as well as a depth to place the object
on. They refer to sprites, images and shapes by their registered ID. They can come in
one of two flavors: create or update. In create mode, a new object is placed onto the
canvas at the specified depth. That object is looked up in the internal library of
objects that was previously added to in a shape, image or sprite tag. In update mode,
a previously placed object is looked up by object ID and depth and its properties are
updated to match the update tag's specifications. In both cases, the place object tag
can include a blend mode, an affine or projection transform, an additive and
multiplicative color and a few other properties. The blend mode and colors specify to
the renderer how to combine the pixels of the placed object with other objects that are
placed on the canvas. The transform specifies how the object is positioned, rotated and
stretched. Using a series of updates, an animator could rotate an object, move its
position on the canvas, change its transparency to fade it in or out and basically any
other operation.

Acting upon a place object tag means placing a new object on the canvas to be
rendered this frame or updating an existing object with new properties which will be
rendered this frame. Objects that are already on the canvas and not updated by a
place object tag will keep their properties and be rendered identically on subsequent
frames. The only exception to this is placed sprites, which automatically advance to
the next frame of their own embedded animation in order to render correctly.

## AP2 Remove Object Tag

The remove object tag looks up an object previously placed by a place object tag and
removes it from the canvas. It can either remove an object by object ID and depth or
it can remove the last placed object on a particular depth. Acting upon a remove object
tag means removing an existing object from the canvas so that it is not rendered on
this frame or subsequent frames.

## AP2 Do Action Tag

The do action tag executes AFP bytecode in order to perform some action. This can mean
requesting a mask to be applied to a placed object, requesting a placed sprite be
advanced or rewound to a specific frame, requesting a placed object be made invisible
or a host of other useful effects. AFP animations use this to provide looping effects
on sprites since the format does not natively support loops. They also use this to
apply masks to placed objects as the format does not natively support defining a mask.
Originally do action tags could also provide interactivity such as in The\*BishiBashi
where the levels themselves were implemented entirely in AFP files and played using
bytecode to read inputs, check game scores and the like. Modern games have stripped
this functionality out and only use it to provide a few useful hooks such as the above
documented effects and things such as triggering sounds to play or informing other
systems what frame of the animation is being rendered.

Acting upon a do action tag means using a bytecode interpreter to execute the bytecode
and apply the desired property changes to the currently placed objects on the canvas.
Note also that the place object tag supports bytecode triggers including an "on load"
trigger that requires bytecode to be executed when the object is placed. So, bytecode
can be found in two different locations but is executed identically either way.

## AP2 Place Camera Tag

The place camera tag registers a camera by specifying where in 3D the camera is and
the focal length from the camera to the render plane. The camera always looks straight
down at the canvas and the focal length in practice alwys matches the Z offset of the
camera. This is only used in conjunction with objects that have a perspective transform
to correctly render the object based on its depth in the Z plane. Acting upon a place
camera tag means storing where the camera is for future projection perspective renders
when the engine goes to display all of the placed objects for a frame.

# Quirks

No format that is this complex will be without its quirks. At some point, Konami
hacked in 3D perspective support to the format. This is extremely rudimentary
and only allows for a camera looking straight down at the canvas and for 2D
quads to be transformed using a 3D perspective transform. Its my best guess that
artists were tired of having to render out individual frames and specify them
in order to achieve correct 3D rotation of arbitrary objects so this system was
put in place. There is no culling, no normals, no depth buffer, FOV, nothing. It
exists simply as a way to specify what depth to project a 2D quad that has been
rotated in 3D space. This is used in newer games mostly for perspective-correct
rotation of objects such as records.

Now, unlike the 2D portion which was based on Flash and has had some 15 or so
years of testing to mature, the 3D portion is much more hacked in and has a host
of quriks. For instance, it appears that they did not do perspective-based masking
correctly and as such some animations which should have masking animations applied
to them appear to do so incorrectly. They also appear to have a bug where specifying
3D perspective projection on an object in a sprite and then placing that sprite
down on the main canvas results in a 2D affine projection instead of a 3D one.
These are all subtle enough that its quite possible QA never caught the problem or
the artist complained and was told it was not a big enough deal to fix.

I briefly considered having a compatibility quirks flag system in order to attempt
to fix these issues and present a renderer that exactly matches what games do.
The problem with that is that this renderer already attempts to be compatible
with about a decade and a half of format changes. Given how much of the format
has been ripped out for newer games, this is already an impossible task. I would
also have to spend a great deal more time trying to figure out exactly HOW they
got these things subtly wrong to replicate them versus understanding how the format
was intended to work. I've made the decision that it is not worth my time to do so.

# References

Much of the understanding of this format came from the various online SWF file format
references as so much of the format mirrors Flash even today. Detailed documentation
on the format itself is entirely missing but the code in this directory provides a
working reference implementation of the format. Wherever this document is vague or
confusing, please refer to the code in `swf.py` for how to parse AFP, `render.py` for
how to render AFP, `container.py` for how to parse TXP2 files and `geo.py` for how to
parse shape structures. Please also refer to `decompile.py` for a ton of details on
how the bytecode itself works.
