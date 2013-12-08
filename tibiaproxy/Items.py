
import struct

ThingAttrGround = 0
ThingAttrGroundBorder = 1
ThingAttrOnBottom = 2
ThingAttrOnTop = 3
ThingAttrContainer = 4
ThingAttrStackable = 5
ThingAttrForceUse = 6
ThingAttrMultiUse = 7
ThingAttrWritable = 8
ThingAttrWritableOnce = 9
ThingAttrFluidContainer = 10
ThingAttrSplash = 11
ThingAttrNotWalkable = 12
ThingAttrNotMoveable = 13
ThingAttrBlockProjectile = 14
ThingAttrNotPathable = 15
ThingAttrPickupable = 16
ThingAttrHangable = 17
ThingAttrHookSouth = 18
ThingAttrHookEast = 19
ThingAttrRotateable = 20
ThingAttrLight = 21
ThingAttrDontHide = 22
ThingAttrTranslucent = 23
ThingAttrDisplacement = 24
ThingAttrElevation = 25
ThingAttrLyingCorpse = 26
ThingAttrAnimateAlways = 27
ThingAttrMinimapColor = 28
ThingAttrLensHelp = 29
ThingAttrFullGround = 30
ThingAttrLook = 31
ThingAttrCloth = 32
ThingAttrMarket = 33
ThingAttrUsable = 34

# additional
ThingAttrOpacity = 100
ThingAttrNotPreWalkable = 101

ThingAttrNoMoveAnimation = 253
ThingAttrChargeable = 254
ThingLastAttr = 255

NumCategories = 4

def load_item(f):
    done = False
    while True:
        attr = ord(f.read(1))

        if attr == ThingLastAttr:
            done = True
            break

        if attr == 16:
            attr = ThingAttrNoMoveAnimation
        elif attr > 16:
            attr -= 1

        if attr == ThingAttrDisplacement:
            f.read(4)

        if attr == ThingAttrLight:
            f.read(4)

        if attr == ThingAttrMarket:
            f.read(6)
            skip = struct.unpack("<H", f.read(2))[0]
            f.read(skip)
            f.read(4)

        if attr == ThingAttrUsable or attr == ThingAttrElevation:
            f.read(2)

        if attr in [ThingAttrGround, ThingAttrWritable, ThingAttrWritableOnce,
                    ThingAttrMinimapColor, ThingAttrCloth, ThingAttrLensHelp]:
            f.read(2)

    assert(done)

    w = ord(f.read(1))
    h = ord(f.read(1))
    area = w*h
    if w > 1 or h > 1:
        f.read(1)
    layers = ord(f.read(1))
    numPatternX = ord(f.read(1))
    numPatternY = ord(f.read(1))
    numPatternZ = ord(f.read(1))
    animationPhases = ord(f.read(1))
    totalSprites = area * layers * numPatternX * numPatternY * numPatternZ * animationPhases
    assert(totalSprites <= 4096)
    for i in range(totalSprites):
        f.read(4)

def load_items(filename="Tibia.dat"):
    f = open("Tibia.dat")
    f.read(4) # skip the checksum
    numItems = [ None for i in range(NumCategories) ]
    items = {}
    for i in range(NumCategories):
        numItems[i] = struct.unpack("<H", f.read(2))[0] + 1
    for i in range(NumCategories):
        firstId = 1
        lastId = numItems[i]
        if i == 0:
            firstId += 100
        for itemId in range(firstId, lastId):
            items[itemId] = load_item(f)

if __name__ == "__main__":
    load_items()
