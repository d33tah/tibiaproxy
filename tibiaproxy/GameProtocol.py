"""
GameProtocol.py - contains code needed to handle the game protocol.
"""

"""
This file is part of tibiaproxy.

tibiaproxy is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Joggertester is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
"""

from NetworkMessage import NetworkMessage, adlerChecksum
import RSA
import struct


def create_handshake_challenge(timestamp, random_number):
    return {'timestamp': timestamp, 'random_number': random_number}


def create_handshake_reply(xtea_key, account_number, password, character_name,
                           timestamp, random_number, challenge_pos, first_16,
                           decrypted_raw):
    return {'xtea_key': xtea_key,
            'account_number': account_number,
            'password': password,
            'character_name': character_name,
            'timestamp': timestamp,
            'random_number': random_number,
            'challenge_pos': challenge_pos,
            'first_16': first_16,
            'decrypted_raw': decrypted_raw}


def parseChallengeMessage(msg):
    """Parse the first (server's) message from the game protocol.

    Args:
        msg (NetworkMessage): the network message to be parsed.

    Returns list
    """
    assert(msg.getU16() == 6)
    assert(msg.getByte() == 0x1F)
    timestamp = msg.getU32()
    random_number = msg.getByte()
    return create_handshake_challenge(timestamp, random_number)


def parseFirstMessage(orig_msg):
    """Parse the first (client's) message from the game protocol.

    Args:
        orig_msg (NetworkMessage): the network message to be parsed.

    Returns list
    """
    orig_msg.skipBytes(16)
    msg_buf = RSA.RSA_decrypt(orig_msg.getRest()[:128])
    msg = NetworkMessage(msg_buf)
    # Extract the XTEA keys from the RSA-decrypted message.
    xtea_key = [msg.getU32() for i in range(4)]
    assert(msg.getByte() == 0)        # gamemaster flag
    account_number = msg.getString()  # account
    character_name = msg.getString()  # character name
    password = msg.getString()        # password
    challenge_pos = msg.getPos()
    timestamp = msg.getU32()
    random_number = msg.getByte()
    return create_handshake_reply(xtea_key=xtea_key,
                                  account_number=account_number,
                                  password=password,
                                  character_name=character_name,
                                  timestamp=timestamp,
                                  random_number=random_number,
                                  challenge_pos=challenge_pos,
                                  first_16=orig_msg.getRaw()[:16],
                                  decrypted_raw=bytearray(msg_buf))


def prepareReply(handshake_reply, real_tibia):
    to_encrypt_raw = handshake_reply['decrypted_raw']
    to_encrypt_msg = NetworkMessage(to_encrypt_raw)
    to_encrypt_msg.skipBytes(handshake_reply['challenge_pos'])
    to_encrypt_msg.replaceU32(handshake_reply['timestamp'])
    to_encrypt_msg.replaceByte(handshake_reply['random_number'])
    to_encrypt = to_encrypt_msg.getRaw()
    first16_wo_headers = handshake_reply['first_16'][6:]
    if real_tibia:
        encrypted = RSA.RSA_encrypt(to_encrypt)
    else:
        encrypted = RSA.RSA_encrypt(to_encrypt, n=RSA.otserv_n)
    rest = first16_wo_headers + encrypted
    checksum = struct.pack("<I", adlerChecksum(rest))
    return (handshake_reply['first_16'][:2] + checksum + rest)

# Generated based on Edubart's OpenTibiaClient code:
#
# egrep '(Game|Client).*= ([0-9]){1,3},' ./src/client/protocolcodes.h | \
#     sed -e 's/GameServer//g' -e 's/Client//g'  | \
#     python -c 'while True:
#         print(
#             "%s: \"%s\"," % tuple(
#                 reversed(
#                     raw_input().split(",")[0].replace(" ","").split("=")
#                 )
#             )
#         )' | sort -n | uniq | grep -v '50:'
packet_types = {
    1: "EnterAccount",
    10: "LoginOrPendingState",
    10: "PendingGame",
    11: "GMActions",
    15: "EnterGame",
    17: "UpdateNeeded",
    20: "LeaveGame",
    20: "LoginError",
    21: "LoginAdvice",
    22: "LoginWait",
    23: "LoginSuccess",
    29: "Ping",
    29: "PingBack",
    30: "Ping",
    30: "PingBack",
    31: "Challenge",
    40: "Death",
    51: "ChangeMapAwareRange",
    100: "AutoWalk",
    100: "FullMap",
    101: "MapTopRow",
    101: "WalkNorth",
    102: "MapRightRow",
    102: "WalkEast",
    103: "MapBottomRow",
    103: "WalkSouth",
    104: "MapLeftRow",
    104: "WalkWest",
    105: "Stop",
    105: "UpdateTile",
    106: "CreateOnMap",
    106: "WalkNorthEast",
    107: "ChangeOnMap",
    107: "WalkSouthEast",
    108: "DeleteOnMap",
    108: "WalkSouthWest",
    109: "MoveCreature",
    109: "WalkNorthWest",
    110: "OpenContainer",
    111: "CloseContainer",
    111: "TurnNorth",
    112: "CreateContainer",
    112: "TurnEast",
    113: "ChangeInContainer",
    113: "TurnSouth",
    114: "DeleteInContainer",
    114: "TurnWest",
    119: "EquipItem",
    120: "Move",
    120: "SetInventory",
    121: "DeleteInventory",
    121: "InspectNpcTrade",
    122: "BuyItem",
    122: "OpenNpcTrade",
    123: "PlayerGoods",
    123: "SellItem",
    124: "CloseNpcTrade",
    125: "OwnTrade",
    125: "RequestTrade",
    126: "CounterTrade",
    126: "InspectTrade",
    127: "AcceptTrade",
    127: "CloseTrade",
    128: "RejectTrade",
    130: "Ambient",
    130: "UseItem",
    131: "GraphicalEffect",
    131: "UseItemWith",
    132: "TextEffect",
    132: "UseOnCreature",
    133: "MissleEffect",
    133: "RotateItem",
    134: "MarkCreature",
    135: "CloseContainer",
    135: "Trappers",
    136: "UpContainer",
    137: "EditText",
    138: "EditList",
    140: "CreatureHealth",
    140: "Look",
    141: "CreatureLight",
    141: "LookCreature",
    142: "CreatureOutfit",
    143: "CreatureSpeed",
    144: "CreatureSkull",
    145: "CreatureParty",
    146: "CreatureUnpass",
    147: "CreatureMarks",
    148: "PlayerHelpers",
    151: "EditList",
    151: "RequestChannels",
    152: "JoinChannel",
    153: "LeaveChannel",
    154: "OpenPrivateChannel",
    155: "OpenRuleViolation",
    156: "CloseRuleViolation",
    157: "CancelRuleViolation",
    158: "CloseNpcChannel",
    159: "PlayerDataBasic",
    160: "ChangeFightModes",
    160: "PlayerData",
    161: "Attack",
    161: "PlayerSkills",
    162: "Follow",
    162: "PlayerState",
    163: "ClearTarget",
    163: "InviteToParty",
    164: "JoinParty",
    164: "SpellDelay",
    165: "RevokeInvitation",
    165: "SpellGroupDelay",
    166: "MultiUseDelay",
    166: "PassLeadership",
    167: "LeaveParty",
    167: "PlayerModes",
    168: "ShareExperience",
    169: "DisbandParty",
    170: "OpenOwnChannel",
    170: "Talk",
    171: "Channels",
    171: "InviteToOwnChannel",
    172: "ExcludeFromOwnChannel",
    172: "OpenChannel",
    173: "OpenPrivateChannel",
    174: "RuleViolationChannel",
    175: "RuleViolationRemove",
    176: "RuleViolationCancel",
    177: "RuleViolationLock",
    178: "OpenOwnChannel",
    179: "CloseChannel",
    180: "TextMessage",
    181: "CancelWalk",
    182: "WalkWait",
    190: "CancelAttackAndFollow",
    190: "FloorChangeUp",
    191: "FloorChangeDown",
    200: "ChooseOutfit",
    201: "UpdateTile",
    202: "RefreshContainer",
    210: "RequestOutfit",
    210: "VipAdd",
    211: "ChangeOutfit",
    211: "VipState",
    212: "Mount",
    212: "VipLogout",
    220: "AddVip",
    220: "TutorialHint",
    221: "AutomapFlag",
    221: "RemoveVip",
    230: "BugReport",
    231: "RuleViolation",
    232: "DebugReport",
    240: "QuestLog",
    240: "RequestQuestLog",
    241: "QuestLine",
    241: "RequestQuestLine",
    242: "NewRuleViolation",
    243: "ChannelEvent",
    243: "RequestItemInfo",
    244: "ItemInfo",
    244: "MarketLeave",
    245: "MarketBrowse",
    245: "PlayerInventory",
    246: "MarketCreate",
    246: "MarketEnter",
    247: "MarketCancel",
    247: "MarketLeave",
    248: "MarketAccept",
    248: "MarketDetail",
    249: "MarketBrowse",
}
