"""
GameProtocol.py - contains code needed to handle the game protocol.
"""

# This file is part of tibiaproxy.
#
# tibiaproxy is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Joggertester is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Foobar; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

from NetworkMessage import NetworkMessage, adlerChecksum
import RSA
import struct


def create_handshake_challenge(timestamp, random_number):
    """Create a handshake challenge dictionary based on the given parameters.

    Args:
        timestamp (int): the challenge's timestamp
        random_number (int): the challenge random number
    Returns dict
    """
    return {'timestamp': timestamp, 'random_number': random_number}


def create_handshake_reply(xtea_key, account_number, password, character_name,
                           timestamp, random_number, challenge_pos, first_16,
                           decrypted_raw):
    """Create a handshake reply dictionary. This is the first packet the client
    sends to the game server.

    Args:
        xtea_key (int): the XTEA key used in further communication
        account_number (string): the account ID
        password (string): the account password
        character_name (string): the character to be logged in
        timestamp (int) the challenge's timestamp response
        random_number (int): the challenge's random number response
        challenge_pos (int): the offset at which the challenge can be found
        first_16 (int): the first 16 bytes of the original message
        decrypted_raw (bytearray): the unencrypted original message

    Returns dict
    """
    # FIXME: decrypted_raw feels odd. There should be a better way.
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
    xtea_key = [msg.getU32() for _ in range(4)]
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
    """Create a handshake reply based on the dictionary from the argument that
    has a modified challenge response.

    handshake_reply (dict): the origina handshake reply dictionary
    real_tibia (bool): whether to reencrypt the message for real Tibia

    Returns bytearray
    """

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
# TYPE="GameServer"
# egrep $TYPE'.*= ([0-9]){1,3},' ./src/client/protocolcodes.h | \
#     sed -e "s/$TYPE//g"   | \
#     python -c 'while True:
#         print(
#             "%s: \"%s\"," % tuple(
#                 reversed(
#                     raw_input().split(",")[0].replace(" ","").split("=")
#                 )
#             )
#         )' | sort -n | uniq | grep -v '^50:'
client_packet_types = {
    1: "EnterAccount",
    10: "PendingGame",
    15: "EnterGame",
    20: "LeaveGame",
    29: "Ping",
    30: "PingBack",
    51: "ChangeMapAwareRange",
    100: "AutoWalk",
    101: "WalkNorth",
    102: "WalkEast",
    103: "WalkSouth",
    104: "WalkWest",
    105: "Stop",
    106: "WalkNorthEast",
    107: "WalkSouthEast",
    108: "WalkSouthWest",
    109: "WalkNorthWest",
    111: "TurnNorth",
    112: "TurnEast",
    113: "TurnSouth",
    114: "TurnWest",
    119: "EquipItem",
    120: "Move",
    121: "InspectNpcTrade",
    122: "BuyItem",
    123: "SellItem",
    124: "CloseNpcTrade",
    125: "RequestTrade",
    126: "InspectTrade",
    127: "AcceptTrade",
    128: "RejectTrade",
    130: "UseItem",
    131: "UseItemWith",
    132: "UseOnCreature",
    133: "RotateItem",
    135: "CloseContainer",
    136: "UpContainer",
    137: "EditText",
    138: "EditList",
    140: "Look",
    141: "LookCreature",
    150: "Talk",
    151: "RequestChannels",
    152: "JoinChannel",
    153: "LeaveChannel",
    154: "OpenPrivateChannel",
    155: "OpenRuleViolation",
    156: "CloseRuleViolation",
    157: "CancelRuleViolation",
    158: "CloseNpcChannel",
    160: "ChangeFightModes",
    161: "Attack",
    162: "Follow",
    163: "InviteToParty",
    164: "JoinParty",
    165: "RevokeInvitation",
    166: "PassLeadership",
    167: "LeaveParty",
    168: "ShareExperience",
    169: "DisbandParty",
    170: "OpenOwnChannel",
    171: "InviteToOwnChannel",
    172: "ExcludeFromOwnChannel",
    190: "CancelAttackAndFollow",
    201: "UpdateTile",
    202: "RefreshContainer",
    210: "RequestOutfit",
    211: "ChangeOutfit",
    212: "Mount",
    220: "AddVip",
    221: "RemoveVip",
    230: "BugReport",
    231: "RuleViolation",
    232: "DebugReport",
    240: "RequestQuestLog",
    241: "RequestQuestLine",
    242: "NewRuleViolation",
    243: "RequestItemInfo",
    244: "MarketLeave",
    245: "MarketBrowse",
    246: "MarketCreate",
    247: "MarketCancel",
    248: "MarketAccept",
}

server_packet_types = {
    10: "LoginOrPendingState",
    11: "GMActions",
    15: "EnterGame",
    17: "UpdateNeeded",
    20: "LoginError",
    21: "LoginAdvice",
    22: "LoginWait",
    23: "LoginSuccess",
    29: "PingBack",
    30: "Ping",
    31: "Challenge",
    40: "Death",
    51: "ChangeMapAwareRange",
    100: "FullMap",
    101: "MapTopRow",
    102: "MapRightRow",
    103: "MapBottomRow",
    104: "MapLeftRow",
    105: "UpdateTile",
    106: "CreateOnMap",
    107: "ChangeOnMap",
    108: "DeleteOnMap",
    109: "MoveCreature",
    110: "OpenContainer",
    111: "CloseContainer",
    112: "CreateContainer",
    113: "ChangeInContainer",
    114: "DeleteInContainer",
    120: "SetInventory",
    121: "DeleteInventory",
    122: "OpenNpcTrade",
    123: "PlayerGoods",
    124: "CloseNpcTrade",
    125: "OwnTrade",
    126: "CounterTrade",
    127: "CloseTrade",
    130: "Ambient",
    131: "GraphicalEffect",
    132: "TextEffect",
    133: "MissleEffect",
    134: "MarkCreature",
    135: "Trappers",
    140: "CreatureHealth",
    141: "CreatureLight",
    142: "CreatureOutfit",
    143: "CreatureSpeed",
    144: "CreatureSkull",
    145: "CreatureParty",
    146: "CreatureUnpass",
    147: "CreatureMarks",
    148: "PlayerHelpers",
    150: "EditText",
    151: "EditList",
    159: "PlayerDataBasic",
    160: "PlayerData",
    161: "PlayerSkills",
    162: "PlayerState",
    163: "ClearTarget",
    164: "SpellDelay",
    165: "SpellGroupDelay",
    166: "MultiUseDelay",
    167: "PlayerModes",
    170: "Talk",
    171: "Channels",
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
    190: "FloorChangeUp",
    191: "FloorChangeDown",
    200: "ChooseOutfit",
    210: "VipAdd",
    211: "VipState",
    212: "VipLogout",
    220: "TutorialHint",
    221: "AutomapFlag",
    240: "QuestLog",
    241: "QuestLine",
    243: "ChannelEvent",
    244: "ItemInfo",
    245: "PlayerInventory",
    246: "MarketEnter",
    247: "MarketLeave",
    248: "MarketDetail",
    249: "MarketBrowse",
}
