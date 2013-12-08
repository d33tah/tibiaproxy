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

from tibiaproxy.NetworkMessage import NetworkMessage, adlerChecksum
from tibiaproxy import RSA
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
    0x01: 'EnterAccount',
    0x0A: 'PendingGame',
    0x0F: 'EnterGame',
    0x14: 'LeaveGame',
    0x1D: 'Ping',
    0x1E: 'PingBack',
    0x33: 'ChangeMapAwareRange',
    0x64: 'AutoWalk',
    0x65: 'WalkNorth',
    0x66: 'WalkEast',
    0x67: 'WalkSouth',
    0x68: 'WalkWest',
    0x69: 'Stop',
    0x6A: 'WalkNorthEast',
    0x6B: 'WalkSouthEast',
    0x6C: 'WalkSouthWest',
    0x6D: 'WalkNorthWest',
    0x6F: 'TurnNorth',
    0x70: 'TurnEast',
    0x71: 'TurnSouth',
    0x72: 'TurnWest',
    0x77: 'EquipItem',
    0x78: 'Move',
    0x79: 'InspectNpcTrade',
    0x7A: 'BuyItem',
    0x7B: 'SellItem',
    0x7C: 'CloseNpcTrade',
    0x7D: 'RequestTrade',
    0x7E: 'InspectTrade',
    0x7F: 'AcceptTrade',
    0x80: 'RejectTrade',
    0x82: 'UseItem',
    0x83: 'UseItemWith',
    0x84: 'UseOnCreature',
    0x85: 'RotateItem',
    0x87: 'CloseContainer',
    0x88: 'UpContainer',
    0x89: 'EditText',
    0x8A: 'EditList',
    0x8C: 'Look',
    0x8D: 'LookCreature',
    0x96: 'Talk',
    0x97: 'RequestChannels',
    0x98: 'JoinChannel',
    0x99: 'LeaveChannel',
    0x9A: 'OpenPrivateChannel',
    0x9B: 'OpenRuleViolation',
    0x9C: 'CloseRuleViolation',
    0x9D: 'CancelRuleViolation',
    0x9E: 'CloseNpcChannel',
    0xA0: 'ChangeFightModes',
    0xA1: 'Attack',
    0xA2: 'Follow',
    0xA3: 'InviteToParty',
    0xA4: 'JoinParty',
    0xA5: 'RevokeInvitation',
    0xA6: 'PassLeadership',
    0xA7: 'LeaveParty',
    0xA8: 'ShareExperience',
    0xA9: 'DisbandParty',
    0xAA: 'OpenOwnChannel',
    0xAB: 'InviteToOwnChannel',
    0xAC: 'ExcludeFromOwnChannel',
    0xBE: 'CancelAttackAndFollow',
    0xC9: 'UpdateTile',
    0xCA: 'RefreshContainer',
    0xD2: 'RequestOutfit',
    0xD3: 'ChangeOutfit',
    0xD4: 'Mount',
    0xDC: 'AddVip',
    0xDD: 'RemoveVip',
    0xE6: 'BugReport',
    0xE7: 'RuleViolation',
    0xE8: 'DebugReport',
    0xF0: 'RequestQuestLog',
    0xF1: 'RequestQuestLine',
    0xF2: 'NewRuleViolation',
    0xF3: 'RequestItemInfo',
    0xF4: 'MarketLeave',
    0xF5: 'MarketBrowse',
    0xF6: 'MarketCreate',
    0xF7: 'MarketCancel',
    0xF8: 'MarketAccept',
}

server_packet_types = {
    0x0A: 'LoginOrPendingState',
    0x0B: 'GMActions',
    0x0F: 'EnterGame',
    0x11: 'UpdateNeeded',
    0x14: 'LoginError',
    0x15: 'LoginAdvice',
    0x16: 'LoginWait',
    0x17: 'LoginSuccess',
    0x1D: 'PingBack',
    0x1E: 'Ping',
    0x1F: 'Challenge',
    0x28: 'Death',
    0x33: 'ChangeMapAwareRange',
    0x64: 'FullMap',
    0x65: 'MapTopRow',
    0x66: 'MapRightRow',
    0x67: 'MapBottomRow',
    0x68: 'MapLeftRow',
    0x69: 'UpdateTile',
    0x6A: 'CreateOnMap',
    0x6B: 'ChangeOnMap',
    0x6C: 'DeleteOnMap',
    0x6D: 'MoveCreature',
    0x6E: 'OpenContainer',
    0x6F: 'CloseContainer',
    0x70: 'CreateContainer',
    0x71: 'ChangeInContainer',
    0x72: 'DeleteInContainer',
    0x78: 'SetInventory',
    0x79: 'DeleteInventory',
    0x7A: 'OpenNpcTrade',
    0x7B: 'PlayerGoods',
    0x7C: 'CloseNpcTrade',
    0x7D: 'OwnTrade',
    0x7E: 'CounterTrade',
    0x7F: 'CloseTrade',
    0x82: 'Ambient',
    0x83: 'GraphicalEffect',
    0x84: 'TextEffect',
    0x85: 'MissleEffect',
    0x86: 'MarkCreature',
    0x87: 'Trappers',
    0x8C: 'CreatureHealth',
    0x8D: 'CreatureLight',
    0x8E: 'CreatureOutfit',
    0x8F: 'CreatureSpeed',
    0x90: 'CreatureSkull',
    0x91: 'CreatureParty',
    0x92: 'CreatureUnpass',
    0x93: 'CreatureMarks',
    0x94: 'PlayerHelpers',
    0x96: 'EditText',
    0x97: 'EditList',
    0x9F: 'PlayerDataBasic',
    0xA0: 'PlayerData',
    0xA1: 'PlayerSkills',
    0xA2: 'PlayerState',
    0xA3: 'ClearTarget',
    0xA4: 'SpellDelay',
    0xA5: 'SpellGroupDelay',
    0xA6: 'MultiUseDelay',
    0xA7: 'PlayerModes',
    0xAA: 'Talk',
    0xAB: 'Channels',
    0xAC: 'OpenChannel',
    0xAD: 'OpenPrivateChannel',
    0xAE: 'RuleViolationChannel',
    0xAF: 'RuleViolationRemove',
    0xB0: 'RuleViolationCancel',
    0xB1: 'RuleViolationLock',
    0xB2: 'OpenOwnChannel',
    0xB3: 'CloseChannel',
    0xB4: 'TextMessage',
    0xB5: 'CancelWalk',
    0xB6: 'WalkWait',
    0xBE: 'FloorChangeUp',
    0xBF: 'FloorChangeDown',
    0xC8: 'ChooseOutfit',
    0xD2: 'VipAdd',
    0xD3: 'VipState',
    0xD4: 'VipLogout',
    0xDC: 'TutorialHint',
    0xDD: 'AutomapFlag',
    0xF0: 'QuestLog',
    0xF1: 'QuestLine',
    0xF3: 'ChannelEvent',
    0xF4: 'ItemInfo',
    0xF5: 'PlayerInventory',
    0xF6: 'MarketEnter',
    0xF7: 'MarketLeave',
    0xF8: 'MarketDetail',
    0xF9: 'MarketBrowse',
}
