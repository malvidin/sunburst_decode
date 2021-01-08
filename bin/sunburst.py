#!/usr/env python
# -*- coding:utf-8 -*-
import re
import random
from itertools import permutations


from datetime import datetime, timedelta
try:
    from enum import Flag
except ImportError:
    pass


try:
    class SecurityApps(Flag):
        WINDOWS_DEFENDER_RUNNING = 0x0001
        WINDOWS_DEFENDER_STOPPED = 0x0002
        WINDOWS_DEFENDER_ATP_RUNNING = 0x0004
        WINDOWS_DEFENDER_ATP_STOPPED = 0x0008
        MS_DEFENDER_FOR_IDENTITY_RUNNING = 0x0010
        MS_DEFENDER_FOR_IDENTITY_STOPPED = 0x0020
        CARBON_BLACK_RUNNING = 0x0040
        CARBON_BLACK_STOPPED = 0x0080
        CROWDSTRIKE_RUNNING = 0x0100
        CROWDSTRIKE_STOPPED = 0x0200
        FIREEYE_RUNNING = 0x0400
        FIREEYE_STOPPED = 0x0800
        ESET_RUNNING = 0x1000
        ESET_STOPPED = 0x2000
        FSECURE_RUNNING = 0x4000
        FSECURE_STOPPED = 0x8000
except:
    pass


def make_trans(text_in, text_out):
    try:
        if isinstance(text_in, bytes):
            trans = bytes.maketrans(text_in, text_out)
        else:
            trans = str.maketrans(text_in, text_out)
    except:
        import string
        trans = string.maketrans(text_in, text_out)
    return trans


def custom_base32encode(input_bytes, rt=True):
    text = 'ph2eifo3n5utg1j8d94qrvbmk0sal76c'
    ret_string = ''

    bits_on_stack = 0
    bit_stack = 0
    for ch in input_bytes:
        bit_stack |= ord(ch) << bits_on_stack
        bits_on_stack += 8
        while bits_on_stack >= 5:
            ret_string += text[bit_stack & 0b11111]
            bit_stack >>= 5
            bits_on_stack -= 5
    if bits_on_stack > 0:
        if rt:
            ret_string += text[bit_stack & 0b11111]
    return ret_string


def custom_base32decode(input_string, rt=True, bits_on_stack=0, bit_stack=0):
    text = 'ph2eifo3n5utg1j8d94qrvbmk0sal76c'
    ret_bytes = b''
    for ch in input_string:
        bit_stack |= text.find(ch) << bits_on_stack
        bits_on_stack += 5
        if bits_on_stack >= 8:
            ret_bytes += bytes(bytearray([bit_stack & 255]))
            bit_stack >>= 8
            bits_on_stack -= 8
    if bits_on_stack > 0 and bit_stack > 0:
        if rt:
            ret_bytes += ' (0b{:06b}, {})'.format(bit_stack & 255, bits_on_stack).encode()
    return bytearray(ret_bytes)


def encode_sub_cipher(input_string):
    text = 'rq3gsalt6u1iyfzop572d49bnx8cvmkewhj'
    text_spec = '0_-.'
    trans = make_trans(text, text[4:] + text[:4])
    trans_string = input_string.translate(trans)
    # Use # to track the special substitutions
    re_spec = '([{}])'.format(re.escape(text_spec))
    trans_string = re.sub(re_spec, r'#\1', trans_string)
    # make the substitutions based on the text replacement string
    spec_choices = {k: text[i::len(text_spec)] for i, k in enumerate(text_spec)}
    while '#' in trans_string:
        idx = trans_string.find('#')
        trans_char = trans_string[idx + 1]
        trans_string = trans_string[:idx] + \
                       '{}{}'.format(text_spec[0], random.choice(spec_choices[trans_char])) + \
                       trans_string[idx + 2:]
    return trans_string


def decode_subs_cipher(input_string):
    text = 'rq3gsalt6u1iyfzop572d49bnx8cvmkewhj'
    text_spec = '0_-.'
    trans = make_trans(text[4:] + text[:4], text)

    for i, ch in enumerate(input_string):
        if ch in text_spec:
            spec_idx = text.find(input_string[i + 1]) % len(text_spec)
            # Since we're walking through each character, the string length must not change
            input_string = input_string[:i] + '#' + text_spec[spec_idx] + input_string[i + 2:]
    input_string = input_string.replace('#', '')
    trans_string = input_string.translate(trans)

    return trans_string


def decode_guid(input_string):
    ret_string = ''
    decoded = custom_base32decode(input_string)
    xor_key = decoded[0]
    encoded_guid = decoded[1:]
    for b in encoded_guid:
        ret_string += '{:02X}'.format(b ^ xor_key)
    return ret_string


def encode_guid(input_string, xor_key=None):
    ret_string = ''
    if xor_key is None:
        xor_key = random.randint(1, 127) | 128
    ret_string += chr(xor_key)
    while len(input_string) > 0:
        hx = input_string[:2]
        input_string = input_string[2:]
        ret_string += chr(int(hx, 16) ^ xor_key)
    return custom_base32encode(ret_string)


def decode_char(first_char, input_char):
    text = '0123456789abcdefghijklmnopqrstuvwxyz'
    return (text.find(input_char) - ord(first_char)) % 36


def decode_dga(input_string):
    data = input_string.split('.')[0]
    system_guid, domain_order, dn_str_lower, decode_info, encoded_string = ('',) * 5
    if len(data) >= 16:
        try:
            domain_order = decode_char(input_string[0], input_string[15])
            s2_ret = decode_stage_two(data)
            if s2_ret and domain_order not in (0, 1, 35) and 20 <= len(data) <= 23:
                return s2_ret
            system_guid = decode_guid(data[:15])[:16]
        except:
            pass
        encoded_string = data[16:]

        if '0' in data[16:]:
            try:
                if encoded_string.startswith('00'):
                    # Custom Base32 Encoding
                    dn_str_lower = custom_base32decode(encoded_string[2:]).decode()
                    decode_info = 'custom_base32'
                else:
                    # Substitution Cipher
                    # This will incorrectly decode some continuation characters from base32 encoding that contain '0'
                    dn_str_lower = decode_subs_cipher(encoded_string)
                    decode_info = 'subs_cipher'
            except:
                decode_info = 'decode failed'
        else:
            # These strings be from a domain 16+ characters long, or continuation characters from base32 encoding
            dn_str_lower = decode_subs_cipher(encoded_string)
            decode_info = 'subs_cipher (no dot)'
    return ';'.join([system_guid, dn_str_lower, decode_info, str(domain_order)])


def decode_stage_two(input_string):
    # The length of the raw input appears to be 23 characters
    decoded_data = custom_base32decode(input_string.split('.')[0], rt=False)
    xor_key = ord(decoded_data[0:1])
    data_xor_byte = b''
    for ch in decoded_data:
        if not isinstance(ch, int):
            ch = ord(ch)
        data_xor_byte += bytes(bytearray([ch ^ xor_key]))
    key_xor_word = from_bytes(data_xor_byte[10:12], 'little')
    data_xor_words = 0
    for i in range(1, 9, 2):
        data_xor_words <<= 16
        w = from_bytes(data_xor_byte[i:i+2], 'big')
        data_xor_words += w ^ key_xor_word
    system_guid = '{:014X}'.format(data_xor_words)
    data_info = from_bytes(b'\x00' + data_xor_byte[9:12], 'big')
    activity_date = datetime(2010, 1, 1) + timedelta(minutes=15*(data_info & 0x0FFFFF))
    if datetime(2020, 1, 1) > activity_date or activity_date > datetime.now() + timedelta(days=30):
        return
    data_len = data_info >> 20

    if 1 <= data_len <= 2:
        str_flags = 'ping'
        data_payload = from_bytes(data_xor_byte[12:12+data_len], 'big')
        try:
            app_flags = SecurityApps(data_payload)
            if app_flags:
                str_flags = '{!s}'.format(app_flags).split('.')[-1]
        except:
            if data_payload > 0:
                str_flags = '0b{:016b}'.format(data_payload)
    else:
        return
    return ';'.join([system_guid, str((activity_date - datetime(1970, 1, 1)).total_seconds()), str_flags, ])


def from_bytes(data_bytes, ret_type=None):
    try:
        return int.from_bytes(data_bytes, ret_type)
    except:
        import struct
        if len(data_bytes) == 0:
            return 0
        e = '<' if ret_type == 'little' else '>'
        if len(data_bytes) > 2:
            f = '{}I'.format(e)
        elif len(data_bytes) > 1:
            f = '{}H'.format(e)
        else:
            f = '{}B'.format(e)
        return struct.unpack(f, data_bytes)[0]


def custom_base32decode_list(input_string):
    # Have not seen names span more than 3 queries (3*16), and do not want to try a large number of permutations
    # Also removing duplicates, but in theory a repeating domain value could include the same value 2+ times
    if len(input_string) > 200:
        return
    re_text = r'[-.0-9a-v]+'
    vals = re.findall(re_text, input_string)
    if len(vals) > 8:
        vals = vals[:8]
    vals = {x.split('.')[0].rstrip('0') for x in vals}
    dn_str_list = []
    for p in permutations(vals):
        try:
            test_join = ''.join(p)
            if test_join.startswith('00'):
                test_join = test_join[2:]
            dn_str_lower_test = custom_base32decode(test_join, rt=False)
            if all(0x20 < ch < 0x7e for ch in dn_str_lower_test):
                dn_str_list.append(dn_str_lower_test.decode('utf8'))
        except:
            pass
    return ';'.join(dn_str_list)


def decode_subs_cipher_list(input_string):
    # Have not seen names span more than 3 queries (3*16), and do not want to try a large number of permutations
    # Also removing duplicates, but in theory a repeating domain value could include the same value 2+ times
    if len(input_string) > 200:
        return
    re_text = r'[-.0-9a-z]+'

    # Replace special two character encodings with a one version for deduplication
    input_string = re.sub('0[13789jklz]', '01', input_string)
    input_string = re.sub('0[2bcegiot]', '02', input_string)
    input_string = re.sub('0[45afhmqux]', '04', input_string)
    input_string = re.sub('0[6dnprsvwy]', '06', input_string)

    vals = re.findall(re_text, input_string)
    if len(vals) > 8:
        vals = vals[:8]

    vals = {x.split('.')[0].rstrip('0') for x in vals}
    dn_str_list = []
    for p in permutations(vals):
        try:
            dn_str_lower = decode_subs_cipher(''.join(p))
            dn_str_list.append(dn_str_lower)
        except:
            pass
    return ';'.join(dn_str_list)
