#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import csv
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'lib'))
from splunklib.six import text_type
from splunklib.searchcommands.internals import CsvDialect

import sunburst


def process_line(input_dict, encoded, decoded, decoder=None):
    if decoder not in ('decode', 'stage2decode', 'b32decode', 'b32encode', 'subsdecode', 'subsencode',
                       'b32decode_list', 'subsdecode_list'):
        return

    if decoder == 'stage2decode':
        func = sunburst.decode_stage_two
    elif decoder == 'b32decode':
        func = sunburst.custom_base32decode
    elif decoder == 'b32encode':
        func = sunburst.custom_base32encode
    elif decoder == 'subsdecode':
        func = sunburst.decode_subs_cipher
    elif decoder == 'subsencode':
        func = sunburst.encode_sub_cipher
    elif decoder == 'b32decode_list':
        func = sunburst.custom_base32decode_list
    elif decoder == 'subsdecode_list':
        func = sunburst.decode_subs_cipher_list
    else:
        func = sunburst.decode_dga

    try:
        if 'encode' in decoder and input_dict[decoded] and not input_dict[encoded]:
            input_dict[encoded] = func(input_dict[decoded])
        if input_dict[encoded] and not input_dict[decoded]:
            input_dict[decoded] = func(input_dict[encoded])
    except:
        pass


def get_csv_writer(infile, outfile, *args):
    reader = csv.DictReader(infile, dialect=CsvDialect)
    header = reader.fieldnames
    for arg in args:
        if arg not in header:
            raise KeyError('{arg!r} from command line arguments not found in input CSV headers'.format(arg=arg))
    writer = csv.DictWriter(outfile, header, dialect=CsvDialect)
    writer.writeheader()
    return reader, writer


def main(decode_type=None):
    parser = argparse.ArgumentParser(description='Decode Sunburst DGA input.')
    parser.add_argument(
        '-d', '--decode_type', type=text_type, default='decode',
        help='Type of decoding to attempt: decode, stage2decode, b32decode, subsdecode, b32decode_list, subsdecode_list'
    )
    parser.add_argument(
        'encoded', type=text_type, nargs=1,
        help='Input string to base64 with base64.')
    parser.add_argument(
        'decoded', type=text_type, nargs=1,
        help='Input string to encode with base64')

    parser.add_argument('-i', '--infile', nargs='?', type=argparse.FileType('r'), default=sys.stdin,
                        help='Input CSV, defaults to stdin')
    parser.add_argument('-o', '--outfile', nargs='?', type=argparse.FileType('w'), default=sys.stdout,
                        help='Input CSV, defaults to stdout')

    args = parser.parse_args(['encoded', 'decoded'])
    decode_type = decode_type or args.decode_type
    infile = args.infile
    outfile = args.outfile

    arg_list = [
        args.encoded[0],
        args.decoded[0],
    ]

    reader, writer = get_csv_writer(infile, outfile, *arg_list)

    for line in reader:
        process_line(line, *arg_list, decoder=decode_type)
        writer.writerow(line)


if __name__ == '__main__':
    main()
