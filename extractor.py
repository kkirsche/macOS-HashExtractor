#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import subprocess
import fnmatch
import xml.etree.ElementTree as ET
import string


def get_user_plist_filenames():
    files = []
    for filename in os.listdir(basepath):
        if fnmatch.fnmatch(filename, '[!_|!nobody]*.plist'):
            files.append(filename)

    return files


def get_plist_contents_from(filename):
    path = basepath + filename
    result = subprocess.run([
        u"sudo /usr/bin/defaults read {}".format(path) +
        u" ShadowHashData 2>/dev/null|tr -dc 0-9a-f|xxd -r -p|" +
        u"plutil -convert xml1 - -o -"
    ], universal_newlines=True, shell=True,
       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    return result.stdout


def remove_whitespace(hash_str):
    return hash_str.translate({
        ord(x): '' for x in set(string.whitespace)
    })


def parse_plist(plist_str):
    root = ET.fromstring(plist_str)
    for child in root.findall(".//data[1]"):
        entropy = child.text.replace(" ", "").strip()
    for child in root.findall(".//integer[1]"):
        iterations = child.text.strip()
    for child in root.findall(".//data[2]"):
        salt = child.text.strip()

    return {
        "entropy": entropy,
        "iterations": iterations,
        "salt": salt
    }


def format_hash(hash_components):
    hash_str = remove_whitespace(
        u"$ml$" +
        hash_components["iterations"] +
        u"$" +
        hash_components["salt"] +
        u"$" +
        hash_components["entropy"]
    )
    return hash_str


def make_crypt_format(user, hash_str):
    fmtd = "{}:{}".format(user, hash_str)
    return fmtd


if __name__ == '__main__':
    basepath = '/var/db/dslocal/nodes/Default/users/'
    files = get_user_plist_filenames()
    for filename in files:
        user = filename.split('.')[0]
        plist_contents = get_plist_contents_from(filename)
        try:
            hash_components = parse_plist(plist_contents)
            formatted_hash = format_hash(hash_components)
            print(make_crypt_format(user, formatted_hash))
            print()
        except:
            print(u"Oops! Something went wrong trying to extract" +
                  u" {}'s password hash!".format(user))
            print()
