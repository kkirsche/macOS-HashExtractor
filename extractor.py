#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import subprocess
import fnmatch
import xml.etree.ElementTree as ET
import string

basepath = '/var/db/dslocal/nodes/Default/users/'


def remove_whitespace(hash_str):
    return hash_str.translate({
        ord(x): '' for x in set(string.whitespace)
    })

for filename in os.listdir(basepath):
    if fnmatch.fnmatch(filename, '[!_|!nobody]*.plist'):
        path = basepath + filename
        result = subprocess.run([
            u"sudo /usr/bin/defaults read {}".format(path) +
            u" ShadowHashData 2>/dev/null|tr -dc 0-9a-f|xxd -r -p|" +
            u"plutil -convert xml1 - -o -"
        ], universal_newlines=True, shell=True,
           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        user = filename.split('.')[0]
        try:
            root = ET.fromstring(result.stdout)
            for child in root.findall(".//data[1]"):
                entropy = child.text.replace(" ", "").strip()
            for child in root.findall(".//integer[1]"):
                iterations = child.text.strip()
            for child in root.findall(".//data[2]"):
                salt = child.text.strip()
            print(
                u"{}:".format(user) +
                remove_whitespace(u"$ml$"+iterations+u"$"+salt+u"$"+entropy)
            )
            print()
        except:
            print(u"Oops! Something went wrong trying to extract" +
                  u" {}'s password hash!".format(user))
            print()
