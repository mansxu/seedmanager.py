#!/usr/bin/env python3
#
# seedmanager.py: a script to convert seed phrases into shards and back
#
import configargparse
import bip39
import sys
import re
from collections import Counter
from Crypto.Protocol.SecretSharing import Shamir
import Crypto.Random
import bitstring

mapwords = dict()
for word in bip39.WORD_TO_INDEX_TABLE:
    if len(word) < 4:
        key = word + 'x'
    else:
        key = word[:4]
    mapwords[key] = (word, bip39.WORD_TO_INDEX_TABLE[word])
    
def split4(s):
    return [mapwords[x][0] for x in filter(lambda x: x != '', re.split('(....)', s))]

def join4(l, s=""):
    return s.join([word[:4] if len(word) > 3 else word + 'x' for word in l.split(" ")])

def word2index(w):
    if w in bip39.WORD_TO_INDEX_TABLE:
        return w
    return mapwords[w][0]
        

if __name__ == "__main__":
    parser = configargparse.ArgumentParser(default_config_files=['/etc/seedmanager.conf','~/.seedmanager'], description="Split and recombine wallet secrets.")
    parser.add_argument('-a', '--action', choices=['make', 'join'])
    parser.add_argument('-f', '--format', choices=['full', '4', '4space', 'dogtag'], default="full")
    parser.add_argument('-g', '--generate', type=int)   
    parser.add_argument('-m', '--template', default="file")    
    parser.add_argument('-p', '--phrases', nargs="*")
    parser.add_argument('-t', '--threshold', type=int, default=3)
    parser.add_argument('-s', '--shares', type=int, default=5)
    o = parser.parse_args()

    joinchar = None
    if o.format == "4":
        joinchar = ""
    elif o.format in ["4space", "dogtag"]:
        joinchar = " "
    if o.phrases is None:
        o.phrases = []
    if len(o.phrases) == 0:
        o.phrases = None
    else:
        o.phrases = "\n".join(o.phrases)

    # try to recognize the structure of the phrases
    if not o.phrases and not o.generate:
        raise Exception("Need data to process (--phrases or --generate)")
    if o.generate:
        data = bip39.encode_bytes(Crypto.Random.get_random_bytes(int(o.generate / 8)))
        if joinchar is not None:
            data = join4(data, joinchar)
        print(data)
        exit(0)
    elif o.phrases == '-' or o.phrases == 'stdin':
        inp = ""
        for l in sys.stdin:
            inp += l
        data = inp
    else:
        try:
            # treat o.phrases as a file name to read
            with open(o.phrases, mode='r') as fh: 
                data = fh.read()
        except:
            data = o.phrases
    data = data.strip()
    # we now have stdin, file, and straight data
    # we accept: single line, long word (48 or 96 chars) (one seed)
    # or multiline, one word or one line, multiword (one seed phrase)
    # or multiline, multiword (different shards)
    # or multiline, all long words (48 or 96 chars) (different shards)
    cmap = Counter(data)
    nlcount = cmap[chr(10)]
    spcount = cmap[" "]
    nlsplit = data.split("\n")
    lines = list()
    for line in nlsplit:
        s = line.split()
        if len(s) == 1 and len(line) > 8:
            spcount += 1
            lines.append(split4(line))
        else:
            lines.append(s)
    phrases = list()
    phrase = None
    # single line, single word
    if nlcount == 0:
        o.action = "make"
        phrases = lines[0]
    # single words separated by newlines:
    elif spcount == 0:
        o.action = "make"
        phrases = [l[0] for l in lines]
    # multiple words on multiple lines
    else:
        o.action = "join"
        phrases = lines

    if o.action == "make":
        b = bip39.decode_phrase(" ".join([word2index(w) for w in phrases]))
        bbs = bitstring.BitArray(b)
        output = list([''] * o.shares)
        for i in range(int(len(b)/16)):
            chunk = bbs[i*128:(i+1)*128]
            shares = Shamir.split(o.threshold, o.shares, chunk.bytes)
            for s in shares:
                idx = s[0]
                bip = bip39.encode_bytes(s[1]).split(" ")
                lastword = bip[-1]
                lastbits = bip39.WORD_TO_INDEX_TABLE[lastword]
                bs = bitstring.BitArray(uint=lastbits, length=11)
                bs[-4:] = bitstring.Bits(uint=idx, length=4)
                bip[-1] = bip39.INDEX_TO_WORD_TABLE[bs.uint]
                out = " ".join(bip)
                if joinchar is not None:
                    out = join4(out, joinchar)
                output[idx - 1] += (joinchar if joinchar is not None else " ") + out
        if o.format == "dogtag":
            for (i, l) in enumerate(output):
                bip = l.strip().split(" ")
                for j in range(int(len(bip)/6)):
                    text = "|".join(bip[j*6:j*6+6]).upper()
                    if j % 2 == 0:
                        text += "| "+o.template[0].upper()+str(i)+" "
                    else:
                        text += "|  "+str(j)
                    print(f"$engrave_script -b -t '{text}' > {o.template}-{i}-{j}.ngc")
        else:
            for l in output:
                print(l.strip())
    elif o.action == "join":
        secret = bytes()
        for i in range(int(len(phrases[0])/12)):
            shares = list()
            for s in range(len(phrases)):
                bs = bitstring.BitArray()
                for w in phrases[s][i*12:(i+1)*12]:
                    idx = bip39.WORD_TO_INDEX_TABLE[word2index(w)]
                    bs.append(bitstring.Bits(uint=idx, length=11))
                idx = bs[-4:].uint
                data = bs[:-4].bytes
                shares.append((idx, data))
            secret += Shamir.combine(shares)
        print(bip39.encode_bytes(secret))
    else:
        raise Exception("unknown action")
