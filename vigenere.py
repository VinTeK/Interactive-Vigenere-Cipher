#!/usr/bin/env python3

import curses, itertools, re, string, sys, textwrap
from curses import wrapper # prevents screwing up the terminal on exception

####FUNCTIONS##################################################################

def getPosFromIndex(xss, index):
    """ Return a (row, col) pair corresponding to an index into a 2D list. """
    if index < 0 or index >= sum(map(len, xss)):
        return None

    r, tmp = 0, [0]
    tmp.extend(itertools.accumulate(map(len, xss)))
    for i in range(len(tmp)-1):
        if index in range(tmp[i], tmp[i+1]):
            r = i
    return r, index - sum(map(len, xss[:r]))

def getIndexOfKey(key, ciphertext, index):
    """ Return the index in this key being used to decipher ciphertext[index].

    This is necessary since the ciphertext may include non-ascii chars which
    the key must skip over.
    """
    keyIndex, i = 0, 0
    while i != index:
        if ciphertext[i].isalpha():
            keyIndex = (keyIndex + 1) % len(key)
        i += 1
    return keyIndex

def offsetIndex(s, i, offset):
    """ Return the new index on this string after it is offset. """
    i = (i + offset) % len(s)
    while not s[i].isalpha(): # skip over nonalphabetics
        i = (i + offset) % len(s)
    return i

def offsetChar(ch, offset):
    """ Return a character offset forwards or backwards in the alphabet. """
    if not len(ch) == 1 or not ch.isalpha:
        return ch
    base = 'a' if ch.islower() else 'A'
    return chr((ord(ch)-ord(base) + offset) % 26 + ord(base))

def encipher(plaintext, key):
    """ Return the ciphertext resulting from this key. """
    ret = []

    key = itertools.cycle(key)

    for p in plaintext:
        c = p
        if p.isalpha():
            base = 'a' if p.islower() else 'A'
            k = next(key).lower() if p.islower() else next(key).upper()
            c = offsetChar(p, ord(k)-ord(base))
        ret.append(c)
    return "".join(ret)

def decipher(ciphertext, key):
    """ Return the plaintext resulting from this key. """
    ret = []

    key = itertools.cycle(key)

    for c in ciphertext:
        p = c
        if c.isalpha():
            base = 'a' if c.islower() else 'A'
            k = next(key).lower() if c.islower() else next(key).upper()
            p = offsetChar(c, ord(base)-ord(k))
        ret.append(p)
    return "".join(ret)

def printMessage(window, ciphertext, key, index, highlight):
    """ Print the current message as deciphered by this key.

    Args:
        window (curses.window): curses window to render onto.
        ciphertext ([str]): ciphertext message.
        key ([str]): key used for deciphering.
        index (int): current highlighted character in ciphertext.
        highlight (bool): should highlighting should be performed?
    """
    h, w = window.getmaxyx()
    msg = decipher(ciphertext, key)
    # This was really tricky to debug: the total length of a message before
    # and after it is textwrapped MAY NOT be equal since spaces may be removed.
    wrapped = textwrap.TextWrapper(drop_whitespace=False, width=w).wrap(msg)
    r, c = getPosFromIndex(wrapped, index)

    #window.addstr(0, 0, str(index)+', '+str((r, c))) # DEBUGGING

    winRow = h//8
    for line in wrapped:
        window.addstr(winRow, 0, line)
        winRow += 1
    if highlight:
        window.chgat(h//8+r, c, 1, curses.A_STANDOUT)

def printKey(window, key, index, highlight):
    """ Print the current key. """
    height, width = window.getmaxyx()

    window.addstr(height//2, 0, "".join(key))
    if highlight:
        window.chgat(height//2, index, 1, curses.A_STANDOUT)

####ARG_PARSING################################################################

if len(sys.argv) < 3:
    print('usage: '+sys.argv[0]+' ciphertext.txt key_length')
    sys.exit(-1)

try:
    fileName, keyLen = sys.argv[1], int(sys.argv[2])
except ValueError:
    print('not a valid key length:', sys.argv[2])
    sys.exit(-1)

try:
    with open(fileName) as f:
        ciphertext = [ch for ch in f.read().strip()]
except FileNotFoundError:
    print('cannot open file:', fileName)
    sys.exit(-1)

####MAIN#######################################################################

def main(stdscr):
    index = 0
    keyMode = True
    key = ['A']*keyLen
    message = key if keyMode else ciphertext

    curses.curs_set(0) # make the cursor invisible

    while True:
        # Render calls.
        stdscr.clear()
        printMessage(stdscr, ciphertext, key, index, not keyMode)
        printKey(stdscr, key, index, keyMode)
        stdscr.refresh()

        # Input parsing.
        ch = stdscr.getch()
        if ch == 27: # ESCAPE key
            break
        elif ch == curses.KEY_DOWN and keyMode:
            key[index] = offsetChar(key[index], -1)
        elif ch == curses.KEY_UP and keyMode:
            key[index] = offsetChar(key[index], 1)
        elif ch == curses.KEY_LEFT:
            index = offsetIndex(message, index, -1)
        elif ch == curses.KEY_RIGHT:
            index = offsetIndex(message, index, 1)
        # Toggle between arbitrary key mode and message mode.
        elif ch == ord(' '):
            keyMode = not keyMode
            index = 0
            message = key if keyMode else ciphertext
        elif ch in list(map(ord, string.ascii_letters)):
            # Set key to arbitrary character. Message is changed.
            if keyMode:
                key[index] = str.upper(chr(ch))
            # Set message to arbitrary character. Key is changed.
            else:
                keyIndex = getIndexOfKey(key, ciphertext, index)
                key[keyIndex] = offsetChar(ciphertext[index], ord('a')-ch)
            index = offsetIndex(message, index, True)

wrapper(main)
