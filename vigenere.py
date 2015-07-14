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

def getIndexOfKey(key, text, index):
    """ Return the index in this key being used to decipher text[index].

    This is necessary since the text may include non-ascii chars which
    the key must skip over.
    """
    keyIndex, i = 0, 0
    while i != index:
        if text[i].isalpha():
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

def printMessage(window, text, key, index, highlight):
    """ Print the current message as deciphered by this key.

    Args:
        window (curses.window): curses window to render onto.
        text ([str]): message to encrypt or decrypt.
        key ([str]): key used for deciphering.
        index (int): current highlighted character in message.
        highlight (bool): should highlighting should be performed?
    """
    h, w = window.getmaxyx()
    # This was really tricky to debug: the total length of a message before
    # and after it is textwrapped MAY NOT be equal since spaces may be removed.
    msg = cipher(text, key)
    wrapped = textwrap.TextWrapper(drop_whitespace=False, width=w-4).wrap(msg)
    r, c = getPosFromIndex(wrapped, index)

    subwin = window.subwin(len(wrapped)+2, w, int(h*0.33)-len(wrapped), 0)
    subwin.box()

    #window.addstr(0, 0, str(index)+', '+str((r, c))) # DEBUGGING

    winRow = 1
    for line in wrapped:
        subwin.addstr(winRow, 2, line)
        winRow += 1
    if highlight:
        subwin.chgat(r+1, c+2, 1, curses.A_STANDOUT)

def printKey(window, key, index, highlight):
    """ Print the current key. """
    h, w = window.getmaxyx()

    subwin = window.subwin(3, len(key)+4, int(h*0.66), w//2-len(key))
    subwin.box()

    subwin.addstr(1, 2, "".join(key))
    if highlight:
        subwin.chgat(1, 2+index, 1, curses.A_STANDOUT)

####ARG_PARSING################################################################

if len(sys.argv) != 5:
    print('usage: '+sys.argv[0]+
            ' -e|-d text|file.txt -k key_string|-l key_length')
    sys.exit(-1)

# Parse cipher mode.
if sys.argv[1] == '-e':
    cipher = encipher
elif sys.argv[1] == '-d':
    cipher = decipher
else:
    print('use either -e|-d for enciphering or deciphering')
    sys.exit(-1)

# Parse filename or message.
try:
    with open(sys.argv[2]) as f:
        text = [ch for ch in f.read().strip()]
# If it isn't openable as a file, then use it as the message itself.
except FileNotFoundError:
    text = [ch for ch in sys.argv[2].strip()]

# Parse key mode.
if sys.argv[3] == '-k':
    keyLenMode = False
elif sys.argv[3] == '-l':
    keyLenMode = True
else:
    print('use either -k key_string|-l key_length')
    sys.exit(-1)

# Parse key string or length.
try:
    if keyLenMode:
        keyLen = int(sys.argv[4])
        key = ['A']*keyLen
    else:
        # If the key is directly provided, just print out the result.
        print(cipher(text, sys.argv[4]))
        sys.exit(0)
except ValueError:
    print('not a valid key length:', sys.argv[4])
    sys.exit(-1)

####MAIN#######################################################################

def main(stdscr):
    index = 0
    keyMode = True
    message = key if keyMode else text

    curses.curs_set(0) # make the cursor invisible

    while True:
        # Render calls.
        stdscr.clear()
        printMessage(stdscr, text, key, index, not keyMode)
        printKey(stdscr, key, index, keyMode)
        stdscr.refresh()

        # Input parsing.
        ch = stdscr.getch()
        if ch == 27: # ESCAPE key
            curses.endwin()
            print(cipher(text, key))
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
            message = key if keyMode else text
        elif ch in list(map(ord, string.ascii_letters)):
            # Set key to arbitrary character. Message is changed.
            if keyMode:
                key[index] = str.upper(chr(ch))
            # Set message to arbitrary character. Key is changed.
            else:
                keyIndex = getIndexOfKey(key, text, index)
                key[keyIndex] = offsetChar(text[index], ord('a')-ch)
            index = offsetIndex(message, index, True)

wrapper(main)
