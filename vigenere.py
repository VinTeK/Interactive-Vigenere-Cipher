#!/usr/bin/env python3

import curses, itertools, re, string, sys, textwrap
from curses import wrapper # prevents screwing up the terminal on exception

####FUNCTIONS##################################################################

def findPunct(s):
    ''' Return a list of (index, punctuation) in this string. '''
    return [(m.start(), s[m.start()]) for m in re.finditer(r'\W', s)]

def insertPunct(s, xs):
    ''' Return a new string with punctation inserted according to xs. '''
    ret = [ch for ch in s]
    for x in xs:
        ret.insert(x[0], x[1])
    return "".join(ret)

def getPosOfIndex(xs, index):
    ''' Return a (row, col) pair corresponding to an index into a 2D list. '''
    if index < 0 or index >= sum(map(len, xs)):
        return None

    r, tmp = 0, [0]
    tmp.extend(itertools.accumulate(map(len, xs)))
    for i in range(len(tmp)-1):
        if index in range(tmp[i], tmp[i+1]):
            r = i
    return r, index - sum(map(len, xs[:r]))

def offsetIndex(s, i, goRight):
    ''' Return the new index on this string after an offset. '''
    offset = 1 if goRight else -1
    i = (i + offset) % len(s)
    while s[i] == ' ':
        i = (i + offset) % len(s)
    return i

def offsetChar(ch, offset):
    ''' Return a character offset forwards or backwards in the alphabet. '''
    if not len(ch) == 1 or not ch.isalpha:
        return ch
    base = 'a' if ch.islower() else 'A'
    return chr((ord(ch)-ord(base) + offset) % 26 + ord(base))

def encipher(plaintext, key):
    ''' Return the ciphertext resulting from this key. '''
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
    ''' Return the plaintext resulting from this key. '''
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

def printMessage(window, ciphertext, spaces, key, index, highlight):
    ''' Print the current message as deciphered by this key.

    Args:
        window: curses window to render onto.
        ciphertext: raw internal ciphertext, represented as a list of str.
        spaces: list of indices where spaces should be inserted in ciphertext.
        key: key used for deciphering, represented as a list of str.
        index: current highlighted character in internal ciphertext.
        highlight: boolean to decide if highlighting should be performed.
    '''
    height, width = window.getmaxyx()
    wrapped = textwrap.wrap(decipher(ciphertext, key), width)
    r, c = getPosOfIndex(wrapped, index)

    winRow = height//8
    for line in wrapped:
        window.addstr(winRow, 0, line)
        winRow += 1
    if highlight:
        window.addstr(0, 0, str(index)+', ('+str(r)+', '+str(c)+')')
        window.addch(height//8+r, c, wrapped[r][c], curses.A_STANDOUT)

def printKey(window, key, index, highlight):
    ''' Print the current key. '''
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
        # Internally, the ciphertext is a continuous list of characters with no
        # non-ascii chars. But, if the original message contains them, we 
        # want to reincorporate them in the final formatted output.
        ciphertext = f.read().strip()
        punct = findPunct(ciphertext)
        ciphertext = [ch for ch in re.sub(r'\W', '', ciphertext)]
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
        printMessage(stdscr, ciphertext, punct, key, index, not keyMode)
        printKey(stdscr, key, index, keyMode)
        stdscr.refresh()

        # Input parsing.
        ch = stdscr.getch()
        if ch == 27: # ESCAPE key
            break
        elif ch == curses.KEY_DOWN and keyMode: # TODO: add up/down for cipher
            key[index] = offsetChar(key[index], -1)
        elif ch == curses.KEY_UP and keyMode:
            key[index] = offsetChar(key[index], 1)
        elif ch == curses.KEY_LEFT:
            index = offsetIndex(message, index, False)
        elif ch == curses.KEY_RIGHT:
            index = offsetIndex(message, index, True)
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
                key[index%keyLen] = offsetChar(message[index], ord('a')-ch)
            index = offsetIndex(message, index, True)

wrapper(main)
