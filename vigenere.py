#!/usr/bin/env python3

import collections, curses, itertools, re, string, sys, textwrap
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

def freqAnalysis(text):
    """ Return the ten most common unigrams, bigrams, and trigrams. """
    text = re.sub(r'\W', '', text)
    n = 10

    uni = collections.Counter(text)
    bi = collections.Counter([text[i:i+2] for i in range(len(text)-1)])
    tri = collections.Counter([text[i:i+3] for i in range(len(text)-2)])

    return uni.most_common(n), bi.most_common(n), tri.most_common(n)

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
    wrap = textwrap.TextWrapper(drop_whitespace=False, width=w-4).wrap(msg)

    vigenere = itertools.cycle(key)
    keyWrap = wrap[:]
    for i in range(len(keyWrap)):
        tmp = [next(vigenere) if ch.isalpha() else ch for ch in keyWrap[i]]
        keyWrap[i] = ''.join(tmp)

    try:
        subwin = window.subwin(len(wrap)*2+2, w, int(h*0.33)-len(wrap)*2+3, 0)
    except curses.error:
        curses.endwin()
        print('message is too big! shrink it or use a larger terminal size.')
        sys.exit(-1)
    subwin.border(ord('|'), ord('|'), ord('-'), ord('-'), *[ord('+')]*4)

    winRow = 2
    for msgLine, keyLine in zip(wrap, keyWrap):
        subwin.addstr(winRow-1, 2, keyLine, curses.A_DIM)
        subwin.addstr(winRow, 2, msgLine, curses.A_BOLD)
        winRow += 2
    if highlight:
        r, c = getPosFromIndex(wrap, index)
        subwin.chgat(r*2+2, c+2, 1, curses.A_STANDOUT)

def printKey(window, key, index, highlight):
    """ Print the current key. """
    h, w = window.getmaxyx()

    try:
        subwin = window.subwin(3, len(key)+4, int(h*0.66), w//2-len(key))
    except curses.error:
        curses.endwin()
        print('key is too big! shrink it or use a larger terminal size.')
        sys.exit(-1)
    subwin.border(ord('|'), ord('|'), ord('-'), ord('-'), *[ord('+')]*4)

    subwin.addstr(1, 2, "".join(key))
    if highlight:
        subwin.chgat(1, 2+index, 1, curses.A_STANDOUT)

def printAnalysis(window, text):
    """ Print out frequency analysis of message. """
    uni, bi, tri = freqAnalysis(''.join(text))
    h, w = window.getmaxyx()

    # Try to add as much frequency analysis information that fits the window.
    def helper(tally, s):
        for gram, num in tally[1:]:
            toAppend = ', '+str(gram)+'*'+str(num)
            if len(s) + len(toAppend) > w-4: break
            s += toAppend
        return s

    uniStr=helper(uni, 'unigrams: '+str(uni[0][0])+'*'+str(uni[0][1]))
    if bi: biStr=helper(bi, 'bigrams:  '+str(bi[0][0])+'*'+str(bi[0][1]))
    if tri: triStr=helper(tri, 'trigrams: '+str(tri[0][0])+'*'+str(tri[0][1]))

    try:
        subwin = window.subwin(5, w, h-5, 0)
    except curses.error:
        curses.endwin()
        print('could not fit analysis window! use larger terminal size.')
        sys.exit(-1)
    subwin.border(ord('|'), ord('|'), ord('-'), ord('-'), *[ord('+')]*4)

    subwin.addstr(1, 2, uniStr)
    if bi: subwin.addstr(2, 2, biStr)
    if tri: subwin.addstr(3, 2, triStr)

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

if not text:
    print('your message must be at least one character')
    sys.exit(-1)

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
        printAnalysis(stdscr, text)
        stdscr.refresh()

        # Input parsing.
        ch = stdscr.getch()
        if ch == 27: # ESCAPE key
            curses.endwin()
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
                key[keyIndex] = offsetChar(text[index], ord('a')-ch).upper()
            index = offsetIndex(message, index, True)

wrapper(main)
# Print out result after exiting interactive mode.
print(cipher(text, key))
