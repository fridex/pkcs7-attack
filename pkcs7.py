#!/usr/bin/python
import sys
from OracleModule import paddingOracle
from OracleModule import genNewKey
from OracleModule import setKey
from OracleModule import encrypt
# uncomment if testing
#import string
#import random

class Ciphertext(object):
    ''' Encapsulation of basic methods used to decipher '''

    def __init__(self, message):
        ''' Init '''
        self.message = message
        self.message_bac = message
        self.intval = [0] * (len(message) / 2)
        self.chars = [0] * (len(message) / 2)

    def set_message(self, message):
        self.message = message

    def get_next_char(self, block, offset):
        ''' Get next char for specific position and offset when backtracking '''
        idx = block * 16 + offset
        ret = self.chars[idx]
        self.chars[idx] = self.chars[idx] + 1
        if ret > 255:
           raise Exception()
        return ret

    def char_reset(self, block, offset):
        ''' Reset char on specific position and offset when backtracking '''
        self.chars[block * 16 + offset] = 0

    def set_intval(self, block, offset, c):
        ''' Store a intervalue for specific block and offset '''
        self.intval[block * 16 + offset] = c

    def get_intval(self, block, offset):
        ''' Get intervalue for specific block and offset '''
        return self.intval[block * 16 + offset]

    def restore(self):
        ''' Restore original ciphertext '''
        self.message = self.message_bac

    def modify(self, block, offset, c):
        ''' Replace ciphertexton on specific block and offset with char c '''
        ret = self.message
        idx = (block * 32) + (offset * 2)
        c = hex(c)[2:] if len(hex(c)) > 3 else '0' + hex(c)[2:]
        ret = ret[:idx] + c + ret[(idx+2):]
        self.message = ret

        return ret

    def block_count(self):
        ''' Return block count in ciphertext '''
        return (len(self.message) / 32)

    def getTillBlock(self, block):
        ''' Get first `block' blocks '''
        return self.message[:(block * 32)]

    def get_deciphered(self):
        ''' Restore original plain text from computed intervalues'''
        ret = ""
        for i in range(0, len(self.message) - 32, 2):
           c = int(self.message[i:(i+2)], 16)
           x = self.intval[i / 2]
           c = c ^ x
           ret = ret + chr(c)
        return ret

    def remove_padding(self, msg):
       ''' Remove padding from message msg '''
       pad = ord(msg[-1])
       return msg[:(len(msg) - pad)]

# Uncomment if testing
#def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
#    return ''.join(random.choice(chars) for _ in range(size))
#
#def toStringList(msg):
#    ret = ""
#    for i in range(0, len(msg)):
#       c = ord(msg[i])
#       c = hex(c)[2:] if len(hex(c)) > 3 else '0' + hex(c)[2:]
#       ret = ret + c
#
#    return ret

def decodeCiphertext(ciphertext):
    ''' Decode ciphertext using oraculum. Use backtracking if a char does not match'''
    ct = Ciphertext(ciphertext);

    block = 0
    while block < ct.block_count() - 1 and block >= 0:
       offset = 15
       while offset >= 0 and offset < 16:
          try:
             c = ct.get_next_char(block, offset)
          except Exception:
             # Out of chars to use to guess... use backtracking, bad previous
             # padding
             ct.char_reset(block, offset)
             offset = offset + 1
             continue

          ct.restore() # Use untouched ciphertext each time

          for i in range(15, offset, -1): # padding for first offset - 1
             ct.modify(block, i, (15 - offset + 1) ^ ct.get_intval(block, i))
          ct.modify(block, offset, c ^ (15 - offset + 1))

          if paddingOracle(ct.getTillBlock(block + 2)):
             # Whooohooo!!! We got it, store the char c and keep rocking!
             ct.set_intval(block, offset, c)
             offset = offset - 1

       if offset < 0:
          # All offsets restored, move to a next block
          block = block + 1
       elif offset > 15:
          if block == 0:
             # We got behind the beginning, something went wrong with oraculum....
             print >> sys.stderr, "Could not decipher!"
             sys.exit(1)
          block = block - 1

    ct.restore()
    return ct.remove_padding(ct.get_deciphered())

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ciphertext = sys.argv[1]
        #setKey('sixteen_byte_key')
    else:
        ciphertext = "fa485ab028cb239a39a9e52df1ebf4c30911b25d73f8906cc45b6bf87f7a693f47609094ccca42050ad609bb3cf979ac"
        # Uncomment if desting
        #random.seed()
        #setKey(id_generator(32))
        #text = id_generator(random.randint(1, 9999))
        #print "text:  " + text
        #cip = toStringList(encrypt(text))
        #print "cip:  " + cip
        #text2 = decodeCiphertext(cip)
        #print "text2: " + text2
        #if text != text2:
        #   sys.exit(1)
        #else:
        #   sys.exit(0)

    print decodeCiphertext(ciphertext)
    sys.exit(0)

