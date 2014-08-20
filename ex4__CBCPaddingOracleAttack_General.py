#--------------------------------------------------------------
#
# padding oracle attacks on CBC
#
# Author: Yingjing Feng
# Email: feng0823yj@gmail.com
# Blog: http://seffyvon.lofter.com
# Date: 2014.08.19
#
#--------------------------------------------------------------

import urllib2
import sys

TARGET = 'http://crypto-class.appspot.com/po?er='
iv = 'f20bdba6ff29eed7b046d1df9fb70000'
fullCipher = '58b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4'
paddings = [0x01,0x0202,0x030303,0x04040404,0x0505050505,0x060606060606,0x07070707070707,0x0808080808080808,0x090909090909090909,0x0a0a0a0a0a0a0a0a0a0a,0x0b0b0b0b0b0b0b0b0b0b0b, 0x0c0c0c0c0c0c0c0c0c0c0c0c, 0x0d0d0d0d0d0d0d0d0d0d0d0d0d, 0x0e0e0e0e0e0e0e0e0e0e0e0e0e0e, 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f,0x10101010101010101010101010101010]


#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
            print f 
        except urllib2.HTTPError, e:          
            print "We got: %d" % e.code       # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding

#--------------------------------------------------------------
# {modified iv}+c0->m0, 
# iv+{modified c0}+c1 --> m0+m1,
# iv+c0+{modified c1}+c2 --> m0+m1+m2,
# iv+c0+...{modified c(i-1)}+ci--> m0+m1+...+mi
#--------------------------------------------------------------

def cycle(cipher): 
    #print 'cipher'
    #print hex(int(cipher,16))
    message = 0
    text = []
    po = PaddingOracle()
    for i in range(0, 16): # from the first byte on right to the first byte on the left
        for g in range(0, 256): 
            g2 = long(g << 8*i) + message # shift i byte(s)
            g2AndPadding = (g2 ^ paddings[i]) << 128 # shift one block(128 bits) right
            newG = hex(long(cipher,16) ^ g2AndPadding) # to int and xor
            newG2 = newG[2:len(newG)-1]
            print g
            #print hex(g2AndPadding)
        #print '~~~~~~~~~'
        #print ' '
            if po.query(newG2):#g==90: # #g == 20: 
                print chr(g)
                message = g2
                text.insert(0, chr(g))
                break
    return ''.join(text)


#------------------------------------------------------------------
# create the ciphers list
#------------------------------------------------------------------

ciphers = []
# 32 digits(2 digit for 1 byte), 
# 16 bytes/ 128-bit a block)
for i in range(0, len(fullCipher)/32):
    tempc = []
    for j in range(0, 32):
        tempc.append(fullCipher[i*32+j])
    d = ''.join(tempc)
    ciphers.append(d)

print ciphers

#------------------------------------------------------------------
# crack m0
#------------------------------------------------------------------

m0 = cycle(iv+ciphers[0]+ciphers[1])
print "final result:" + m0
#p = PaddingOracle()
#print p.query(iv+fullCipher)


#------------------------------------------------------------------
# crack m0, m1, ..., mn
#-----------c-------------------------------------------------------
"""
plaintext = ''
for i in range(0, len(ciphers)):
    toQuery = iv
    for j in range(0, i+1):
        toQuery = toQuery + ciphers[j]
    plaintext = plaintext + cycle(toQuery)
print plaintext
"""
