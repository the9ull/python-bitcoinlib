#!/usr/bin/env python3
#
# Copyright (C) 2015 Peter Todd
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

# WARNING: Do not run this on a wallet with a non-trivial amount of BTC. This
# utility has had very little testing and is being published as a
# proof-of-concept only.

# Requires python-bitcoinlib w/ sendmany support:
#
# https://github.com/petertodd/python-bitcoinlib/commit/6a0a2b9429edea318bea7b65a68a950cae536790

import sys
import hashlib

from bitcoin import *
from bitcoin.core import *
from bitcoin.core.script import *
from bitcoin.wallet import *

SelectParams('segnet')

if sys.argv[1:]:
    d = x(sys.argv[1])
    t = CTransaction.deserialize(d)
    print(t)
    sys.exit(0)


# Create the (in)famous correct brainwallet secret key.
h = hashlib.sha256(b'correct horse battery staple').digest()
k = hashlib.sha256(b'current morse battery stable').digest()
seckey = CBitcoinSecret.from_secret_bytes(h)
kpub = CBitcoinSecret.from_secret_bytes(k).pub
# kpub = b'\x04' + b'\xfe\x69'*32  # 1+64byte # Funded transaction!


# Create a redeemScript. Similar to a scriptPubKey the redeemScript must be
# satisfied for the funds to be spent.
txin_redeemScript = CScript([OP_1, seckey.pub, kpub, OP_2, OP_CHECKMULTISIG])
print(b2x(txin_redeemScript))

# Create the magic P2SH scriptPubKey format from that redeemScript. You should
# look at the CScript.to_p2sh_scriptPubKey() function in bitcoin.core.script to
# understand what's happening, as well as read BIP16:
# https://github.com/bitcoin/bips/blob/master/bip-0016.mediawiki
txin_scriptPubKey = txin_redeemScript.to_p2sh_scriptPubKey()
print(b2x(txin_scriptPubKey))
# Convert the P2SH scriptPubKey to a base58 Bitcoin address and print it.
# You'll need to send some funds to it to create a txout to spend.
txin_p2sh_address = CBitcoinAddress.from_scriptPubKey(txin_scriptPubKey)
print('Pay to:', str(txin_p2sh_address))

# Same as the txid:vout the createrawtransaction RPC call requires
#
# lx() takes *little-endian* hex and converts it to bytes; in Bitcoin
# transaction hashes are shown little-endian rather than the usual big-endian.
# There's also a corresponding x() convenience function that takes big-endian
# hex and converts it to bytes.
txid = lx('d7000d7b437421bbf0fcd465d28c6946954dd6faaec491c02f831ef47429c589')
vout = 0
# Valid input:
# https://segnet.smartbit.com.au/tx/d7000d7b437421bbf0fcd465d28c6946954dd6faaec491c02f831ef47429c589

#
# {
#       "value": 0.00010000,
#       "n": 0,
#       "scriptPubKey": {
#         "asm": "OP_HASH160 93d31ad1e309a1950fbc86c711f44b5eaabf0e31 OP_EQUAL",
#         "hex": "a91493d31ad1e309a1950fbc86c711f44b5eaabf0e3187",
#         "reqSigs": 1,
#         "type": "scripthash",
#         "addresses": [
#           "MMNnTSnrzFijzyJUYiYRzYbjjZK8wLSn9B"
#         ]
#       }
# }

# Create the txin structure, which includes the outpoint. The scriptSig
# defaults to being empty.
# >>> prevout=None, scriptSig=CScript(), witness=[], nSequence = 0xffffffff
txin = CMutableTxIn(COutPoint(txid, vout))

# Create the txout. This time we create the scriptPubKey from a Bitcoin
# address.
txout = CMutableTxOut(int(0.000001*COIN), CBitcoinAddress('DBbMDdC9jHs9azYdME9xvdwSiiJn45Yyvf').to_scriptPubKey())

# Create the unsigned transaction.
tx = CMutableTransaction([txin], [txout])

# Calculate the signature hash for that transaction. Note how the script we use
# is the redeemScript, not the scriptPubKey. That's because when the CHECKSIG
# operation happens EvalScript() will be evaluating the redeemScript, so the
# corresponding SignatureHash() function will use that same script when it
# replaces the scriptSig in the transaction being hashed with the script being
# executed.
# sighash = SignatureHash(txin_redeemScript, tx, 0, SIGHASH_ALL)
sighash = Segwit0SignatureHash(txin_redeemScript, tx, 0, int(.00001*COIN), SIGHASH_ALL)

# Now sign it. We have to append the type of signature we want to the end, in
# this case the usual SIGHASH_ALL.
sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

# Set the scriptSig of our transaction input appropriately.
# OLD >>> txin.scriptSig = CScript([sig, txin_redeemScript])

Hash1 = lambda msg: hashlib.sha256(msg).digest()  # I am sure that this is not a Hash() call

sign = True
if sign:
    txin.witness = [b'', sig, txin_redeemScript] # CScript([OP_0, sig, txin_redeemScript])  # OP_0 at start → only if CHECKMULTISIG (bug)
    txin.scriptSig = CScript([OP_0, Hash1(txin_redeemScript)])  # OP_0 → Version 0 of segwit

# Problem: the witness is not serialized
# print('Wit:', b2x(txin.witness))
# because witness is in the wrong place.
# So: let's put witness in the right place
# TODO: this code must be inside the CTransaction definition
assert len(txin.witness) <= 10000
tx.witness = CTxWitness([CTxinWitness(CScriptWitness(txin.witness))])

# Verify the signature worked. This calls EvalScript() and actually executes
# the opcodes in the scripts to see if everything worked out. If it doesn't an
# exception will be raised.
# VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

# Done! Print the transaction to standard output with the bytes-to-hex
# function.
bb = tx.serialize()
print(b2x(bb))
