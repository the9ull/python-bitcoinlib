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
if sys.version_info.major < 3:
    sys.stderr.write('Sorry, Python 3.x required by this example.\n')
    sys.exit(1)

import argparse
import hashlib
import logging
import sys
import os

import bitcoin.rpc
from bitcoin.core import *
from bitcoin.core.script import *
from bitcoin.wallet import *

txid = lx('7e195aa3de827814f172c362fcf838d92ba10e3f9fdd9c3ecaf79522b311b22d')
vout = 0

# Create the txin structure, which includes the outpoint. The scriptSig
# defaults to being empty.
txin = CMutableTxIn(COutPoint(txid, vout))

# We also need the scriptPubKey of the output we're spending because
# SignatureHash() replaces the transaction scriptSig's with it.
#
# Here we'll create that scriptPubKey from scratch using the pubkey that
# corresponds to the secret key we generated above.
txin_scriptPubKey = CScript([OP_DUP, OP_HASH160, Hash160(seckey.pub), OP_EQUALVERIFY, OP_CHECKSIG])

# Create the txout. This time we create the scriptPubKey from a Bitcoin
# address.
txout = CMutableTxOut(0.001*COIN, CBitcoinAddress('1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8').to_scriptPubKey())

# Create the unsigned transaction.
tx = CMutableTransaction([txin], [txout])

# Calculate the signature hash for that transaction.
sighash = SignatureHash(txin_scriptPubKey, tx, 0, SIGHASH_ALL)

# Now sign it. We have to append the type of signature we want to the end, in
# this case the usual SIGHASH_ALL.
sig = seckey.sign(sighash) + bytes([SIGHASH_ALL])

# Set the scriptSig of our transaction input appropriately.
txin.scriptSig = CScript([sig, seckey.pub])

# Verify the signature worked. This calls EvalScript() and actually executes
# the opcodes in the scripts to see if everything worked out. If it doesn't an
# exception will be raised.
VerifyScript(txin.scriptSig, txin_scriptPubKey, tx, 0, (SCRIPT_VERIFY_P2SH,))

# Done! Print the transaction to standard output with the bytes-to-hex
# function.
print(b2x(tx.serialize()))
