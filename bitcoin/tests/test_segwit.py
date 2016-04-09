# Copyright (C) 2013-2015 The python-bitcoinlib developers
#
# This file is part of python-bitcoinlib.
#
# It is subject to the license terms in the LICENSE file found in the top-level
# directory of this distribution.
#
# No part of python-bitcoinlib, including this file, may be copied, modified,
# propagated, or distributed except according to the terms contained in the
# LICENSE file.

from __future__ import absolute_import, division, print_function, unicode_literals

import unittest
import hashlib

import bitcoin
from bitcoin.core import *
from bitcoin.core.script import *
from bitcoin.core.scripteval import *
from bitcoin.wallet import *

# Cosa posso testare.
# Le firme non possono essere confrontate staticamente, ogni firma è diversa.
# Le firme: posso firmare qualcosa e poi verificare che la firma sia corretta. Peccato che non abbia implementato
# io 'sta cosa, quindi che dovrebbe farci qui?
# Sarebbe carino farmi verificare cose da Core (ma non posso fargli eseguire script)
# E regtest? Necessario Core. Potrei rubare del codice python da Core.

# Legacy tx -> get_txid() == GetHash()

# Check SegNetParams

class Test_Witness(unittest.TestCase):

    def make_legacy_tx(self):

        tx = CMutableTransaction()

        return tx

    def test_segnetparams(self):

        def T(addr, scriptPubKey):
            a = CBitcoinAddress(addr)
            self.assertEqual(a.to_scriptPubKey(), x(scriptPubKey))

        bitcoin.SelectParams('segnet')
        T('DPt81S759GYVBaYoEubFkTnQu2grd2DZaM', '76a914cd956057bf12bcbc47c0c95145a23afe154cfcec88ac')
        # 0x76 -> OP_DUP
        # 0xa9 -> OP_HASH160
        # 0x14 -> Push 20 bytes
        # 0xac -> OP_CHECKSIG

        T('MRjHpDwWoWnLjhf7obYr4537H7fXdBjLWw', 'a914c3946f25a2506a3c981bc31eaabca4cc9bf207bf87')
        # 0xa9 -> OP_HASH160
        # 0x14 -> Push 20 bytes
        # 0x87 -> OP_EQUAL

        with self.assertRaises(CBitcoinAddressError):
            CBitcoinAddress('15urYnyeJe3gwbGJ74wcX89Tz7ZtsFDVew')
        # with self.assertRaises(CBitcoinAddressError):
        #     CBitcoinAddress('3xxx')

    def test_transactions(self):

        bitcoin.SelectParams('mainnet')
        h = CKey(hashlib.sha256(b'').digest())


        txin_redeemScript = CScript([OP_1, h.pub, h.pub, OP_2, OP_CHECKMULTISIG])

        # Input to use
        txid = lx('022d1cbb635efb150a2b2ff350839d208f7e9178d37f5fa1e1d69f211ce66327')
        vout = 0

        txin = CMutableTxIn(COutPoint(txid, vout))
        txout = CMutableTxOut(int(0.000001*COIN), CBitcoinAddress('1HKpHuzmehdaTCyoYuT2PuyRwZk3uyiq85').to_scriptPubKey())
        tx = CMutableTransaction([txin], [txout])

        CheckTransaction(tx)

        stx = x('01000000012763e61c219fd6e1a15f7fd378917e8f209d8350f32f2b0a15fb5e63bb1c2d02000000'
                '0000ffffffff0164000000000000001976a914b310fa167c0cec49230649ca99fefde6994dacb988'
                'ac00000000')

        # The biulding of the unsigned transaction is deterministic
        self.assertEqual(tx.serialize(), stx)

        tx2 = CTransaction.deserialize(stx)

        # VerifyScript()
        # VerifyScript(tx.vin[i].scriptSig, prevouts[tx.vin[i].prevout], tx, i, flags=flags)

        # amount should be obtained by COutPoint. It must be equal to the value of
        # prevout: txid:vout
        sighash = SignatureHash1(txin_redeemScript, tx, 0, int(.0001*COIN), SIGHASH_ALL)

        # Now sign it. We have to append the type of signature we want to the end, in
        # this case the usual SIGHASH_ALL.
        sig = h.sign(sighash) + bytes([SIGHASH_ALL])

        # TODO: verify the signature
        # bitcoin.core.scripteval.VerifyScript does not support witness

    def test_padding_error(self):
        """Deprecatd"""
        stx = x('0100000002dbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce000000006b4830450221009627444320dc5ef8d7f68f35010b4c050a6ed0d96b67a84db99fda9c9de58b1e02203e4b4aaa019e012e65d69b487fdf8719df72f488fa91506a80c49a33929f1fd50121022b78b756e2258af13779c1a1f37ea6800259716ca4b7f0b87610e0bf3ab52a01ffffffffdbb33bdf185b17f758af243c5d3c6e164cc873f6bb9f40c0677d6e0f8ee5afce010000009300483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303483045022015bd0139bcccf990a6af6ec5c1c52ed8222e03a0d51c334df139968525d2fcd20221009f9efe325476eb64c3958e4713e9eefe49bf1d820ed58d2112721b134e2a1a5303ffffffff01a0860100000000001976a9149bc0bbdd3024da4d0c38ed1aecf5c68dd1d3fa1288ac00000000')

        tx2 = CTransaction.deserialize(stx)

class Test_CScriptWitness(unittest.TestCase):
    CScriptWitness

class Test_CTxInWitness(unittest.TestCase):
    CTxinWitness

class Test_CTxWitness(unittest.TestCase):
    CTxWitness

if __name__ == "__main__":
    unittest.main()