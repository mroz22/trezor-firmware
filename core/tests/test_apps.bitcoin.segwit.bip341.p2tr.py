from common import *

from apps.bitcoin.common import SIGHASH_ALL_TAPROOT
from apps.bitcoin.scripts import output_derive_script
from apps.bitcoin.sign_tx.bitcoin import Bip143Hash
from apps.bitcoin.writers import get_tx_hash
from apps.common import coins
from trezor.messages import SignTx
from trezor.messages import TxInput
from trezor.messages import TxOutput
from trezor.messages import PrevOutput
from trezor.enums import InputScriptType
from trezor.enums import OutputScriptType


class TestSegwitBip341P2TR(unittest.TestCase):
    # pylint: disable=C0301

    tx = SignTx(coin_name='Bitcoin', version=2, lock_time=0x00000000, inputs_count=2, outputs_count=1)
    inp1 = TxInput(address_n=[0],
                       prev_hash=unhexlify('8dcb562f365cfeb249be74e7865135cf035add604234fc0d8330b49bec92605f'),
                       prev_index=0,
                       amount=500000000,  # 5 btc
                       script_type=InputScriptType.SPENDWITNESS,
                       multisig=None,
                       sequence=0,
                       script_pubkey=unhexlify("0014196a5bea745288a7f947993c28e3a0f2108d2e0a"))
    inp2 = TxInput(address_n=[1],
                       prev_hash=unhexlify('e1323b577ed0d216f4e52bf2b4c490710dfa0088dae3d15e8ba26ad792184361'),
                       prev_index=1,
                       multisig=None,
                       amount=600000000,  # 6 btc
                       script_type=InputScriptType.SPENDTAPROOT,
                       sequence=0,
                       script_pubkey=unhexlify("512029d942d0408906b359397b6f87c5145814a9aefc8c396dd05efa8b5b73576bf2"))
    out1 = TxOutput(address='1AVrNUPAytZZbisNduCacWcEVJS6eGRvaa',
                        amount=1000000000,
                        script_type=OutputScriptType.PAYTOADDRESS,
                        multisig=None,
                        address_n=[])

    def test_prevouts(self):
        bip143 = Bip143Hash()
        bip143.add_input(self.inp1, self.inp1.script_pubkey)
        bip143.add_input(self.inp2, self.inp2.script_pubkey)
        prevouts_hash = get_tx_hash(bip143.h_prevouts)
        self.assertEqual(hexlify(prevouts_hash), b'32553b113292dfa8216546e721388a6c19c76626ca65dc187e0348d6ed445f81')

    def test_amounts(self):
        bip143 = Bip143Hash()
        bip143.add_input(self.inp1, self.inp1.script_pubkey)
        bip143.add_input(self.inp2, self.inp2.script_pubkey)
        prevouts_hash = get_tx_hash(bip143.h_amounts)
        self.assertEqual(hexlify(prevouts_hash), b'5733468db74734c00efa0b466bca091d8f1aab074af2538f36bd0a734a5940c5')

    def test_scriptpubkeys(self):
        bip143 = Bip143Hash()
        bip143.add_input(self.inp1, self.inp1.script_pubkey)
        bip143.add_input(self.inp2, self.inp2.script_pubkey)
        prevouts_hash = get_tx_hash(bip143.h_scriptpubkeys)
        self.assertEqual(hexlify(prevouts_hash), b'423cd73484fc5e3e0a623442846c279c2216f25a2f32d161fea6c5821a1adde7')

    def test_sequence(self):
        bip143 = Bip143Hash()
        bip143.add_input(self.inp1, self.inp1.script_pubkey)
        bip143.add_input(self.inp2, self.inp2.script_pubkey)
        sequence_hash = get_tx_hash(bip143.h_sequences)
        self.assertEqual(hexlify(sequence_hash), b'af5570f5a1810b7af78caf4bc70a660f0df51e42baf91d4de5b2328de0e83dfc')

    def test_outputs(self):
        coin = coins.by_name(self.tx.coin_name)
        bip143 = Bip143Hash()

        script_pubkey = output_derive_script(self.out1.address, coin)
        txo_bin = PrevOutput(amount=self.out1.amount, script_pubkey=script_pubkey)
        bip143.add_output(txo_bin, script_pubkey)

        outputs_hash = get_tx_hash(bip143.h_outputs)
        self.assertEqual(hexlify(outputs_hash), b'8cdee56004a241f9c79cc55b7d79eaed04909d84660502a2d4e9c357c2047cf5')

    def test_preimage_testdata(self):
        coin = coins.by_name(self.tx.coin_name)
        bip143 = Bip143Hash()
        bip143.add_input(self.inp1, self.inp1.script_pubkey)
        bip143.add_input(self.inp2, self.inp2.script_pubkey)

        script_pubkey = output_derive_script(self.out1.address, coin)
        txo_bin = PrevOutput(amount=self.out1.amount, script_pubkey=script_pubkey)
        bip143.add_output(txo_bin, script_pubkey)

        # test data public key hash
        # only for input 2 - input 1 is not taproot
        result = bip143.preimage_hash(1, self.inp2, b"", 1, self.tx, coin, SIGHASH_ALL_TAPROOT)
        self.assertEqual(hexlify(result), b'07333acfe6dce8196f1ad62b2e039a3d9f0b6627bf955be767c519c0f8789ff4')


if __name__ == '__main__':
    unittest.main()
