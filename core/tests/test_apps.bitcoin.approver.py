# flake8: noqa: F403,F405
from common import *  # isort:skip

import storage.cache_codec
from trezor import wire
from trezor.crypto import bip32
from trezor.enums import InputScriptType, OutputScriptType
from trezor.messages import (
    AuthorizeCoinJoin,
    CoinJoinPayment,
    CoinJoinRequest,
    SignTx,
    TxInput,
    TxOutput,
)

from apps.bitcoin.authorization import FEE_RATE_DECIMALS, CoinJoinAuthorization
from apps.bitcoin.sign_tx.approvers import CoinJoinApprover
from apps.bitcoin.sign_tx.bitcoin import Bitcoin
from apps.bitcoin.sign_tx.tx_info import TxInfo
from apps.common import coins


class TestApprover(TestCaseWithContext):
    def setUp(self):
        self.coin = coins.by_name("Bitcoin")
        self.fee_rate_percent = 0.3
        self.no_fee_threshold = 1000000
        self.min_registrable_amount = 5000
        self.coordinator_name = "www.example.com"

        self.node = bip32.HDNode(
            depth=0,
            fingerprint=0,
            child_num=0,
            chain_code=bytearray(32),
            private_key=b"\x01" * 32,
            curve_name="secp256k1",
        )

        self.msg_auth = AuthorizeCoinJoin(
            coordinator=self.coordinator_name,
            max_rounds=10,
            max_coordinator_fee_rate=int(self.fee_rate_percent * 10**FEE_RATE_DECIMALS),
            max_fee_per_kvbyte=7000,
            address_n=[H_(10025), H_(0), H_(0), H_(1)],
            coin_name=self.coin.coin_name,
            script_type=InputScriptType.SPENDTAPROOT,
        )
        if not utils.USE_THP:
            storage.cache_codec.start_session()

    def make_coinjoin_request(self, inputs):
        return CoinJoinRequest(
            fee_rate=int(self.fee_rate_percent * 10**FEE_RATE_DECIMALS),
            no_fee_threshold=self.no_fee_threshold,
            min_registrable_amount=self.min_registrable_amount,
            mask_public_key=bytearray(),
            signature=bytearray(),
        )

    def test_coinjoin_lots_of_inputs(self):
        denomination = 10_000_000
        coordinator_fee = int(self.fee_rate_percent / 100 * denomination)
        fees = coordinator_fee + 500

        # Other's inputs.
        inputs = [
            TxInput(
                prev_hash=bytes(32),
                prev_index=0,
                amount=denomination,
                script_pubkey=bytes(22),
                script_type=InputScriptType.EXTERNAL,
                sequence=0xFFFFFFFF,
                witness=bytes(1),
            )
            for i in range(99)
        ]

        # Our input.
        inputs.insert(
            30,
            TxInput(
                prev_hash=bytes(32),
                prev_index=0,
                address_n=[H_(10025), H_(0), H_(0), H_(1), 0, 1],
                amount=denomination,
                script_type=InputScriptType.SPENDTAPROOT,
                sequence=0xFFFFFFFF,
            ),
        )

        # Other's CoinJoined outputs.
        outputs = [
            TxOutput(
                address="",
                amount=denomination - fees,
                script_type=OutputScriptType.PAYTOTAPROOT,
                payment_req_index=0,
            )
            for i in range(99)
        ]

        # Our CoinJoined output.
        outputs.insert(
            40,
            TxOutput(
                address="",
                address_n=[H_(10025), H_(0), H_(0), H_(1), 0, 2],
                amount=denomination - fees,
                script_type=OutputScriptType.PAYTOTAPROOT,
                payment_req_index=0,
            ),
        )

        # Coordinator's output.
        outputs.append(
            TxOutput(
                address="",
                amount=coordinator_fee * len(outputs),
                script_type=OutputScriptType.PAYTOTAPROOT,
                payment_req_index=0,
            )
        )

        coinjoin_req = self.make_coinjoin_request(inputs)
        tx = SignTx(
            outputs_count=len(outputs),
            inputs_count=len(inputs),
            coin_name=self.coin.coin_name,
            lock_time=0,
            coinjoin_request=coinjoin_req,
        )
        authorization = CoinJoinAuthorization(self.msg_auth)
        approver = CoinJoinApprover(tx, self.coin, authorization)
        signer = Bitcoin(tx, None, self.coin, approver)
        tx_info = TxInfo(signer, tx)

        for txi in inputs:
            if txi.script_type == InputScriptType.EXTERNAL:
                approver.add_external_input(txi)
            else:
                await_result(approver.add_internal_input(txi, self.node))

        for txo in outputs:
            if txo.address_n:
                await_result(approver.add_change_output(txo, script_pubkey=bytes(22)))
            else:
                await_result(
                    approver.add_external_output(
                        txo, script_pubkey=bytes(22), tx_info=tx_info
                    )
                )

        await_result(approver.approve_tx(tx_info, [], None))

    def test_coinjoin_input_account_depth_mismatch(self):
        txi = TxInput(
            prev_hash=bytes(32),
            prev_index=0,
            address_n=[H_(10025), H_(0), H_(0), H_(1), 0],
            amount=10000000,
            script_type=InputScriptType.SPENDTAPROOT,
        )

        coinjoin_req = self.make_coinjoin_request([txi])
        tx = SignTx(
            outputs_count=201,
            inputs_count=100,
            coin_name=self.coin.coin_name,
            lock_time=0,
            coinjoin_request=coinjoin_req,
        )
        authorization = CoinJoinAuthorization(self.msg_auth)
        approver = CoinJoinApprover(tx, self.coin, authorization)

        with self.assertRaises(wire.ProcessError):
            await_result(approver.add_internal_input(txi, self.node))

    def test_coinjoin_input_account_path_mismatch(self):
        txi = TxInput(
            prev_hash=bytes(32),
            prev_index=0,
            address_n=[H_(10025), H_(0), H_(1), H_(1), 0, 0],
            amount=10000000,
            script_type=InputScriptType.SPENDTAPROOT,
        )

        coinjoin_req = self.make_coinjoin_request([txi])
        tx = SignTx(
            outputs_count=201,
            inputs_count=100,
            coin_name=self.coin.coin_name,
            lock_time=0,
            coinjoin_request=coinjoin_req,
        )
        authorization = CoinJoinAuthorization(self.msg_auth)
        approver = CoinJoinApprover(tx, self.coin, authorization)

        with self.assertRaises(wire.ProcessError):
            await_result(approver.add_internal_input(txi, self.node))

    # Firmware Dark: AuthorizeCoinJoin.payment

    PAYMENT_ADDRESS = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    PAYMENT_SCRIPT = bytes.fromhex("0014751e76e8199196d454941c45d1b3a323f1433bd6")
    PAYMENT_AMOUNT = 1_234_567
    ANCHOR_PREV_HASH = b"\x11" * 32
    ANCHOR_PREV_INDEX = 3
    OTHER_PREV_HASH = b"\x22" * 32

    def make_payment_auth(self, max_rounds=10):
        msg_auth = AuthorizeCoinJoin(
            coordinator=self.msg_auth.coordinator,
            max_rounds=max_rounds,
            max_coordinator_fee_rate=self.msg_auth.max_coordinator_fee_rate,
            max_fee_per_kvbyte=self.msg_auth.max_fee_per_kvbyte,
            address_n=self.msg_auth.address_n,
            coin_name=self.msg_auth.coin_name,
            script_type=self.msg_auth.script_type,
            payment=CoinJoinPayment(
                address=self.PAYMENT_ADDRESS,
                amount=self.PAYMENT_AMOUNT,
                anchor_prev_hash=self.ANCHOR_PREV_HASH,
                anchor_prev_index=self.ANCHOR_PREV_INDEX,
            ),
        )
        return CoinJoinAuthorization(msg_auth)

    def sign_payment_tx(
        self,
        authorization,
        our_inputs=((ANCHOR_PREV_HASH, ANCHOR_PREV_INDEX),),
        payment_outputs=((PAYMENT_AMOUNT, PAYMENT_SCRIPT),),
        foreign_payment=False,
    ):
        denomination = 10_000_000
        coordinator_fee = int(self.fee_rate_percent / 100 * denomination)
        fees = coordinator_fee + 500
        paid = sum(amount for amount, _ in payment_outputs)
        our_paid = 0 if foreign_payment else paid

        # Other's inputs and our inputs; the first of ours also funds the payments,
        # unless they are foreign.
        inputs = [
            TxInput(
                prev_hash=bytes(32),
                prev_index=0,
                amount=denomination + (paid if foreign_payment and i == 0 else 0),
                script_pubkey=bytes(22),
                script_type=InputScriptType.EXTERNAL,
                sequence=0xFFFFFFFF,
                witness=bytes(1),
            )
            for i in range(9)
        ]
        for i, (prev_hash, prev_index) in enumerate(our_inputs):
            inputs.insert(
                4 + i,
                TxInput(
                    prev_hash=prev_hash,
                    prev_index=prev_index,
                    address_n=[H_(10025), H_(0), H_(0), H_(1), 0, 1 + i],
                    amount=denomination + (our_paid if i == 0 else 0),
                    script_type=InputScriptType.SPENDTAPROOT,
                    sequence=0xFFFFFFFF,
                ),
            )

        # Other's outputs, our change and the payments.
        outputs = [
            (
                TxOutput(
                    address="",
                    amount=denomination - fees,
                    script_type=OutputScriptType.PAYTOTAPROOT,
                ),
                bytes(22),
            )
            for i in range(9)
        ]
        for i in range(len(our_inputs)):
            outputs.insert(
                2 + i,
                (
                    TxOutput(
                        address="",
                        address_n=[H_(10025), H_(0), H_(0), H_(1), 1, 2 + i],
                        amount=denomination - fees,
                        script_type=OutputScriptType.PAYTOTAPROOT,
                    ),
                    bytes(22),
                ),
            )
        for amount, script_pubkey in payment_outputs:
            outputs.insert(
                6,
                (
                    TxOutput(
                        address=self.PAYMENT_ADDRESS,
                        amount=amount,
                        script_type=OutputScriptType.PAYTOADDRESS,
                    ),
                    script_pubkey,
                ),
            )
        outputs.append(
            (
                TxOutput(
                    address="",
                    amount=coordinator_fee * (9 + len(our_inputs)),
                    script_type=OutputScriptType.PAYTOTAPROOT,
                ),
                bytes(22),
            )
        )

        tx = SignTx(
            outputs_count=len(outputs),
            inputs_count=len(inputs),
            coin_name=self.coin.coin_name,
            lock_time=0,
            coinjoin_request=self.make_coinjoin_request(inputs),
        )
        approver = CoinJoinApprover(tx, self.coin, authorization)
        signer = Bitcoin(tx, None, self.coin, approver)
        tx_info = TxInfo(signer, tx)

        for txi in inputs:
            if txi.script_type == InputScriptType.EXTERNAL:
                approver.add_external_input(txi)
            else:
                await_result(approver.add_internal_input(txi, self.node))

        for txo, script_pubkey in outputs:
            if txo.address_n:
                await_result(approver.add_change_output(txo, script_pubkey))
            else:
                await_result(
                    approver.add_external_output(txo, script_pubkey, tx_info=tx_info)
                )

        await_result(approver.approve_tx(tx_info, [], None))

    def assert_sign_fails(self, authorization, message, **kwargs):
        with self.assertRaises(wire.ProcessError) as e:
            self.sign_payment_tx(authorization, **kwargs)
        self.assertEqual(e.value.message, message)
        # No round was used up.
        self.assertEqual(authorization.params.max_rounds, 10)

    def test_coinjoin_payment_not_authorized(self):
        # Without an authorized payment, the payment output is our fee.
        authorization = CoinJoinAuthorization(self.msg_auth)
        self.assert_sign_fails(authorization, "Total fee over threshold.")

    def test_coinjoin_payment(self):
        authorization = self.make_payment_auth()
        self.sign_payment_tx(authorization)
        self.assertEqual(authorization.params.max_rounds, 9)

        # A retry that spends the anchor too, e.g. a blame round.
        self.sign_payment_tx(authorization)
        self.assertEqual(authorization.params.max_rounds, 8)

    def test_coinjoin_payment_anchor_not_first(self):
        authorization = self.make_payment_auth()
        self.sign_payment_tx(
            authorization,
            our_inputs=(
                (self.OTHER_PREV_HASH, 0),
                (self.ANCHOR_PREV_HASH, self.ANCHOR_PREV_INDEX),
            ),
        )
        self.assertEqual(authorization.params.max_rounds, 9)

    def test_coinjoin_payment_must_spend_anchor(self):
        # Without the anchor, the payment is our fee.
        authorization = self.make_payment_auth()
        self.assert_sign_fails(
            authorization,
            "Total fee over threshold.",
            our_inputs=((self.ANCHOR_PREV_HASH, self.ANCHOR_PREV_INDEX + 1),),
        )
        # Same index, different transaction.
        self.assert_sign_fails(
            authorization,
            "Total fee over threshold.",
            our_inputs=((self.OTHER_PREV_HASH, self.ANCHOR_PREV_INDEX),),
        )

    def test_coinjoin_payment_lookalike_funded_by_others(self):
        # An output like the payment, funded by others in a round that does not spend
        # the anchor (e.g. after the payment was made), is foreign as in upstream.
        authorization = self.make_payment_auth()
        self.sign_payment_tx(
            authorization,
            our_inputs=((self.OTHER_PREV_HASH, 0),),
            foreign_payment=True,
        )
        self.assertEqual(authorization.params.max_rounds, 9)

    def test_coinjoin_payment_wrong_amount(self):
        authorization = self.make_payment_auth()
        self.assert_sign_fails(
            authorization,
            "Total fee over threshold.",
            payment_outputs=((self.PAYMENT_AMOUNT + 1, self.PAYMENT_SCRIPT),),
        )

    def test_coinjoin_payment_wrong_script(self):
        authorization = self.make_payment_auth()
        self.assert_sign_fails(
            authorization,
            "Total fee over threshold.",
            payment_outputs=((self.PAYMENT_AMOUNT, bytes(22)),),
        )

    def test_coinjoin_payment_credited_once(self):
        # Two identical payment outputs funded by us: only one is the payment.
        authorization = self.make_payment_auth()
        self.assert_sign_fails(
            authorization,
            "Total fee over threshold.",
            payment_outputs=(
                (self.PAYMENT_AMOUNT, self.PAYMENT_SCRIPT),
                (self.PAYMENT_AMOUNT, self.PAYMENT_SCRIPT),
            ),
        )

    def test_coinjoin_payment_authorized_but_not_in_tx(self):
        # A round without the payment signs as without an authorized payment,
        # whether it spends the anchor or not.
        authorization = self.make_payment_auth()
        self.sign_payment_tx(authorization, payment_outputs=())
        self.sign_payment_tx(
            authorization,
            our_inputs=((self.OTHER_PREV_HASH, 0),),
            payment_outputs=(),
        )
        self.assertEqual(authorization.params.max_rounds, 8)


if __name__ == "__main__":
    unittest.main()
