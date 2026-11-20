# CoinJoin payments (Firmware Dark)

Firmware Dark lets a pre-authorized CoinJoin session pay one third party from inside a round: the payment is one more
output of the CoinJoin transaction. Suite Dark uses it for "pay in coinjoin" and offers it only when the device reports
`Capability_CoinJoinPayment`. Upstream firmware does not have it.

## Why upstream firmware refuses such a round

`CoinJoinApprover` treats every output that is not our own change as somebody else's and bounds what we lose to them:

```
our_fees = total_in - external_in - change_out
our_fees <= coordination fee + max mining fee for our weight + min(min_registrable_amount, 5000) + one output's fee
```

A payment funded by our inputs is neither change nor somebody else's input, so it counts as our fee and signing fails
with `Total fee over threshold.`, unless the payment is small enough to fit in that slack.

## Protocol

```protobuf
message AuthorizeCoinJoin {
    ...
    optional CoinJoinPayment payment = 200;

    message CoinJoinPayment {
        required string address = 1;
        required uint64 amount = 2;
        required bytes anchor_prev_hash = 3;   // same byte order as TxInput.prev_hash (txid as displayed)
        required uint32 anchor_prev_index = 4;
    }
}

Capability_CoinJoinPayment = 1001 [(bitcoin_only) = true];
```

Fork-only numbers are high so that they do not collide with future upstream ones. Field numbers must stay below 256
because core decodes field tags as one byte (`common/protob/pb2py`, `decode.rs`); enum values may go up to 65535.

## Authorization

`authorize_coinjoin` with a payment:

1. rejects a zero amount, an address that is not valid for the coin and an anchor hash that is not 32 bytes long;
2. checks that the message fits the 256-byte authorization cache field;
3. shows the payment (address, then amount) with `trezor.ui.layouts.confirm_output`, then the usual CoinJoin
   confirmation. The screens send `ButtonRequest_ConfirmOutput`. The source account is shown in the info menu on Safe
   3/5/7 and not at all on Model T. There are no new translation strings; the cancel wording is that of transaction
   signing.

Nothing is shown before the checks pass. The authorization is stored as the serialized `AuthorizeCoinJoin` message in
`APP_COMMON_AUTHORIZATION_DATA`, which Firmware Dark raises from 128 to 256 bytes (`storage/cache_codec.py`,
`storage/cache_thp.py`). The device never changes the stored payment.

## Signing and the anchor

A signed CoinJoin transaction never expires. A malicious coordinator could collect all our signatures of a round that
carries the payment, report the round as failed and broadcast it later, after the host paid again in another round with
other inputs. The anchor, an outpoint of the account that the host chooses when it creates the payment, prevents that:

- In a transaction that spends the anchor, the first external output with exactly the payment's `script_pubkey` and
  amount is the payment: its amount is excluded from `our_fees` and its weight is added to ours, so the mining-fee bound
  covers it. Any further identical output is foreign.
- In a transaction that does not spend the anchor, no output is the payment: everything is checked exactly as upstream.
  A payment funded by our inputs then fails with `Total fee over threshold.`; an identical output funded by somebody else
  (for example after the payment was made, or to a reused address) is just foreign.
- Every transaction that carries the payment spends the anchor, so at most one of them can ever confirm.

All inputs are processed before the outputs (`Bitcoin.step1_process_inputs`), so the approver knows whether the anchor is
spent when it sees the payment output. A transaction without the payment output is signed exactly as upstream.

The host must keep the anchor and pass the same one in every authorization with that payment (also after a replug or a
restart), register the anchor UTXO in every round that carries the payment, and spend it in an ordinary send to cancel the
payment. A device-recorded anchor was considered and rejected: the device would record it at approval, before the
signatures are streamed, and a host whose signing was interrupted would not know it.

## Security notes

- Compared with upstream, the user can additionally lose only the authorized amount to the authorized script, at most
  once per anchor, plus the mining fee for the payment output's weight at `max_fee_per_kvbyte`.
- A compromised host can obtain a second payment only through a second on-device approval of the payment screen with a
  different anchor. The anchor is not shown, and the honest host asks for the same screen after every replug, so such an
  approval looks routine. Accepted risk in this version; the extra money still goes to the approved payee.
- Firmware without this change ignores the unknown field: it shows no payment, authorizes, and later refuses to sign the
  payment round. Hosts therefore check `Capability_CoinJoinPayment` first.
- Legacy (T1B1) is not built by Firmware Dark. Its nanopb options ignore the new field.

## Tests

- `core/tests/test_apps.bitcoin.approver.py`: crediting with the anchor (also not as the first input), a retry, no
  credit without the anchor (also same index, different hash), wrong amount or script, a duplicate payment output, a
  round without the payment, an identical output funded by others.
- `tests/device_tests/bitcoin/test_authorize_coinjoin.py`, `test_payment_*`: capability, the payment and CoinJoin
  screens, signing and a retry, no anchor, no authorized payment, wrong amount, invalid payments (nothing shown), an
  authorization that is too large. No UI fixtures are recorded.
