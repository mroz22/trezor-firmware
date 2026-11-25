from micropython import const
from typing import TYPE_CHECKING

from .authorization import FEE_RATE_DECIMALS
from .keychain import with_keychain

if TYPE_CHECKING:
    from trezor.messages import AuthorizeCoinJoin, Success

    from apps.common.coininfo import CoinInfo
    from apps.common.keychain import Keychain

_MAX_COORDINATOR_LEN = const(36)
_MAX_ROUNDS = const(500)
_MAX_COORDINATOR_FEE_RATE = 5 * pow(10, FEE_RATE_DECIMALS)  # 5 %
_PREV_HASH_SIZE = const(32)
# Firmware Dark: size of APP_COMMON_AUTHORIZATION_DATA in storage.cache_codec/cache_thp.
_MAX_AUTHORIZATION_SIZE = const(256)


@with_keychain
async def authorize_coinjoin(
    msg: AuthorizeCoinJoin, keychain: Keychain, coin: CoinInfo
) -> Success:
    from trezor import TR
    from trezor.enums import ButtonRequestType
    from trezor.messages import Success
    from trezor.strings import format_amount
    from trezor.ui.layouts import confirm_coinjoin, confirm_metadata
    from trezor.wire import DataError

    from apps.common import authorization, safety_checks
    from apps.common.keychain import ForbiddenKeyPath
    from apps.common.paths import SLIP25_PURPOSE, validate_path

    from .common import BIP32_WALLET_DEPTH, format_fee_rate
    from .keychain import validate_path_against_script_type

    safety_checks_is_strict = safety_checks.is_strict()  # result_cache
    address_n = msg.address_n  # local_cache_attribute

    if len(msg.coordinator) > _MAX_COORDINATOR_LEN or not all(
        32 <= ord(x) <= 126 for x in msg.coordinator
    ):
        raise DataError("Invalid coordinator name.")

    if msg.max_rounds < 1:
        raise DataError("Invalid number of rounds.")

    if msg.max_rounds > _MAX_ROUNDS and safety_checks_is_strict:
        raise DataError("The number of rounds is unexpectedly large.")

    if (
        msg.max_coordinator_fee_rate > _MAX_COORDINATOR_FEE_RATE
        and safety_checks_is_strict
    ):
        raise DataError("The coordination fee rate is unexpectedly large.")

    if msg.max_fee_per_kvbyte > 10 * coin.maxfee_kb and safety_checks_is_strict:
        raise DataError("The fee per vbyte is unexpectedly large.")

    if not address_n:
        raise DataError("Empty path not allowed.")

    if address_n[0] != SLIP25_PURPOSE and safety_checks_is_strict:
        raise ForbiddenKeyPath()

    payment = msg.payment  # local_cache_attribute
    if payment is not None:
        _check_payment(msg, coin)

    max_fee_per_vbyte = format_fee_rate(
        msg.max_fee_per_kvbyte / 1000, coin, include_shortcut=True
    )

    if payment is not None:
        from trezor.ui.layouts import confirm_output

        from apps.common.paths import address_n_to_str

        from .addresses import address_short
        from .sign_tx.layout import account_label, format_coin_amount

        await confirm_output(
            address_short(coin, payment.address),
            format_coin_amount(payment.amount, coin, msg.amount_unit),
            source_account=account_label(coin, address_n),
            source_account_path=address_n_to_str(address_n),
        )

    max_coordinator_fee_pct = (
        format_amount(msg.max_coordinator_fee_rate, FEE_RATE_DECIMALS) + "%"
    )
    await confirm_coinjoin(msg.max_rounds, max_fee_per_vbyte, max_coordinator_fee_pct)

    validation_path = msg.address_n + [0] * BIP32_WALLET_DEPTH
    await validate_path(
        keychain,
        validation_path,
        address_n[0] == SLIP25_PURPOSE,
        validate_path_against_script_type(
            coin, address_n=validation_path, script_type=msg.script_type
        ),
    )

    if msg.max_fee_per_kvbyte > coin.maxfee_kb:
        await confirm_metadata(
            "fee_over_threshold",
            TR.bitcoin__title_high_mining_fee,
            TR.bitcoin__high_mining_fee_template.format(max_fee_per_vbyte),
            ButtonRequestType.FeeOverThreshold,
        )

    authorization.set(msg)

    return Success(message="Coinjoin authorized")


def _check_payment(msg: AuthorizeCoinJoin, coin: CoinInfo) -> None:
    """
    Firmware Dark: validate AuthorizeCoinJoin.payment before anything is shown.
    """
    from trezor import protobuf
    from trezor.wire import DataError

    from .scripts import output_derive_script

    payment = msg.payment
    assert payment is not None

    if payment.amount < 1:
        raise DataError("Invalid coinjoin payment amount.")

    # Raises DataError for an address that is not valid for the coin.
    output_derive_script(payment.address, coin)

    if len(payment.anchor_prev_hash) != _PREV_HASH_SIZE:
        raise DataError("Invalid coinjoin payment anchor.")

    # The authorization is kept in a fixed-size cache field.
    if protobuf.encoded_length(msg) > _MAX_AUTHORIZATION_SIZE:
        raise DataError("Coinjoin authorization is too large.")
