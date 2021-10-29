# This file is part of the Trezor project.
#
# Copyright (C) 2012-2019 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

import pytest

from trezorlib import ethereum
from trezorlib.tools import parse_path

from ...common import parametrize_using_common_fixtures

pytestmark = [pytest.mark.altcoin, pytest.mark.ethereum, pytest.mark.skip_t1]


@parametrize_using_common_fixtures("ethereum/sign_typed_data.json")
def test_ethereum_sign_typed_data(client, parameters, result):
    with client:
        address_n = parse_path(parameters["path"])
        ret = ethereum.sign_typed_data(
            client,
            address_n,
            parameters["data"],
            metamask_v4_compat=parameters["metamask_v4_compat"],
        )
        assert ret.address == result["address"]
        assert f"0x{ret.signature.hex()}" == result["sig"]
