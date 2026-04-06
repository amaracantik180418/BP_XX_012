// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Base Punk Collective — BP_XX_012

    A social contract for DAO growth: patches (membership), rituals (proposals),
    and accountable treasury motion with an execution delay.

    This file is intentionally self-contained for mainnet deployments:
    - no external imports
    - explicit errors/events
    - defensive ETH/ERC20 handling
*/

/*//////////////////////////////////////////////////////////////
                            INTERFACES
//////////////////////////////////////////////////////////////*/

interface IERC20Minimal {
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

interface IERC721ReceiverMinimal {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

/*//////////////////////////////////////////////////////////////
                            LIBRARIES
//////////////////////////////////////////////////////////////*/

library BPAddress {
    error BPAddress_NonContract(address target);
    error BPAddress_CallFailed();
    error BPAddress_EmptyReturn();

    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function sendValue(address payable to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert BPAddress_CallFailed();
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
        if (!isContract(target)) revert BPAddress_NonContract(target);
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) revert BPAddress_CallFailed();
        return ret;
    }

    function functionCallOptionalReturn(address token, bytes memory data) internal {
        bytes memory ret = functionCall(token, data);
        if (ret.length == 0) return; // some tokens return no data
        if (ret.length < 32) revert BPAddress_EmptyReturn();
        if (!abi.decode(ret, (bool))) revert BPAddress_CallFailed();
    }
}

library BPSafeERC20 {
    using BPAddress for address;

    function safeTransfer(IERC20Minimal token, address to, uint256 amount) internal {
        address(token).functionCallOptionalReturn(abi.encodeWithSelector(token.transfer.selector, to, amount));
    }

    function safeTransferFrom(IERC20Minimal token, address from, address to, uint256 amount) internal {
        address(token).functionCallOptionalReturn(
            abi.encodeWithSelector(token.transferFrom.selector, from, to, amount)
        );
    }

    function safeApprove(IERC20Minimal token, address spender, uint256 amount) internal {
        address(token).functionCallOptionalReturn(abi.encodeWithSelector(token.approve.selector, spender, amount));
    }
}

library BPMath {
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? (a - b) : (b - a);
    }

    function sqrt(uint256 x) internal pure returns (uint256 y) {
        if (x == 0) return 0;
        uint256 z = (x + 1) / 2;
        y = x;
        while (z < y) {
            y = z;
            z = (x / z + z) / 2;
        }
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }
}

library BPStrings {
    bytes16 private constant _HEX = "0123456789abcdef";

    function toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = _HEX[value & 0xf];
            value >>= 4;
        }
        return string(buffer);
    }
}

library BPECDSA {
    error BPECDSA_BadSig();
    error BPECDSA_BadS();
    error BPECDSA_BadV();

    // secp256k1n/2 per EIP-2
    uint256 private constant _SECP256K1N_DIV_2 =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

