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
