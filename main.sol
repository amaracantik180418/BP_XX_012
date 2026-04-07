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

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert BPECDSA_BadSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        if (uint256(s) > _SECP256K1N_DIV_2) revert BPECDSA_BadS();
        if (v != 27 && v != 28) revert BPECDSA_BadV();
        address signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert BPECDSA_BadSig();
        return signer;
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

library BPMerkle {
    function verify(bytes32[] calldata proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computed = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            computed = computed <= p ? keccak256(abi.encodePacked(computed, p)) : keccak256(abi.encodePacked(p, computed));
        }
        return computed == root;
    }
}

/*//////////////////////////////////////////////////////////////
                            CORE GUARDS
//////////////////////////////////////////////////////////////*/

abstract contract BPReentrancyGuard {
    error BP_Reentry();
    uint256 private _bpLock;
    modifier nonReentrant() {
        if (_bpLock == 1) revert BP_Reentry();
        _bpLock = 1;
        _;
        _bpLock = 0;
    }
}

abstract contract BPPausable {
    error BP_Paused();
    error BP_NotPaused();
    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert BP_Paused();
        _;
    }

    modifier whenPaused() {
        if (!paused) revert BP_NotPaused();
        _;
    }
}

/*//////////////////////////////////////////////////////////////
                        BP_XX_012 MAIN CONTRACT
//////////////////////////////////////////////////////////////*/

contract BP_XX_012 is BPReentrancyGuard, BPPausable {
    using BPSafeERC20 for IERC20Minimal;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error BP_Unauthorized();
    error BP_Zero();
    error BP_BadArray();
    error BP_BadTime();
    error BP_BadRange();
    error BP_Exists();
    error BP_NotFound();
    error BP_Locked();
    error BP_TooSoon();
    error BP_TooLate();
    error BP_Already();
    error BP_Soulbound();
    error BP_BadSig();
    error BP_BadTarget();
    error BP_ExecFailed(uint256 idx);
    error BP_SupplyCap();
    error BP_Quorum();
    error BP_Dust();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event BP_PauseFlip(bool on, address indexed by, uint64 at);
    event BP_GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event BP_TreasurerSet(address indexed oldTreasurer, address indexed newTreasurer);
    event BP_ParametersSet(bytes32 indexed key, uint256 value);

    event BP_PatchMinted(address indexed to, uint256 indexed patchId, uint256 seed, bytes32 vibe);
    event BP_PatchBurned(address indexed from, uint256 indexed patchId);
    event BP_PatchNote(uint256 indexed patchId, bytes32 indexed noteHash);

    event BP_Proposed(
        uint256 indexed proposalId,
        address indexed author,
        bytes32 indexed topic,
        uint64 voteStart,
        uint64 voteEnd,
        uint64 eta,
        uint256 minPower
    );
    event BP_VoteCast(uint256 indexed proposalId, address indexed voter, uint8 support, uint256 weight, uint256 salt);
    event BP_Queued(uint256 indexed proposalId, uint64 eta);
    event BP_Canceled(uint256 indexed proposalId, address indexed by);
    event BP_Executed(uint256 indexed proposalId, address indexed by);

    event BP_TreasuryDeposit(address indexed from, uint256 amount, bytes32 memo);
    event BP_TreasuryWithdraw(address indexed to, uint256 amount, bytes32 memo);
    event BP_TokenSweep(address indexed token, address indexed to, uint256 amount);

    event BP_DelegateSet(address indexed delegator, address indexed delegate, uint64 atBlock);
    event BP_Manifest(bytes32 indexed manifestoHash, bytes32 indexed audioHash, bytes32 indexed artHash);

    /*//////////////////////////////////////////////////////////////
                                METADATA
    //////////////////////////////////////////////////////////////*/

    string public constant name = "Base Punk Collective Patch";
    string public constant symbol = "BPATCH";

    // Deliberately nonstandard constant names & values for distinct fingerprints.
    bytes32 public constant BP_VIBE =
        0x67b1e0a7d59cfbb6f5fd0c9bb4bcd8a6c6e62b4b9b74f72a67d45f6a3f86ad33;
    bytes32 public constant BP_RITUAL =
        0x0e4f778d4a3b3ad62a5f77f9d1e847a77df1c6e4a6e0c53b51e6cfedac0f3a7b;

    uint256 private constant _BASIS = 10_000;

    /*//////////////////////////////////////////////////////////////
                                IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    // These are not trusted for privileges; they are “scene anchors” & default recipients.
    address public immutable SCENE_ANCHOR_A;
    address public immutable SCENE_ANCHOR_B;
    address public immutable SCENE_ANCHOR_C;

    /*//////////////////////////////////////////////////////////////
                                ROLES
    //////////////////////////////////////////////////////////////*/

    address public guardian;
    address public treasurer;

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert BP_Unauthorized();
        _;
    }

    modifier onlyTreasurer() {
        if (msg.sender != treasurer) revert BP_Unauthorized();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                PATCH (SOULBOUND ERC721-LIKE)
    //////////////////////////////////////////////////////////////*/

    mapping(uint256 => address) private _ownerOf;
    mapping(address => uint256) private _balanceOf;
    mapping(uint256 => address) private _getApproved;
    mapping(address => mapping(address => bool)) private _isApprovedForAll;

    uint256 public totalMinted;
    uint256 public burned;
    uint256 public immutable supplyCap;

    mapping(uint256 => bytes32) public patchVibe; // extra on-chain flavor
    mapping(uint256 => bytes32) public patchNoteHash;

    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    event Approval(address indexed owner, address indexed spender, uint256 indexed tokenId);
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /*//////////////////////////////////////////////////////////////
                                GOVERNANCE SNAPSHOT
    //////////////////////////////////////////////////////////////*/

    // Delegate system (not a token transfer system; patches are soulbound).
    mapping(address => address) public delegates;
    mapping(address => uint256) public nonces;

    // Vote checkpoints (single weight per address, but tracked by block for governance)
    struct Checkpoint {
        uint32 fromBlock;
        uint224 votes;
    }
    mapping(address => Checkpoint[]) private _checkpoints;
    Checkpoint[] private _totalCheckpoints;

    /*//////////////////////////////////////////////////////////////
                                PROPOSALS + TIMELOCK
    //////////////////////////////////////////////////////////////*/

    // governance parameters (settable by governance execution only)
    uint256 public votingDelayBlocks;
    uint256 public votingPeriodBlocks;
    uint256 public timelockDelaySeconds;
    uint256 public proposalThresholdBps; // bps of total votes required to propose
    uint256 public quorumBps; // bps of total votes required for validity
    uint256 public maxActions;
    uint256 public maxCalldataBytes;

    struct Action {
        address target;
        uint256 value;
        bytes data;
    }

    struct Proposal {
        address author;
        bytes32 topic;
        uint64 voteStart;
        uint64 voteEnd;
        uint64 eta;
        bool queued;
        bool executed;
        bool canceled;
