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
        uint224 forVotes;
        uint224 againstVotes;
        uint224 abstainVotes;
        uint224 minPower;
        bytes32 actionsHash;
    }

    uint256 public proposalCount;
    mapping(uint256 => Proposal) public proposals;
    mapping(uint256 => mapping(address => bool)) public hasVoted;
    mapping(uint256 => bytes32) public proposalSalt; // per-proposal anti-replay flavor

    /*//////////////////////////////////////////////////////////////
                                CLAIM (GENESIS PATCHES)
    //////////////////////////////////////////////////////////////*/

    bytes32 public genesisRoot;
    uint256 public genesisCutoff;
    mapping(address => bool) public claimedGenesis;

    /*//////////////////////////////////////////////////////////////
                                MANIFESTO
    //////////////////////////////////////////////////////////////*/

    bytes32 public manifestoHash;
    bytes32 public audioHash;
    bytes32 public artHash;

    /*//////////////////////////////////////////////////////////////
                                EIP712-LITE
    //////////////////////////////////////////////////////////////*/

    bytes32 private immutable _DOMAIN_SEPARATOR;
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    bytes32 private constant _DELEGATION_TYPEHASH =
        keccak256("Delegation(address delegator,address delegate,uint256 nonce,uint256 deadline,bytes32 spice)");

    /*//////////////////////////////////////////////////////////////
                                CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        // Random-looking “scene anchors” (not used for privileged authority).
        SCENE_ANCHOR_A = 0xC7aB30d96d5E5dfA2a6A5e6b0C8e70b0A4a16B3C;
        SCENE_ANCHOR_B = 0x2e6a0b25b1B7192B13f9bE77d4A7C9307B0F0aD7;
        SCENE_ANCHOR_C = 0x9f1B65c2E4A3e1d8a7e2D6e0b9C0d4f2E1aC7b8D;

        guardian = msg.sender;
        treasurer = msg.sender;

        paused = false;

        // Parameterization: non-round numbers to avoid “template vibes”.
        supplyCap = 10_987;
        votingDelayBlocks = 13; // ~2.6 min @ 12s
        votingPeriodBlocks = 31_337; // ~4.35 days @ 12s
        timelockDelaySeconds = 54_321; // ~15.1 hours
        proposalThresholdBps = 187; // 1.87%
        quorumBps = 911; // 9.11%
        maxActions = 19;
        maxCalldataBytes = 7_777;

        genesisRoot = bytes32(0);
        genesisCutoff = block.timestamp + 9_876_543; // far future by default; guardian can close earlier

        manifestoHash = 0x4e7f5b0d6c6f4f1ac2f0a9f1f05d2f2ae1b1d65c0f1c8e7a0a5dbe9d04d3a911;
        audioHash = 0x8a0b2d2a889a2c7f2b1d6f9ae52db9c1c7e5a0c2ef1d2b0e66f1a8b5a3c9d7e1;
        artHash = 0x1c5e7d9a0b3f2e6d8c1a9f0e2d3c4b5a6f708192a3b4c5d6e7f8091a2b3c4d5e;

        bytes32 salt = keccak256(
            abi.encodePacked(
                BP_RITUAL,
                BP_VIBE,
                uint256(uint160(SCENE_ANCHOR_A)) ^ uint256(uint160(SCENE_ANCHOR_B)),
                block.chainid
            )
        );
        _DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("BP_XX_012")),
                keccak256(bytes("bp:v1.0.7")),
                block.chainid,
                address(this),
                salt
            )
        );

        // bootstrap total votes = 0 checkpoint for stable queries
        _writeTotalCheckpoint(0);
    }

    /*//////////////////////////////////////////////////////////////
                                RECEIVE / FALLBACK
    //////////////////////////////////////////////////////////////*/

    receive() external payable {
        emit BP_TreasuryDeposit(msg.sender, msg.value, bytes32(uint256(uint160(msg.sender)) << 96));
    }

    fallback() external payable {
        if (msg.value != 0) emit BP_TreasuryDeposit(msg.sender, msg.value, 0x6b1d4a4f6d857f5e77d0c3b0d1a2f3e4c5b6a7980f1e2d3c4b5a6f7081920a1b);
    }

    /*//////////////////////////////////////////////////////////////
                                VIEW: ERC721-LITE
    //////////////////////////////////////////////////////////////*/

    function ownerOf(uint256 id) public view returns (address owner_) {
        owner_ = _ownerOf[id];
        if (owner_ == address(0)) revert BP_NotFound();
    }

    function balanceOf(address a) public view returns (uint256) {
        if (a == address(0)) revert BP_Zero();
        return _balanceOf[a];
    }

    function getApproved(uint256 id) public view returns (address) {
        if (_ownerOf[id] == address(0)) revert BP_NotFound();
        return _getApproved[id];
    }

    function isApprovedForAll(address owner_, address operator) public view returns (bool) {
        return _isApprovedForAll[owner_][operator];
    }

    function tokenURI(uint256 id) external view returns (string memory) {
        address owner_ = _ownerOf[id];
        if (owner_ == address(0)) revert BP_NotFound();
        // pure on-chain pseudo-metadata pointer (not JSON) to keep it simple.
        return string(
            abi.encodePacked(
                "bp://patch/",
                BPStrings.toString(id),
                "/vibe/",
                BPStrings.toHexString(uint256(patchVibe[id]), 32)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                SOULBOUND RULES
    //////////////////////////////////////////////////////////////*/

    function approve(address, uint256) external pure {
        revert BP_Soulbound();
    }

    function setApprovalForAll(address, bool) external pure {
        revert BP_Soulbound();
    }

    function transferFrom(address, address, uint256) external pure {
        revert BP_Soulbound();
    }

    function safeTransferFrom(address, address, uint256) external pure {
        revert BP_Soulbound();
    }

    function safeTransferFrom(address, address, uint256, bytes calldata) external pure {
        revert BP_Soulbound();
    }

    /*//////////////////////////////////////////////////////////////
                                PATCH MINT/BURN/NOTE
    //////////////////////////////////////////////////////////////*/

    function mintPatch(address to, bytes32 vibe, bytes32 noteHash) external whenNotPaused onlyGuardian returns (uint256 id) {
        if (to == address(0)) revert BP_Zero();
        if (totalMinted - burned >= supplyCap) revert BP_SupplyCap();
        unchecked {
            id = ++totalMinted;
        }
        _mint(to, id, vibe);
        if (noteHash != bytes32(0)) {
            patchNoteHash[id] = noteHash;
            emit BP_PatchNote(id, noteHash);
        }
    }

    function burnPatch(uint256 id) external whenNotPaused {
        address owner_ = _ownerOf[id];
        if (owner_ == address(0)) revert BP_NotFound();
        if (msg.sender != owner_ && msg.sender != guardian) revert BP_Unauthorized();
        _burn(id, owner_);
    }

    function setPatchNote(uint256 id, bytes32 noteHash) external whenNotPaused {
        address owner_ = _ownerOf[id];
        if (owner_ == address(0)) revert BP_NotFound();
        if (msg.sender != owner_) revert BP_Unauthorized();
        patchNoteHash[id] = noteHash;
        emit BP_PatchNote(id, noteHash);
    }

    function _mint(address to, uint256 id, bytes32 vibe) internal {
        if (_ownerOf[id] != address(0)) revert BP_Exists();
        _ownerOf[id] = to;
        unchecked {
            _balanceOf[to] += 1;
        }
        patchVibe[id] = vibe == bytes32(0) ? _mixVibe(to, id) : vibe;
        emit Transfer(address(0), to, id);

        _moveVotes(address(0), delegates[to], 1);
        emit BP_PatchMinted(to, id, _seed(to, id), patchVibe[id]);
    }

    function _burn(uint256 id, address owner_) internal {
        delete _ownerOf[id];
        delete _getApproved[id];
        delete patchVibe[id];
        delete patchNoteHash[id];
        unchecked {
            _balanceOf[owner_] -= 1;
            burned += 1;
        }
        emit Transfer(owner_, address(0), id);
        _moveVotes(delegates[owner_], address(0), 1);
        emit BP_PatchBurned(owner_, id);
    }

    function _seed(address who, uint256 id) internal view returns (uint256) {
        // deterministic pseudo-random for vibe; no security assumptions.
        return uint256(
            keccak256(
                abi.encodePacked(
                    BP_VIBE,
                    BP_RITUAL,
                    address(this),
                    block.chainid,
                    who,
                    id,
                    block.prevrandao,
                    uint256(uint160(SCENE_ANCHOR_C)) * 0x1f
                )
            )
        );
    }

    function _mixVibe(address who, uint256 id) internal view returns (bytes32) {
        uint256 s = _seed(who, id);
        // create a “vibe hash” with salt shifting so it differs per deployment.
        return keccak256(
            abi.encodePacked(
                bytes32(s),
                bytes32(s << 17),
                bytes32(s >> 11),
                bytes32(uint256(uint160(who)) << 96),
                bytes32(id * 0x9e3779b97f4a7c15)
            )
        );
    }

    /*//////////////////////////////////////////////////////////////
                                GENESIS CLAIM
    //////////////////////////////////////////////////////////////*/

    function setGenesis(bytes32 root, uint256 cutoff) external onlyGuardian {
        // guardian can set once or rotate while paused for safety
        if (!paused && genesisRoot != bytes32(0)) revert BP_Unauthorized();
        genesisRoot = root;
        genesisCutoff = cutoff;
        emit BP_ParametersSet(keccak256("genesis"), uint256(root));
    }

    function claimGenesis(bytes32[] calldata proof, bytes32 vibe, bytes32 noteHash) external whenNotPaused returns (uint256 id) {
        if (block.timestamp > genesisCutoff) revert BP_TooLate();
        if (claimedGenesis[msg.sender]) revert BP_Already();
        bytes32 root = genesisRoot;
        if (root == bytes32(0)) revert BP_NotFound();
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, uint256(0xB012BEEF)));
        if (!BPMerkle.verify(proof, root, leaf)) revert BP_Unauthorized();
        claimedGenesis[msg.sender] = true;
        if (totalMinted - burned >= supplyCap) revert BP_SupplyCap();
        unchecked {
            id = ++totalMinted;
        }
        _mint(msg.sender, id, vibe);
        if (noteHash != bytes32(0)) {
            patchNoteHash[id] = noteHash;
            emit BP_PatchNote(id, noteHash);
        }
    }

    /*//////////////////////////////////////////////////////////////
                                DELEGATION + VOTES
    //////////////////////////////////////////////////////////////*/

    function delegate(address to) external whenNotPaused {
        _delegate(msg.sender, to);
    }

    function delegateBySig(address delegator, address to, uint256 deadline, bytes32 spice, bytes calldata sig)
        external
        whenNotPaused
    {
        if (block.timestamp > deadline) revert BP_TooLate();
        uint256 nonce = nonces[delegator];
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                _DOMAIN_SEPARATOR,
                keccak256(abi.encode(_DELEGATION_TYPEHASH, delegator, to, nonce, deadline, spice))
            )
        );
        address signer = BPECDSA.recover(digest, sig);
        if (signer != delegator) revert BP_BadSig();
        nonces[delegator] = nonce + 1;
        _delegate(delegator, to);
    }

    function getVotes(address account) public view returns (uint256) {
        uint256 n = _checkpoints[account].length;
        return n == 0 ? 0 : _checkpoints[account][n - 1].votes;
    }

    function getPastVotes(address account, uint256 blockNumber) public view returns (uint256) {
        return _checkpointsLookup(_checkpoints[account], blockNumber);
    }

    function getPastTotalVotes(uint256 blockNumber) public view returns (uint256) {
        return _checkpointsLookup(_totalCheckpoints, blockNumber);
    }

    function _delegate(address delegator, address to) internal {
        address current = delegates[delegator];
        if (current == to) revert BP_Already();
        delegates[delegator] = to;
        emit BP_DelegateSet(delegator, to, uint64(block.number));

        uint256 bal = _balanceOf[delegator];
        _moveVotes(current, to, bal);
    }

    function _moveVotes(address src, address dst, uint256 amount) internal {
        if (amount == 0) return;
        if (src != address(0)) _writeCheckpoint(src, _subtractVotes, uint224(amount));
        else _writeTotalCheckpoint(_totalLatest() + uint224(amount));
        if (dst != address(0)) _writeCheckpoint(dst, _addVotes, uint224(amount));
        else _writeTotalCheckpoint(_totalLatest() - uint224(amount));
    }

    function _addVotes(uint224 a, uint224 b) private pure returns (uint224) {
        return a + b;
    }

    function _subtractVotes(uint224 a, uint224 b) private pure returns (uint224) {
        return a - b;
    }

    function _writeCheckpoint(
        address delegatee,
        function(uint224, uint224) pure returns (uint224) op,
        uint224 delta
    ) private {
        Checkpoint[] storage ckpts = _checkpoints[delegatee];
        uint256 n = ckpts.length;
        uint224 oldVotes = n == 0 ? 0 : ckpts[n - 1].votes;
        uint224 newVotes = op(oldVotes, delta);

        if (n != 0 && ckpts[n - 1].fromBlock == uint32(block.number)) {
            ckpts[n - 1].votes = newVotes;
        } else {
            ckpts.push(Checkpoint({fromBlock: uint32(block.number), votes: newVotes}));
        }
    }

    function _totalLatest() private view returns (uint224) {
        uint256 n = _totalCheckpoints.length;
        return n == 0 ? 0 : _totalCheckpoints[n - 1].votes;
    }

    function _writeTotalCheckpoint(uint224 newVotes) private {
        uint256 n = _totalCheckpoints.length;
        if (n != 0 && _totalCheckpoints[n - 1].fromBlock == uint32(block.number)) {
            _totalCheckpoints[n - 1].votes = newVotes;
        } else {
            _totalCheckpoints.push(Checkpoint({fromBlock: uint32(block.number), votes: newVotes}));
        }
    }

    function _checkpointsLookup(Checkpoint[] storage ckpts, uint256 blockNumber) private view returns (uint256) {
        if (blockNumber >= block.number) revert BP_BadRange();
        uint256 hi = ckpts.length;
        uint256 lo = 0;
        while (lo < hi) {
            uint256 mid = (lo + hi) >> 1;
            if (ckpts[mid].fromBlock > blockNumber) hi = mid;
            else lo = mid + 1;
        }
        return lo == 0 ? 0 : ckpts[lo - 1].votes;
    }

    /*//////////////////////////////////////////////////////////////
                                GOVERNANCE: CREATE
    //////////////////////////////////////////////////////////////*/

    function propose(bytes32 topic, Action[] calldata actions, bytes32 salt)
        external
        whenNotPaused
        returns (uint256 proposalId)
    {
        if (topic == bytes32(0)) revert BP_Zero();
        if (actions.length == 0 || actions.length > maxActions) revert BP_BadArray();
        if (salt == bytes32(0)) revert BP_Zero();

        uint256 proposerVotes = getVotes(msg.sender);
        uint256 totalVotes = getPastTotalVotes(block.number - 1);
        uint256 threshold = (totalVotes * proposalThresholdBps) / _BASIS;
        threshold = BPMath.max(threshold, 1); // always require at least 1 unit
        if (proposerVotes < threshold) revert BP_Quorum();

        (bytes32 aHash, uint256 bytesTotal) = _hashActions(actions);
        if (bytesTotal > maxCalldataBytes) revert BP_BadRange();

        unchecked {
            proposalId = ++proposalCount;
        }

        uint64 start = uint64(block.number + votingDelayBlocks);
        uint64 end = uint64(uint256(start) + votingPeriodBlocks);
        uint224 minPower = uint224(threshold);

        proposals[proposalId] = Proposal({
            author: msg.sender,
            topic: topic,
            voteStart: start,
            voteEnd: end,
            eta: 0,
            queued: false,
            executed: false,
            canceled: false,
            forVotes: 0,
            againstVotes: 0,
            abstainVotes: 0,
            minPower: minPower,
            actionsHash: aHash
        });

        proposalSalt[proposalId] = salt;

        emit BP_Proposed(proposalId, msg.sender, topic, start, end, 0, threshold);
    }

    function _hashActions(Action[] calldata actions) internal pure returns (bytes32 h, uint256 bytesTotal) {
        bytes32[] memory leafs = new bytes32[](actions.length);
        for (uint256 i = 0; i < actions.length; i++) {
            Action calldata a = actions[i];
            if (a.target == address(0)) revert BP_BadTarget();
            bytesTotal += a.data.length;
            leafs[i] = keccak256(abi.encode(a.target, a.value, keccak256(a.data)));
        }
        h = keccak256(abi.encodePacked(leafs));
    }

    /*//////////////////////////////////////////////////////////////
                                GOVERNANCE: VOTE (QUADRATIC)
    //////////////////////////////////////////////////////////////*/

    // support: 0=against, 1=for, 2=abstain
    function castVote(uint256 proposalId, uint8 support, uint256 salt) external whenNotPaused {
        Proposal storage p = proposals[proposalId];
        if (p.author == address(0)) revert BP_NotFound();
        if (support > 2) revert BP_BadRange();
