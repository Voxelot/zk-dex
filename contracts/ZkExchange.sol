//ZK-Exchange handles all ZK verification, note and order state management, token escrowing
pragma solidity ^0.5.0;

import "./interfaces/IERC20.sol";
import {Verifier as MintVerifier} from "./verifiers/CreateNoteVerifier.sol";
import {Verifier as SpendVerifier} from "./verifiers/SpendNoteVerifier.sol";
import {Verifier as ClaimVerifier} from "./verifiers/ClaimNoteVerifier.sol";
import {Verifier as CreateOrderVerifier} from "./verifiers/CreateOrderVerifier.sol";
import {Verifier as FillOrderVerifier} from "./verifiers/FillOrderVerifier.sol";

contract ZkExchange is MintVerifier, SpendVerifier, ClaimVerifier, CreateOrderVerifier, FillOrderVerifier {

    enum NoteState {
        INVALID,
        MINTED,
        SPENT,
        EXCHANGABLE,
        PENDING
    }

    struct Note {
        uint256 timeCreated;
        NoteState state;
        // clients are responsible for storing private note fields, (e.g encrypted on IPFS)
    }

    enum OrderState {
        INVALID,
        CREATED,
        FILLED,
        VOIDED
    }

    struct Order {
        uint256 timeCreated;
        bytes32 makerNote; // pre-exchange note
        bytes32 makerFillNote; // post-exchange note
        OrderState state;
    }

    event Mint(bytes32 noteHash);
    event Exchangeable(bytes32 noteHash);
    event Spend(bytes32 noteHash);
    event Claim(bytes32 noteHash, address token, uint256 value);
    event CreateOrder(bytes32 orderHash, bytes32 makerNoteHash, bytes32 makerFillNoteHash);
    event FillOrder(bytes32 orderHash, bytes32 takerFillNoteHash, bytes32 makerFillNoteHash);

    mapping (bytes32 => Note) notes;
    mapping (bytes32 => Order) orders;

    function createOrder(
        // snark params
        uint256[2] calldata a,
        uint256[2] calldata a_p,
        uint256[2][2] calldata b,
        uint256[2] calldata b_p,
        uint256[2] calldata c,
        uint256[2] calldata c_p,
        uint256[2] calldata h,
        uint256[2] calldata k,
        //orderHash0, orderHash1, noteHash0, noteHash1, fillNoteHash0, fillNoteHash1, output
        uint256[7] calldata publicParams
    )
    external
    {
        bytes32 orderHash = calcHash(publicParams[0], publicParams[1]);
        bytes32 noteHash = calcHash(publicParams[2], publicParams[3]);
        bytes32 fillNoteHash = calcHash(publicParams[4], publicParams[5]);

        require(
            notes[noteHash].state == NoteState.MINTED,
            "Invalid maker note"
        );

        require(
            notes[fillNoteHash].timeCreated == 0,
            "Duplicate maker fill note exists"
        );
        
        require(
            orders[orderHash].timeCreated == 0,
            "Invalid or duplicate order"
        );

        require(
            CreateOrderVerifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, publicParams),
            "Invalid create order proof"
        );
        
        notes[noteHash].state = NoteState.EXCHANGABLE;
        notes[fillNoteHash] = Note(now, NoteState.PENDING);
        orders[orderHash] = Order(now, noteHash, fillNoteHash, OrderState.CREATED);

        emit CreateOrder(orderHash, noteHash, fillNoteHash);
        emit Exchangeable(noteHash);
    }

    function fillOrder(
        // snark params
        uint256[2] calldata a,
        uint256[2] calldata a_p,
        uint256[2][2] calldata b,
        uint256[2] calldata b_p,
        uint256[2] calldata c,
        uint256[2] calldata c_p,
        uint256[2] calldata h,
        uint256[2] calldata k,
        //orderHash0, orderHash1, noteHash0, noteHash1, fillNoteHash0, fillNoteHash1, output
        uint256[7] calldata publicParams
    )
    external
    {
        bytes32 orderHash = calcHash(publicParams[0], publicParams[1]);
        bytes32 takerNoteHash = calcHash(publicParams[2], publicParams[3]);
        bytes32 takerFillNoteHash = calcHash(publicParams[4], publicParams[5]);
        bytes32 makerNoteHash = orders[orderHash].makerNote;
        bytes32 makerFillNoteHash = orders[orderHash].makerFillNote;

        require(
            orders[orderHash].state == OrderState.CREATED,
            "Invalid order"
        );
        orders[orderHash].state = OrderState.FILLED;
        
        // ensure maker note is exchangable
        require(
            notes[makerNoteHash].state == NoteState.EXCHANGABLE,
            "Maker note invalid"
        );

        // ensure maker fill note is pending
        require(
            notes[makerFillNoteHash].state == NoteState.PENDING,
            "Maker fill note invalid"
        );

        // ensure taker note is spendable
        require(
            notes[takerNoteHash].state == NoteState.MINTED,
            "Invalid taker note"
        );

        // ensure taker fill note is not already in use
        require(
            notes[takerFillNoteHash].timeCreated == 0,
            "Taker fill note is already minted or invalid"
        );

        // verify proof
        require(
            FillOrderVerifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, publicParams),
            "Invalid fill order proof"
        );

        // spend maker and taker notes
        notes[makerNoteHash].state = NoteState.SPENT;
        notes[takerNoteHash].state = NoteState.SPENT;
        // activate pending maker fill note
        notes[makerFillNoteHash].state = NoteState.MINTED;
        // mint taker fill note
        notes[takerFillNoteHash] = Note(now, NoteState.MINTED);
        // log order filled, order notes spent, and fill notes minted
        emit FillOrder(orderHash, takerFillNoteHash, makerFillNoteHash);
        emit Spend(makerNoteHash);
        emit Spend(takerNoteHash);
        emit Mint(takerFillNoteHash);
        emit Mint(makerFillNoteHash);
    }

    function mintNote(
        // snark params
        uint256[2] calldata a,
        uint256[2] calldata a_p,
        uint256[2][2] calldata b,
        uint256[2] calldata b_p,
        uint256[2] calldata c,
        uint256[2] calldata c_p,
        uint256[2] calldata h,
        uint256[2] calldata k,
        //notehash0, notehash1, tokenaddr, value, output
        uint256[5] calldata publicParams
    )
    external
    {
        bytes32 noteHash = calcHash(publicParams[0], publicParams[1]);
        address token = address(publicParams[2]);
        uint256 value = uint256(publicParams[3]);

        // ensure note uniqueness
        require(notes[noteHash].timeCreated == 0, "Note already minted");

        // add note to registry
        notes[noteHash] = Note(now, NoteState.MINTED);

        // transfer tokens
        require(
            ERC20(token).transferFrom(msg.sender, address(this), value),
            "Token transfer failed"
        );
        require(
            MintVerifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, publicParams),
            "Invalid mint proof"
        );
        emit Mint(noteHash);
    }

    function spendNote(
        // snark params
        uint256[2] calldata a,
        uint256[2] calldata a_p,
        uint256[2][2] calldata b,
        uint256[2] calldata b_p,
        uint256[2] calldata c,
        uint256[2] calldata c_p,
        uint256[2] calldata h,
        uint256[2] calldata k,
        //originalHash0, originalHash1, note0h0, note0h1, note1h0, note1h1, output
        uint256[7] calldata publicParams
    )
    external
    {
        bytes32[3] memory noteRefs = get3Notes(publicParams);
        require(notes[noteRefs[0]].state == NoteState.MINTED, "Note is either invalid or already spent");
        require(notes[noteRefs[1]].state == NoteState.INVALID, "output note1 is already minted");
        require(notes[noteRefs[2]].state == NoteState.INVALID, "output note2 is already minted");

        require(
            SpendVerifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, publicParams),
            "Invalid spend proof"
        );

        notes[noteRefs[0]].state = NoteState.SPENT;
        notes[noteRefs[1]] = Note(now, NoteState.MINTED);
        notes[noteRefs[2]] = Note(now, NoteState.MINTED);
        emit Spend(noteRefs[0]);
        emit Mint(noteRefs[1]);
        emit Mint(noteRefs[2]);
    }

    /**
     * @dev consume note and transfer tokens to claimant
     */
    function claimNote(
        address to,
        // snark params
        uint256[2] calldata a,
        uint256[2] calldata a_p,
        uint256[2][2] calldata b,
        uint256[2] calldata b_p,
        uint256[2] calldata c,
        uint256[2] calldata c_p,
        uint256[2] calldata h,
        uint256[2] calldata k,
        //notehash0, notehash1, tokenaddr, value, output
        uint256[5] calldata publicParams
    )
    external
    {
        bytes32 noteHash = calcHash(publicParams[0], publicParams[1]);
        address token = address(publicParams[2]);
        uint256 value = uint256(publicParams[3]);

        // ensure note is minted and unspent
        require(notes[noteHash].state == NoteState.MINTED, "Note already spent");
        
        // mark note as spent
        notes[noteHash].state == NoteState.SPENT;

        require(
            ERC20(token).transferFrom( address(this), to, value),
            "Token transfer failed"
        );
        require(
            ClaimVerifier.verifyTx(a, a_p, b, b_p, c, c_p, h, k, publicParams),
            "Invalid claim proof"
        );
    }

    function get3Notes(uint256[7] memory input)
    internal
    pure
    returns(bytes32[3] memory _notes)
    {
        _notes[0] = calcHash(input[0], input[1]);
        _notes[1] = calcHash(input[2], input[3]);
        _notes[2] = calcHash(input[4], input[5]);
    }

    /**
     * @dev Concatenates the 2 chunks of the sha256 hash of the note
     * @notice This method is required due to the field limitations imposed by the zokrates zkSnark library
     * @param _a Most significant 128 bits of the note hash
     * @param _b Least significant 128 bits of the note hash
    */
    function calcHash(uint256 _a, uint256 _b)
    internal
    pure
    returns(bytes32 noteHash)
    {
        uint256 combinedHash = _a * (2 ** 16) + _b;
        noteHash = bytes32(combinedHash);
    }
}