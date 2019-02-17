/*    
Copyright 2019 to the Miximus Authors

This file is part of Miximus.

Miximus is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Miximus is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Miximus.  If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity ^0.5.0;

import "../../ethsnarks/contracts/Verifier.sol";
import "../../ethsnarks/contracts/MerkleTree.sol";
import "../../ethsnarks/contracts/MiMC.sol";


contract Miximus
{
    using MerkleTree for MerkleTree.Data;

    // Denomination of each token
    uint constant public AMOUNT = 1 ether;

    // Stores the nullifiers for every spent coin (preventing double spend)
    mapping (uint256 => bool) public nullifiers;

    // Stores all of the valid merkle tree roots
    mapping (uint256 => bool) public roots;

    MerkleTree.Data internal tree;


    /**
    * Used to be notified that a specific leaf has been deposited
    */
    event OnDeposit( uint256 leaf_hash, uint256 leaf_index );


    /**
    * Used to quickly lookup if a coin has been spent
    */
    event OnWithdraw( uint256 nullifier );


    /**
    * What is the current root for the merkle tree
    */
    function GetRoot()
        public view returns (uint256)
    {
        return tree.GetRoot();
    }


    /**
    * Returns leaf offset
    */
    function Deposit(uint256 leaf)
        public payable returns (uint256 new_root, uint256 new_offset)
    {
        require( msg.value == AMOUNT, "Must deposit exact amount" );

        (new_root, new_offset) = tree.Insert(leaf);

        roots[new_root] = true;

        emit OnDeposit(leaf, new_offset);
    }


    function MakeLeafHash(uint256 secret)
        public pure returns (uint256)
    {
        uint256[] memory vals = new uint256[](1);
        vals[0] = secret;
        return MiMC.Hash(vals);
    }


    /**
    * Retrieve the merkle tree path for a specific leaf
    * TODO: remove `out_addr` - it's unnecessary, given we know the leaf index
    */
    function GetPath(uint256 in_leaf_index)
        public view returns (uint256[29] memory out_path, bool[29] memory out_addr)
    {
        return tree.GetProof(in_leaf_index);
    }


    function GetExtHash()
        public view returns (uint256)
    {
        return uint256(sha256(
            abi.encodePacked(
                address(this),
                msg.sender
            ))) % Verifier.ScalarField();
    }


    function IsSpent(uint256 nullifier)
        public view returns (bool)
    {
        return nullifiers[nullifier];
    }


    /**
    * Condense multiple public inputs down to a single one to be provided to the zkSNARK circuit
    */
    function HashPublicInputs(
        uint256 in_root,
        uint256 in_nullifier,
        uint256 in_exthash
    )
        public pure returns (uint256)
    {
        uint256[] memory inputs_to_hash = new uint256[](3);

        inputs_to_hash[0] = in_root;
        inputs_to_hash[1] = in_nullifier;
        inputs_to_hash[2] = in_exthash;

        return MiMC.Hash(inputs_to_hash);
    }


    function VerifyProof(
        uint256 in_root,
        uint256 in_nullifier,
        uint256 in_exthash,
        uint256[8] memory proof
    )
        public view returns (bool)
    {
        // Public inputs for the zkSNARK circuit are hashed into a single input
        uint256[] memory snark_input = new uint256[](1);
        snark_input[0] = HashPublicInputs(in_root, in_nullifier, in_exthash);

        // Retrieve verifying key
        uint256[14] memory vk;
        uint256[] memory vk_gammaABC;
        (vk, vk_gammaABC) = GetVerifyingKey();

        // Validate the proof
        return Verifier.Verify( vk, vk_gammaABC, proof, snark_input );
    }


    /**
    * Withdraw a token from the mixer
    */
    function Withdraw(
        uint256 in_root,
        uint256 in_nullifier,
        uint256[8] memory in_proof
    )
        public
    {
        require( false == nullifiers[in_nullifier], "Cannot double-spend" );

        require( true == roots[in_root], "Must specify known merkle tree root" );

        bool is_valid = VerifyProof(in_root, in_nullifier, GetExtHash(), in_proof);

        require( is_valid, "Proof invalid!" );

        nullifiers[in_nullifier] = true;

        msg.sender.transfer(AMOUNT);

        emit OnWithdraw(in_nullifier);
    }


    /**
    * Contracts which inherit this one must implement a mechanism to retrieve the verification key
    *
    * It is up to the implementor to figure out how to do this, but it could be hard-coded or
    * passed in via the constructor.
    *
    * See `TestableMiximus` as an example, which loads the verification key from storage.
    */
    function GetVerifyingKey ()
        public view returns (uint256[14] memory out_vk, uint256[] memory out_gammaABC);
}
