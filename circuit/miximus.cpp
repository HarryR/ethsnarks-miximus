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

#include "miximus.hpp"
#include "export.hpp"
#include "import.hpp"
#include "stubs.hpp"
#include "utils.hpp"

#include "gadgets/mimc.hpp"
#include "gadgets/merkle_tree.cpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>


#include <nlohmann/json.hpp>
using json = nlohmann::json;


using libsnark::dual_variable_gadget;
using ethsnarks::ppT;
using ethsnarks::FieldT;
using ethsnarks::ProtoboardT;

const size_t MIXIMUS_TREE_DEPTH = 29;


namespace ethsnarks {


/**
* This class implements the following circuit:
*
* def circuit(secret, path_var, address_bits, nullifier, root, external_hash, pub_hash):
*   assert H(root, nullifier, external_hash) == pub_hash
*   leaf_hash = H(secret) # Prove we know the secret for the leaf
*   assert root == merkle_authenticate(path_var, address_bits, leaf_hash) # Prove that leaf exists within the tree
*   assert H(secret, address_bits) == nullifier
*
* The following statements must be true for privacy of both the depositor and the withdrawee:
*
*  1. The depositor must not know when the coin has been withdrawn
*  2. The withdrawee must know when it has been deposited (this is necessary, but decreases privacy)
*  3. The withdrawee must be assured that only they can withdraw the coin
*  4. No observer should be able to link deposit and withdraw
*  5. Neither the observer or depositor should be able to prevent the withdrawee from withdrawing the deposit
*
* The input parameters are:
*
*  - `secret` (private) proves ownership of the coin
*  - `path_var` (private): merkle authentication path array
*  - `address_bits` (private): leaf offset (in bits, little-endian)
*  - `nullifier` (hashed-public): double-spend uniqueness tag
*  - `root` (hashed-public): merkle root to authenticate against
*  - `external_hash` (hashed-public): used to bind the proof to contract-controlled parameters
*  - `pub_hash` (public): Used to reduce the number of public inputs
*
* It is cheaper to hash multiple public inputs into a single variable because the cost of hashing data on-chain
* is less than each public input. Each hashed input costs 20k gas, whereas every public SNARK input costs 40k gas.
*
* The depositor and withdrawee can be separate roles, e.g. I can deposit a coin that only you can withdraw
* When they are separate roles the process for deposit/withdraw works as follows:
*
*  1. Recipient (withdrawee) generates a random secret
*  2. Recipient hashes that secret, provides the hash to the depositor (sender)
*  3. Sender makes the deposit using the hashed secret as the leaf
*  4. Recipient verifies the deposit for their leaf
*  5. Recipient withdraws deposit using their secret with a zkSNARK proof
* 
*/
class mod_miximus : public GadgetT
{
public:
    typedef MiMC_hash_gadget HashT;
    const size_t tree_depth = MIXIMUS_TREE_DEPTH;

    // public inputs
    const VariableT pub_hash_var;

    // hashed public inputs
    const VariableT root_var;
    const VariableT external_hash_var;

    // public constants
    const VariableArrayT m_IVs;

    // constant inputs
    const VariableT zero;

    // private inputs
    const VariableT secret_var;
    dual_variable_gadget<FieldT> address_bits;
    const VariableArrayT path_var;

    // logic gadgets
    HashT nullifier_hash;
    HashT pub_hash;
    HashT leaf_hash;
    merkle_path_authenticator<HashT> m_authenticator;

    mod_miximus(
        ProtoboardT &in_pb,
        const std::string &annotation_prefix
    ) :
        GadgetT(in_pb, annotation_prefix),

        // public inputs
        pub_hash_var(make_variable(in_pb, FMT(annotation_prefix, ".pub_hash_var"))),

        // hashed public inputs
        root_var(make_variable(in_pb, FMT(annotation_prefix, ".root_var"))),
        external_hash_var(make_variable(in_pb, FMT(annotation_prefix, ".external_hash_var"))),

        // Initialisation vector for merkle tree hard-coded constants
        // Means that H('a', 'b') on level1 will have a different output than the same values on level2
        m_IVs(merkle_tree_IVs(in_pb)),

        // constant zero, used as IV for hash functions
        zero(make_variable(in_pb, FMT(annotation_prefix, ".zero"))),

        // private inputs
        secret_var(make_variable(in_pb, FMT(annotation_prefix, ".secret_var"))),
        address_bits(in_pb, tree_depth, FMT(annotation_prefix, ".address_bits")),
        path_var(make_var_array(in_pb, tree_depth, FMT(annotation_prefix, ".path"))),

        // nullifier = H(address_bits, secret)
        nullifier_hash(in_pb, zero, {address_bits.packed, secret_var}, FMT(annotation_prefix, ".nullifier_hash")),

        // pub_hash = H(root, nullifier, external_hash)
        pub_hash(in_pb, zero, {root_var, nullifier_hash.result(), external_hash_var}, FMT(annotation_prefix, ".pub_hash")),

        // leaf_hash = H(secret)
        leaf_hash(in_pb, zero, {secret_var}, FMT(annotation_prefix, ".leaf_hash")),

        // assert merkle_path_authenticate(leaf_hash, path, root)
        m_authenticator(in_pb, tree_depth, address_bits.bits, m_IVs, leaf_hash.result(), root_var, path_var, FMT(annotation_prefix, ".authenticator"))
    {
        // Only one public input variable is passed, which is `pub_hash`
        // The actual values are provided as private inputs
        in_pb.set_input_sizes( 1 );

        // The 3 hashed public variables are:
        // - root_var (provided by user, authenticated by contract, merkle root of the tree)
        // - nullifier_var (provided by user, this is the unique tag, used to prevent double spends)
        // - external_hash_var  (provided by contract)
    }

    void generate_r1cs_constraints()
    {
        nullifier_hash.generate_r1cs_constraints();
        address_bits.generate_r1cs_constraints(true);

        // Ensure privately provided public inputs match the hashed input
        pub_hash.generate_r1cs_constraints();
        this->pb.add_r1cs_constraint(
            ConstraintT(pub_hash_var, FieldT::one(), pub_hash.result()),
            ".pub_hash_var == H(root, nullifier, external_hash)");

        // Enforce zero internally
        this->pb.add_r1cs_constraint(
            ConstraintT(zero, zero, zero - zero),
            "0 * 0 == 0 - 0 ... zero is zero!");

        leaf_hash.generate_r1cs_constraints();
        m_authenticator.generate_r1cs_constraints();
    }

    void generate_r1cs_witness(
        const FieldT in_root,         // merkle tree root
        const FieldT in_exthash,      // hash of external parameters
        const FieldT in_secret,     // spend secret
        const libff::bit_vector in_address,
        const std::vector<FieldT> &in_path
    ) {
        // hashed public inputs
        this->pb.val(root_var) = in_root;
        this->pb.val(external_hash_var) = in_exthash;

        // private inputs
        this->pb.val(secret_var) = in_secret;
        address_bits.bits.fill_with_bits(this->pb, in_address);
        address_bits.generate_r1cs_witness_from_bits();

        nullifier_hash.generate_r1cs_witness();

        // public hash
        this->pb.val(pub_hash_var) = mimc_hash({in_root, this->pb.val(nullifier_hash.result()), in_exthash});
        pub_hash.generate_r1cs_witness();

        for( size_t i = 0; i < tree_depth; i++ )
        {
            this->pb.val(path_var[i]) = in_path[i];
        }

        leaf_hash.generate_r1cs_witness();
        m_authenticator.generate_r1cs_witness();
    }
};

// namespace ethsnarks
}


size_t miximus_tree_depth( void ) {
    return MIXIMUS_TREE_DEPTH;
}


char* miximus_nullifier( const char *in_secret, const char *in_leaf_index )
{
    ppT::init_public_params();

    const FieldT arg_secret(in_secret);
    const FieldT arg_index(in_leaf_index);
    const FieldT arg_result(ethsnarks::mimc_hash({arg_index, arg_secret}));

    // Convert result to mpz
    const auto result_bigint = arg_result.as_bigint();
    mpz_t result_mpz;
    mpz_init(result_mpz);
    result_bigint.to_mpz(result_mpz);

    // Convert to string
    char *result_str = mpz_get_str(nullptr, 10, result_mpz);
    assert( result_str != nullptr );
    mpz_clear(result_mpz);

    return result_str;
}


static char *miximus_prove_internal(
    const char *pk_file,
    const FieldT arg_root,
    const FieldT arg_exthash,
    const FieldT arg_secret,
    const libff::bit_vector address_bits,
    const std::vector<FieldT> arg_path
)
{
    // Create protoboard with gadget
    ProtoboardT pb;
    ethsnarks::mod_miximus mod(pb, "miximus");
    mod.generate_r1cs_constraints();
    mod.generate_r1cs_witness(arg_root, arg_exthash, arg_secret, address_bits, arg_path);

    if( ! pb.is_satisfied() )
    {
        std::cerr << "Not Satisfied!" << std::endl;
        return nullptr;
    }

    std::cerr << pb.num_constraints() << " constraints" << std::endl;

    // Return proof as a JSON document, which must be destroyed by the caller
    const auto proof_as_json = ethsnarks::stub_prove_from_pb(pb, pk_file);
    return ::strdup(proof_as_json.c_str());
}


char *miximus_prove_json( const char *pk_file, const char *in_json )
{
    ppT::init_public_params();

    const auto root = json::parse(in_json);
    const auto arg_root = ethsnarks::parse_FieldT(root.at("root"));
    const auto arg_secret = ethsnarks::parse_FieldT(root.at("secret")); 
    const auto arg_exthash = ethsnarks::parse_FieldT(root.at("exthash"));

    const auto arg_path = ethsnarks::create_F_list(root.at("path"));
    if( arg_path.size() != MIXIMUS_TREE_DEPTH )
    {
        std::cerr << "Path length doesn't match tree depth" << std::endl;
        return nullptr;
    }

    // Fill address bits from integer
    unsigned long address = root.at("address").get<decltype(address)>();
    assert( (sizeof(address) * 8) >= MIXIMUS_TREE_DEPTH );
    libff::bit_vector address_bits;
    address_bits.resize(MIXIMUS_TREE_DEPTH);
    for( size_t i = 0; i < MIXIMUS_TREE_DEPTH; i++ )
    {
        address_bits[i] = (address & (1u<<i)) != 0;
    }

    return miximus_prove_internal(pk_file, arg_root, arg_exthash, arg_secret, address_bits, arg_path);
}


char *miximus_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_exthash,
    const char *in_secret,
    const char *in_address,
    const char **in_path
) {
    ppT::init_public_params();

    const FieldT arg_root(in_root);
    const FieldT arg_exthash(in_exthash);
    const FieldT arg_secret(in_secret);

    // Fill address bits with 0s and 1s from str
    // XXX: populate bits from integer (offset of the leaf in the merkle tree)
    //      parse integer from string, rather than passing as unsigned?
    libff::bit_vector address_bits;
    address_bits.resize(MIXIMUS_TREE_DEPTH);
    if( strlen(in_address) != MIXIMUS_TREE_DEPTH )
    {
        std::cerr << "Address length doesnt match depth" << std::endl;
        return nullptr;
    }
    for( size_t i = 0; i < MIXIMUS_TREE_DEPTH; i++ )
    {
        if( in_address[i] != '0' && in_address[i] != '1' ) {
            std::cerr << "Address bit " << i << " invalid, unknown: " << in_address[i] << std::endl;
            return nullptr;
        }
        address_bits[i] = '0' - in_address[i];
    }

    // Fill path from field elements from in_path
    std::vector<FieldT> arg_path;
    arg_path.resize(MIXIMUS_TREE_DEPTH);
    for( size_t i = 0; i < MIXIMUS_TREE_DEPTH; i++ ) {
        assert( in_path[i] != nullptr );
        arg_path[i] = FieldT(in_path[i]);
    }

    return miximus_prove_internal(pk_file, arg_root, arg_exthash, arg_secret, address_bits, arg_path);
}


int miximus_genkeys( const char *pk_file, const char *vk_file )
{
    return ethsnarks::stub_genkeys<ethsnarks::mod_miximus>(pk_file, vk_file);
}


bool miximus_verify( const char *vk_json, const char *proof_json )
{
    return ethsnarks::stub_verify( vk_json, proof_json );
}
