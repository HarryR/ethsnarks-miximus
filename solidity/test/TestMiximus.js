const TestableMiximus = artifacts.require("TestableMiximus");

const crypto = require("crypto");

const fs = require("fs");
const ffi = require("ffi");
const ref = require("ref");
const ArrayType = require("ref-array");
const BN = require("bn.js");

var StringArray = ArrayType(ref.types.CString);

const MiximusVerifyingKeyPath = "../.keys/miximus.vk.json";
const MiximusProvingKeyPath = "../.keys/miximus.pk.raw";

var libmiximus = ffi.Library("../.build/libmiximus", {
    // Retrieve depth of tree
    "miximus_tree_depth": [
        "size_t", []
    ],

    // Create a proof for the parameters
    "miximus_prove": [
        "string", [
            "string",       // pk_file
            "string",       // in_root
            "string",       // in_exthash
            "string",       // in_spend_preimage
            "string",       // in_address
            StringArray,    // in_path
        ]
    ],

    // Create a proof for the parameters (encoded as json)
    "miximus_prove_json": [
        "string", [
            "string",       // pk_file
            "string",       // args_json
        ]
    ],

    // Verify a proof
    "miximus_verify": [
        "bool", [
            "string",   // vk_json
            "string",   // proof_json
        ]
    ],

    // Create nullifier
    "miximus_nullifier": [
        "string", [
            "string",   // secret (base 10 number)
            "string",   // leaf_index (base 10 number)
        ]
    ]
});



let list_flatten = (l) => {
    return [].concat.apply([], l);
};


let vk_to_flat = (vk) => {
    return [
        list_flatten([
            vk.alpha[0], vk.alpha[1],
            list_flatten(vk.beta),
            list_flatten(vk.gamma),
            list_flatten(vk.delta),
        ]),
        list_flatten(vk.gammaABC)
    ];
};


let proof_to_flat = (proof) => {
    return list_flatten([
        proof.A,
        list_flatten(proof.B),
        proof.C
    ]);
};


contract("TestableMiximus", () => {
    describe("Deposit", () => {
        let obj;
        let secret;
        let leaf_hash;
        let proof_root;
        let nullifier;
        let proof;
        let new_root_and_offset;

        it("gets ready for deposit", async () => {
            obj = await TestableMiximus.deployed();

            // Parameters for deposit
            secret = new BN(crypto.randomBytes(30).toString("hex"), 16);
            leaf_hash = await obj.MakeLeafHash.call(secret);

            // Perform deposit
            new_root_and_offset = await obj.Deposit.call(leaf_hash, {value: 1000000000000000000});
        });

        it("deposits", async () => {
            await obj.Deposit.sendTransaction(leaf_hash, {value: 1000000000000000000});
        });

        it("construct arguments for withdraw", async () => {
            // TODO: verify amount has been transferred
            // Build parameters for proving
            let tmp = await obj.GetPath.call(new_root_and_offset[1]);
            let proof_address = tmp[1].map((_) => _ ? "1" : "0").join("");
            let proof_path = [];
            for( var i = 0; i < proof_address.length; i++ ) {
                proof_path.push( "0x" + tmp[0][i].toString(16) );
            }
            proof_root = await obj.GetRoot.call();
            // TODO: verify proof root equals expected one
            proof_root = new_root_and_offset[0];
            let leaf_index = new_root_and_offset[1];
            let proof_exthash = await obj.GetExtHash.call();

            // Calcuate our nullifier, so we can verify the proof matches what is expected
            nullifier = libmiximus.miximus_nullifier(secret.toString(10), leaf_index.toString(10));
            let proof_pub_hash = await obj.HashPublicInputs.call(proof_root, nullifier, proof_exthash);

            // Run prover to generate proof
            let proof_address_int = proof_address.split("").map((v, i) => (parseInt(v) ? Math.pow(2, i) : 0)).reduce(function(a, b) { return a + b; }, 0);
            let json_args = {
                'root': "0x" + proof_root.toString(16),
                'exthash': "0x" + proof_exthash.toString(16),
                'secret': "0x" + secret.toString(16),
                'address': proof_address_int,
                'path': proof_path,
            };
            let proof_json = libmiximus.miximus_prove_json(MiximusProvingKeyPath, JSON.stringify(json_args));

            // There *must* be JSON returned, containing the valid proof
            assert.notStrictEqual(proof_json, null);
            proof = JSON.parse(proof_json);

            // Ensure proof inputs match what is expected
            assert.strictEqual("0x" + proof_pub_hash.toString(16), proof.input[0]);

            // Re-verify proof using native library
            // XXX: node-ffi on OSX will not null-terminate strings returned from `readFileSync` !
            let vk_json = fs.readFileSync(MiximusVerifyingKeyPath);
            let proof_valid_native = libmiximus.miximus_verify(vk_json + '\0', proof_json);
            assert.strictEqual(proof_valid_native, true);
            let vk = JSON.parse(vk_json);


            // Verify VK and Proof together
            let [vk_flat, vk_flat_IC] = vk_to_flat(vk);
            let test_verify_args = [
                vk_flat,                // (alpha, beta, gamma, delta)
                vk_flat_IC,             // gammaABC[]
                proof_to_flat(proof),   // A B C
                [  
                    proof.input[0]
                ]
            ];
            let test_verify_result = await obj.TestVerify(...test_verify_args);
            assert.strictEqual(test_verify_result, true);


            // Verify whether or not our proof would be valid
            let proof_valid = await obj.VerifyProof.call(
                proof_root,
                nullifier,
                proof_exthash,
                proof_to_flat(proof));
            assert.strictEqual(proof_valid, true);


            // Verify nullifier doesn't exist
            let is_spent_b4_withdraw = await obj.IsSpent(nullifier.toString(10));
            assert.strictEqual(is_spent_b4_withdraw, false);
        });

        it("withdraws", async () => {
            // Then perform the withdraw
            await obj.Withdraw(
                proof_root.toString(10),
                nullifier.toString(10),
                proof_to_flat(proof));
        });

        it("nullifier exists after withdraw", async () => {
            // Verify nullifier exists
            let is_spent = await obj.IsSpent(nullifier.toString(10));
            assert.strictEqual(is_spent, true);
            // TODO: verify balance has been increased
        });
    });
});
