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

#ifndef MIXIMUS_HPP_
#define MIXIMUS_HPP_

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

const extern size_t MIXIMUS_TREE_DEPTH;

/**
* Prover inputs is a JSON dictionary with the following structure:
* {
*    "root": "0x..",     // Merkle root
*    "exthash": "0x...", // Hash of external arguments 
*    "secret": "0x...",  // Secret for the leaf
*    "address": 1234,    // Index of the leaf, or address of the leaf in the tree
*    "path": ["0x...", "0x...", ...] // Merkle tree authentication path
* }
*
* Returns proof as JSON string
*/
char *miximus_prove_json( const char *pk_file, const char *in_json );


char *miximus_prove(
    const char *pk_file,
    const char *in_root,
    const char *in_exthash,
    const char *in_secret,
    const char *in_address,
    const char **in_path
);

int miximus_genkeys( const char *pk_file, const char *vk_file );

bool miximus_verify( const char *vk_json, const char *proof_json );

char* miximus_nullifier( const char *in_secret, const char *in_leaf_index );

size_t miximus_tree_depth( void );

#ifdef __cplusplus
} // extern "C" {
#endif

#endif
