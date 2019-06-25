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

#include <iostream> // cerr
#include <fstream>  // ifstream,ofstream

#include "miximus.cpp"
#include "stubs.hpp"
#include "utils.hpp" // hex_to_bytes


using std::cerr;
using std::cout;
using std::endl;
using std::ofstream;

using ethsnarks::stub_main_genkeys;
using ethsnarks::stub_main_verify;
using ethsnarks::mod_miximus;


static int main_prove( int argc, char **argv )
{
    if( argc < (9 + (int)MIXIMUS_TREE_DEPTH) )
    {
        cerr << "Usage: " << argv[0] << " prove <pk.raw> <proof.json> <public:root> <public:nullifier> <public:exthash> <secret:secret> <secret:merkle-address> <secret:merkle-path ...>" << endl;
        cerr << "Args: " << endl;
        cerr << "\t<pk.raw>         Path to proving key" << endl;
        cerr << "\t<proof.json>     Write proof to this file" << endl;
        cerr << "\t<root>           Merkle tree root" << endl;
        cerr << "\t<exthash>        Hash of external variables" << endl;
        cerr << "\t<secret>         Spend secret" << endl;
        cerr << "\t<merkle-address> 0 and 1 bits for tree path" << endl;
        cerr << "\t<merkle-path...> items for merkle tree path" << endl;
        return 1;
    }

    auto pk_filename = argv[2];
    auto proof_filename = argv[3];
    auto arg_root = argv[4];
    auto arg_exthash = argv[5];
    auto arg_secret = argv[6];
    auto arg_address = argv[7];
    
    const char *arg_path[MIXIMUS_TREE_DEPTH];
    for( size_t i = 0; i < MIXIMUS_TREE_DEPTH; i++ ) {
        arg_path[i] = argv[9 + i];
    }

    auto proof_json = miximus_prove(pk_filename, arg_root, arg_exthash, arg_secret, arg_address, arg_path);
    if( proof_json == nullptr ) {
        std::cerr << "Failed to prove\n";
        return 1;
    }

    ofstream fh;
    fh.open(proof_filename, std::ios::binary);
    fh << proof_json;
    fh.flush();
    fh.close();

    return 0;
}


void read_all_file (const std::string &filename, std::string &out) {
    std::ifstream fh(filename, std::ios::binary);

    fh.seekg(0, std::ios::end);   
    out.reserve(fh.tellg());
    fh.seekg(0, std::ios::beg);

    out.assign((std::istreambuf_iterator<char>(fh)),
                std::istreambuf_iterator<char>());
}


void read_all_stdin (std::string &out) {
    // don't skip the whitespace while reading
    std::cin >> std::noskipws;
    // use stream iterators to copy the stream to a string
    std::istream_iterator<char> it(std::cin);
    std::istream_iterator<char> end;
    out.assign(it, end);
}


static int main_prove_json( int argc, char **argv )
{
    if( argc < 3 ) {
        std::cerr << "Usage: " << argv[0] << " prove_json <proving.key> [-|input.json] [-|proof.json]\n";
        return 1;
    }    

    const std::string input_file((argc > 3) ? argv[3] : "-");
    const std::string output_file((argc > 4) ? argv[4] : "-");

    std::string json_buf;
    if( input_file == "-" ) {
        read_all_stdin(json_buf);
    }
    else {
        read_all_file(input_file, json_buf);
    }

    auto pk_filename = argv[2];
    auto proof_json = miximus_prove_json(pk_filename, json_buf.c_str());
    if( proof_json == nullptr ) {
        std::cerr << "Failed to prove\n";
        return 2;
    }

    // output to stdout by default
    if( output_file == "-" ) {
        std::cout << proof_json;
        return 0;
    }

    // Otherwise output to specific file
    ofstream fh;
    fh.open(output_file, std::ios::binary);
    fh << proof_json;
    fh.flush();
    fh.close();

    std::cerr << "OK\n";

    return 0;
}


int main( int argc, char **argv )
{
    if( argc < 2 )
    {
        cerr << "Usage: " << argv[0] << " <genkeys|prove|prove_json|verify> [...]" << endl;
        return 1;
    }

    const std::string arg_cmd(argv[1]);

    if( arg_cmd == "prove" )
    {
        return main_prove(argc, argv);
    }
    else if( arg_cmd == "prove_json" )
    {
        return main_prove_json(argc, argv);
    }
    else if( arg_cmd == "genkeys" )
    {
        return stub_main_genkeys<mod_miximus>(argv[0], argc-1, &argv[1]);
    }
    else if( arg_cmd == "verify" )
    {
        return stub_main_verify(argv[0], argc-1, (const char **)&argv[1]);
    }

    cerr << "Error: unknown sub-command " << arg_cmd << endl;
    return 2;
}
