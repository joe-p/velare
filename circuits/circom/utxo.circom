pragma circom 2.1.5;

include "./mimc.circom";

template UTXO() {
    signal input spender;
    signal input asset;
    signal input amount;
    signal input blinding_secret;

    signal output commitment;

    component H = MiMC_Sum(4);
    H.msgs[0] <== spender;
    H.msgs[1] <== asset;
    H.msgs[2] <== amount;
    H.msgs[3] <== blinding_secret;
    commitment <== H.out;
}
