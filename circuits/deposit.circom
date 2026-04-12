pragma circom 2.1.5;

include "./mimc.circom";

template Deposit(N) {
    //////////////////////////////////////////////
    // Public outputs
    ///////////////////////////////////////////// 
    signal output commitment;

    //////////////////////////////////////////////
    // Public inputs
    //////////////////////////////////////////////
    signal input addr;
    signal input asset;
    signal input amount;

    //////////////////////////////////////////////
    // Private inputs
    //////////////////////////////////////////////
    signal input secret;
   
    component H = MiMC_Sum(4);
    H.msgs[0] <== addr;
    H.msgs[1] <== asset;
    H.msgs[2] <== amount;
    H.msgs[3] <== secret;
    commitment <== H.out;

}

component main {public [addr, asset, amount]}  = Deposit(1);
