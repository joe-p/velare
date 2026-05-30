pragma circom 2.1.5;

include "./spend.circom";
include "./mimc.circom";

// Wrapper around Spend(IN, OUT) that exposes a single public signal:
// a MiMC hash of every public signal of the underlying Spend circuit.
//
// All of Spend's inputs (public and private) become private inputs here.
// The hashed signals, in the same order Spend exposes them publicly, are:
//   inputs[IN], outputs[OUT], spender, asset, receivers[OUT]
template SpendHashed(IN, OUT) {
    //////////////////////////////////////////////
    // Single public output
    //////////////////////////////////////////////
    signal output hash;

    //////////////////////////////////////////////
    // Inputs (all private to this wrapper)
    //////////////////////////////////////////////
    signal input spender;
    signal input asset;
    signal input receivers[OUT];

    signal input in_amounts[IN];
    signal input in_secrets[IN];

    signal input out_amounts[OUT];
    signal input out_secrets[OUT];

    //////////////////////////////////////////////
    // Run the Spend circuit
    //////////////////////////////////////////////
    component spend = Spend(IN, OUT);
    spend.spender <== spender;
    spend.asset <== asset;

    for (var i = 0; i < OUT; i++) {
        spend.receivers[i] <== receivers[i];
    }
    for (var i = 0; i < IN; i++) {
        spend.in_amounts[i] <== in_amounts[i];
        spend.in_secrets[i] <== in_secrets[i];
    }
    for (var i = 0; i < OUT; i++) {
        spend.out_amounts[i] <== out_amounts[i];
        spend.out_secrets[i] <== out_secrets[i];
    }

    //////////////////////////////////////////////
    // Hash all public signals into one
    //////////////////////////////////////////////
    var N = IN + OUT + 2 + OUT;
    component H = MiMC_Sum(N);

    var idx = 0;
    for (var i = 0; i < IN; i++) {
        H.msgs[idx] <== spend.inputs[i];
        idx++;
    }
    for (var i = 0; i < OUT; i++) {
        H.msgs[idx] <== spend.outputs[i];
        idx++;
    }
    H.msgs[idx] <== spender;
    idx++;
    H.msgs[idx] <== asset;
    idx++;
    for (var i = 0; i < OUT; i++) {
        H.msgs[idx] <== receivers[i];
        idx++;
    }

    hash <== H.out;
}
