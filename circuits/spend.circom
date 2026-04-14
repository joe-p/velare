pragma circom 2.1.5;

include "./utxo.circom";
include "./node_modules/circomlib/circuits/bitify.circom";
include "./node_modules/circomlib/circuits/comparators.circom";

template SumU64(N) {
    signal input amounts[N];
    signal output sum;

    component amount_bits[N] ;
    signal sums[N];
    component sum_bits[N - 1];
    
    amount_bits[0] = Num2Bits(64);
    amount_bits[0].in <== amounts[0];
    sums[0] <== amounts[0];

    for (var i = 1; i < N; i++) {
        amount_bits[i] = Num2Bits(64);
        amount_bits[i].in <== amounts[i];

        sums[i] <== sums[i-1] + amounts[i];

        sum_bits[i - 1] = Num2Bits(64);
        sum_bits[i - 1].in <== sums[i];
    }

    sum <== sums[N-1];
}

template Spend(IN, OUT) {
    //////////////////////////////////////////////
    // Public outputs
    //////////////////////////////////////////////
    signal output inputs[IN];
    signal output outputs[OUT];

    //////////////////////////////////////////////
    // Public inputs
    //////////////////////////////////////////////
    signal input spender;
    signal input asset;
    
    signal input receivers[OUT];

    //////////////////////////////////////////////
    // Private inputs
    //////////////////////////////////////////////
    signal input in_amounts[IN];
    signal input in_secrets[IN];

    signal input out_amounts[OUT];
    signal input out_secrets[OUT];

    //////////////////////////////////////////////
    // Verify total in == total out
    //////////////////////////////////////////////
    component in_sum = SumU64(IN);
    for (var i = 0; i < IN; i++) {
        in_sum.amounts[i] <== in_amounts[i];
    }

    component out_sum = SumU64(OUT);
    for (var i = 0; i < OUT; i++) {
        out_sum.amounts[i] <== out_amounts[i];
    }

    in_sum.sum === out_sum.sum;

    //////////////////////////////////////////////
    // Output input and output UTXOs
    //////////////////////////////////////////////
    component in_utxo[IN];

    for (var i = 0; i < IN; i++) {
        in_utxo[i] = UTXO();
        in_utxo[i].spender <== spender;
        in_utxo[i].asset <== asset;
        in_utxo[i].amount <== in_amounts[i];
        in_utxo[i].blinding_secret <== in_secrets[i];
        inputs[i] <== in_utxo[i].commitment;    
    }

    component out_utxo[OUT];

    for (var i = 0; i < OUT; i++) {
        out_utxo[i] = UTXO();
        out_utxo[i].spender <== receivers[i];
        out_utxo[i].asset <== asset;
        out_utxo[i].amount <== out_amounts[i];
        out_utxo[i].blinding_secret <== out_secrets[i];
        outputs[i] <== out_utxo[i].commitment;
    }
}

component main {public [spender, asset, receivers]}  = Spend(2, 2);

