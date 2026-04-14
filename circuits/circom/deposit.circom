pragma circom 2.1.5;

include "./utxo.circom";
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";

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

template Deposit(OUT) {
    //////////////////////////////////////////////
    // Public outputs
    //////////////////////////////////////////////
    signal output in_amount;
    signal output outputs[OUT];
    
    //////////////////////////////////////////////
    // Public inputs
    //////////////////////////////////////////////
    signal input asset;
    
    signal input receivers[OUT];

    //////////////////////////////////////////////
    // Private inputs
    //////////////////////////////////////////////
    signal input out_amounts[OUT];
    signal input out_secrets[OUT];

    //////////////////////////////////////////////
    // Set in_amount = sum(out_amounts)
    //////////////////////////////////////////////
    component out_sum = SumU64(OUT);
    for (var i = 0; i < OUT; i++) {
        out_sum.amounts[i] <== out_amounts[i];
    }

    in_amount <== out_sum.sum;

    //////////////////////////////////////////////
    // Output input and output UTXOs
    //////////////////////////////////////////////
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

component main {public [asset, receivers]}  = Deposit(1);

