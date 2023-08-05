
module aes_wrap #(
parameter DATA_W = 128,      //data width
parameter KEY_L = 128,       //key length
parameter NO_ROUNDS = 10     //number of rounds
)(
input clk,                       //system clock
input reset_n,                     //asynch reset_n
input flush,

input data_valid_in,             //data valid signal
input cipherkey_valid_in,        //cipher key valid signal
input [KEY_L-1:0] cipher_key,    //cipher key
input [DATA_W-1:0] plain_text,   //plain text
output valid_out,                //output valid signal
output [DATA_W-1:0] cipher_text,  //cipher text

input data_valid_in2,             //data valid signal
input cipherkey_valid_in2,        //cipher key valid signal
input [KEY_L-1:0] cipher_key2,    //cipher key
input [DATA_W-1:0] plain_text2,   //plain text
output valid_out2,                //output valid signal
output [DATA_W-1:0] cipher_text2  //cipher text
);

Top_PipelinedCipher #(
    .DATA_W         ( DATA_W             ),
    .KEY_L          ( KEY_L     ),
    .NO_ROUNDS      ( NO_ROUNDS )
)aes_top
( 
    .clk(clk),
    .reset(reset_n),
    .data_valid_in(data_valid_in),
    .cipherkey_valid_in(cipherkey_valid_in),
    .cipher_key(cipher_key),
    .plain_text(plain_text),
    .valid_out(valid_out),
    .cipher_text(cipher_text)
);

Top_PipelinedCipher #(
    .DATA_W         ( DATA_W             ),
    .KEY_L          ( KEY_L     ),
    .NO_ROUNDS      ( NO_ROUNDS )
)aes_top2
(
    .clk(clk),
    .reset(reset_n),
    .data_valid_in(data_valid_in2),
    .cipherkey_valid_in(cipherkey_valid_in2),
    .cipher_key(cipher_key2),
    .plain_text(plain_text2),
    .valid_out(valid_out2),
    .cipher_text(cipher_text2)
    );

endmodule