//==================================================================================================
//  Filename      : aes_top_wrapper.v
//  Created On    : 2021-04-12
//  Revision      :
//  Author        : August Ning, Yajun Zhu
//  Company       : Princeton University
//  Email         : aning@princeton.edu
//
//  Description   : Wrapper for AES module that to allow it to accept commands from dcp
//
//==================================================================================================

`define AES_DATA_WIDTH_BITS 128
`define MSG_DATA_SIZE_WIDTH 3

// `ifdef DEFAULT_NETTYPE_NONE
// `default_nettype none
// `endif

// `define AES_WRITE_KEY_HIGH_ADDR
// `define AES_WRITE_KEY_LOW_ADDR
// `define AES_WRITE_PLAIN_HIGH_ADDR
// `define AES_WRITE_PLAIN_LOW_ADDR
// `define AES_READ_CIPHER_ADDR

// `define AES_READ_CIPHER_HIGH_ADDR
// `define AES_READ_CIPHER_LOW_ADDR

module aes_top_wrapper (
    input  wire clk,
    input  wire rst_n,

    input  wire                             config_hsk,     // When handshake is high, address is valid
    input  wire [15:0]                      config_addr,    // noc1decoder_dcp_address, address will correspond with instruction
    input  wire [31:0]                      config_data_hi, // noc1decoder_dcp_data
    input  wire [31:0]                      config_data_lo,
    input  wire                             config_load,    // It is a Load if high (a read ciphertext), if low it's a store (write to plaintext or key reg?)
    // input  wire [`MSG_DATA_SIZE_WIDTH-1:0]  config_size,    // what does this do?

    output wire                             aes_out_valid,
    output wire [63:0]                      aes_out_data  
);

    localparam AES_WRITE_KEY_HIGH_ADDR      = 16'h0010;
    localparam AES_WRITE_KEY_LOW_ADDR       = 16'h0020;
    localparam AES_WRITE_PLAIN_HIGH_ADDR    = 16'h0030;
    localparam AES_WRITE_PLAIN_LOW_ADDR     = 16'h0040;
    localparam AES_READ_CIPHER_HIGH_ADDR    = 16'h0050;
    localparam AES_READ_CIPHER_LOW_ADDR     = 16'h0060;

    reg [`AES_DATA_WIDTH_BITS-1:0] aes_key_data_reg;
    reg [`AES_DATA_WIDTH_BITS-1:0] aes_plaintext_data_reg;
    reg [`AES_DATA_WIDTH_BITS-1:0] aes_ciphertext_data_reg;

    reg aes_inputs_valid_reg;
    // reg aes_plaintext_valid_reg;
    // reg aes_ciphertext_valid_reg;

    // not too sure if we need to regs for the outputs, but maybe useful
    wire aes_ciphertext_valid;
    wire [`AES_DATA_WIDTH_BITS-1:0] aes_ciphertext_data;

    always @(posedge clk) begin
        if ( !rst_n ) begin
            aes_key_data_reg        <= 128'b0;
            aes_plaintext_data_reg  <= 128'b0;
            aes_ciphertext_data_reg <= 128'h11110000111100002222000022220000;

            aes_inputs_valid_reg    <= 1'b0;
        end
        else if ( config_hsk && ( config_addr == AES_WRITE_KEY_HIGH_ADDR ) ) begin
            aes_key_data_reg[127:96]    <= config_data_hi;
            aes_key_data_reg[95:64]     <= config_data_lo;  
        end
        else if ( config_hsk && ( config_addr == AES_WRITE_KEY_LOW_ADDR ) ) begin
            aes_key_data_reg[63:32]    <= config_data_hi;
            aes_key_data_reg[31:0]     <= config_data_lo;  
        end
        else if ( config_hsk && ( config_addr == AES_WRITE_PLAIN_HIGH_ADDR ) ) begin
            aes_plaintext_data_reg[127:96]    <= config_data_hi;
            aes_plaintext_data_reg[95:64]     <= config_data_lo;  
        end
        else if ( config_hsk && ( config_addr == AES_WRITE_PLAIN_LOW_ADDR ) ) begin
            aes_plaintext_data_reg[63:32]    <= config_data_hi;
            aes_plaintext_data_reg[31:0]     <= config_data_lo;
            aes_inputs_valid_reg             <= 1'b1;
        end

        if ( aes_inputs_valid_reg ) begin
            aes_inputs_valid_reg <= 1'b0;
        end

        if ( aes_ciphertext_valid ) begin
            aes_ciphertext_data_reg <= aes_ciphertext_data;
        end
    end

    assign aes_out_data = ( config_addr == AES_READ_CIPHER_HIGH_ADDR ) ? 
                            aes_ciphertext_data_reg[127:64] : aes_ciphertext_data_reg[63:0] ;
    assign aes_out_valid = config_hsk && config_load;

    // WIP

    Top_PipelinedCipher aes_top
    ( 
        .clk(clk),
        .reset(rst_n),
        .data_valid_in(aes_inputs_valid_reg),
        .cipherkey_valid_in(aes_inputs_valid_reg),
        .cipher_key(aes_key_data_reg),
        .plain_text(aes_plaintext_data_reg),
        .valid_out(aes_ciphertext_valid),
        .cipher_text(aes_ciphertext_data)
    );

endmodule