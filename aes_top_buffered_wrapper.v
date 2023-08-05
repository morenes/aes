//==================================================================================================
//  Filename      : aes_top_buffered_wrapper.v
//  Created On    : 2021-04-12
//  Revision      :
//  Author        : August Ning, Yajun Zhu
//  Company       : Princeton University
//  Email         : aning@princeton.edu
//
//  Description   : Wrapper for AES module that to allow it to accept commands from dcp
//                  The buffer helps with pipelining
//
//==================================================================================================

`define AES_DATA_WIDTH_BITS             128
`define CIPHERTEXT_OUTPUT_BUFFER_SIZE   16
module aes_top_buffered_wrapper (
    input  wire clk,
    input  wire rst_n,

    input  wire                             config_hsk,     // When handshake is high, address is valid
    input  wire [15:0]                      config_addr,    // noc1decoder_dcp_address, address will correspond with instruction
    input  wire [31:0]                      config_data_hi, // noc1decoder_dcp_data
    input  wire [31:0]                      config_data_lo,
    input  wire                             config_load,    // It is a Load if high (a read ciphertext), if low it's a store (write to plaintext or key reg?)

    output wire                             aes_out_valid,
    output wire [63:0]                      aes_out_data  
);
    
    // instructions corresond to inputs you'll get from config_addr
    localparam AES_WRITE_KEY_HIGH_ADDR      = 16'h0010;
    localparam AES_WRITE_KEY_LOW_ADDR       = 16'h0020;
    localparam AES_WRITE_PLAIN_HIGH_ADDR    = 16'h0030;
    localparam AES_WRITE_PLAIN_LOW_ADDR     = 16'h0040;
    localparam AES_READ_CIPHER_HIGH_ADDR    = 16'h0050;
    localparam AES_READ_CIPHER_LOW_ADDR     = 16'h0060;

    reg [`AES_DATA_WIDTH_BITS-1:0]  aes_key_data_reg;
    reg [`AES_DATA_WIDTH_BITS-1:0]  aes_plaintext_data_reg;
    reg                             aes_inputs_valid_reg;

    // make ciphertext output write to a circular buffer
    // wires are used as outputs from AES module
    reg [`AES_DATA_WIDTH_BITS-1:0]  aes_ciphertext_data_reg  [15:0];
    wire [`AES_DATA_WIDTH_BITS-1:0] aes_ciphertext_data;
    reg                             aes_ciphertext_valid_reg [15:0];
    wire                            aes_ciphertext_valid;

    // regs used to keep track of circular buffer
    reg [3:0] aes_ciphertext_data_reg_head;
    reg [3:0] aes_ciphertext_data_reg_tail;
    reg [3:0] aes_ciphertext_data_reg_curr;

    // this genvar loop is used for creating the control logic for the output buffer 
    genvar k;
    generate
        for (k = 0; k < `CIPHERTEXT_OUTPUT_BUFFER_SIZE; k = k + 1) begin
            always @( posedge clk ) begin 
                if (! rst_n ) begin
                    aes_ciphertext_data_reg[k]  <= 128'hAAAA_AAAA_AAAA_AAAA_BBBB_BBBB_BBBB_BBBB;
                    aes_ciphertext_valid_reg[k] <= 1'b0;
                end
                else begin
                    // when the write plaintext low command is received, allocate a valid spot
                    // at the tail of the ciphertext buffer
                    if ( config_hsk && ( config_addr == AES_WRITE_PLAIN_LOW_ADDR ) && 
                        ( !aes_ciphertext_valid_reg[aes_ciphertext_data_reg_tail] ) && 
                        ( k == aes_ciphertext_data_reg_tail ) ) begin
                        aes_ciphertext_valid_reg[k]     <= 1'b1;
                        aes_ciphertext_data_reg_tail    <= aes_ciphertext_data_reg_tail + 1'b1;
                    end
                    // the curr reg keeps track of where to write the output of the aes module
                    // output of the aes module is only valid if the curr index is valid
                    if ( aes_ciphertext_valid && ( aes_ciphertext_valid_reg[aes_ciphertext_data_reg_curr] ) && 
                        ( k == aes_ciphertext_data_reg_curr ) ) begin
                        aes_ciphertext_data_reg[k]      <= aes_ciphertext_data;
                        aes_ciphertext_data_reg_curr    <= aes_ciphertext_data_reg_curr + 1'b1;
                    end
                    // head register is where the output from aes read instructions should return from
                    // after the encryption result has been consumed, free it for the next encryption
                    if ( aes_out_valid && ( config_addr == AES_READ_CIPHER_LOW_ADDR ) && 
                        ( aes_ciphertext_valid_reg[aes_ciphertext_data_reg_head] ) &&
                        ( k == aes_ciphertext_data_reg_head ) ) begin
                        aes_ciphertext_valid_reg[k]     <= 1'b0;
                        aes_ciphertext_data_reg_head    <= aes_ciphertext_data_reg_head + 1'b1;
                    end
                end
            end
        end
    endgenerate

    // alway block used for populating aes key and plaintext registers
    // accepts valid instructions and will update the corresponding registers
    always @(posedge clk) begin
        if ( !rst_n ) begin
            aes_key_data_reg        <= 128'b0;
            aes_plaintext_data_reg  <= 128'b0;

            aes_inputs_valid_reg    <= 1'b0;
            aes_ciphertext_data_reg_head <= 4'b0;
            aes_ciphertext_data_reg_tail <= 4'b0;
            aes_ciphertext_data_reg_curr <= 4'b0;
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
        // when the plaintext lower bits are written, that signals the module to start
        // encrypting. it's up to the programmer to use this correctly
        else if ( config_hsk && ( config_addr == AES_WRITE_PLAIN_LOW_ADDR ) && 
                ( !aes_ciphertext_valid_reg[aes_ciphertext_data_reg_tail] ) ) begin
            aes_plaintext_data_reg[63:32]    <= config_data_hi;
            aes_plaintext_data_reg[31:0]     <= config_data_lo;
            aes_inputs_valid_reg             <= 1'b1;
        end

        if ( aes_inputs_valid_reg ) begin
            aes_inputs_valid_reg <= 1'b0;
        end
    end

    // assign the output. the lowerbit -1 indexing has to do with the circular buffer's logic
    assign aes_out_data = ( config_addr == AES_READ_CIPHER_HIGH_ADDR ) ? 
                            aes_ciphertext_data_reg[aes_ciphertext_data_reg_head][127:64] : 
                            aes_ciphertext_data_reg[aes_ciphertext_data_reg_head - 4'b1][63:0] ;
    assign aes_out_valid = config_hsk && config_load;

    // pipelined aes module from open cores. module is plug and play, and designer only
    // has to implement the control signals and how to pass data to the module
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
