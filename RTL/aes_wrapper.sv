module aes_wrapper (
    input  logic        clk,
    input  logic       reset_n,
    
    // Streaming input
    input  logic        in_valid,
    output logic        in_ready,
    input  logic [255:0] key,
    input  logic [127:0] data_in,
    input  logic        encdec,
    input  logic        keylen,
    
    // Streaming output
    output logic         out_valid,
    output logic  [127:0] data_out
);

    // Internal AES register bus
    logic [7:0]  addr;
    logic [31:0] wdata;
    logic [31:0] rdata;
    logic cs;
    logic we;
    
    // FSM states
    localparam IDLE        = 4'd0;
    localparam LOAD_CONFIG = 4'd1;
    localparam LOAD_KEY    = 4'd2;
    localparam LOAD_BLOCK  = 4'd3;
    localparam START       = 4'd4;
    localparam WAIT_DONE   = 4'd5;
    localparam READ_RESULT = 4'd6;
    
    logic [3:0] state;
    logic [3:0] word_cnt;
    
    logic [255:0] key_reg;
    logic [127:0] block_reg;
    
    assign in_ready = (state == IDLE);
    
    always @(posedge clk or negedge reset_n) begin
        if (!reset_n) begin
            state      <= IDLE;
            cs         <= 0;
            we         <= 0;
            addr       <= 0;
            wdata      <= 0;
            word_cnt   <= 0;
            key_reg    <= 0;
            block_reg  <= 0;
            out_valid  <= 0;
            data_out   <= 0;
        end else begin            
            cs        <= 0;
            we        <= 0;
            out_valid <= 0;
            
            case (state)
                
                IDLE: begin
                    if (in_valid) begin
                        key_reg   <= key;
                        block_reg <= data_in;
                        state     <= LOAD_CONFIG;
                    end
                end
                
                LOAD_CONFIG: begin
                    cs    <= 1;
                    we    <= 1;
                    addr  <= 8'h0A;
                    wdata <= {30'b0, keylen, encdec};
                    word_cnt <= 0;
                    state <= LOAD_KEY;
                end
                
                LOAD_KEY: begin
                    cs   <= 1;
                    we   <= 1;
                    addr <= 8'h10 + word_cnt;
                    wdata <= key_reg[255 - 32*word_cnt -: 32];
                    
                    word_cnt <= word_cnt + 1;
                    
                    if (word_cnt == 7)
                        state <= LOAD_BLOCK;
                end
                
                LOAD_BLOCK: begin
                    cs   <= 1;
                    we   <= 1;
                    addr <= 8'h20 + word_cnt[1:0];
                    wdata <= block_reg[127 - 32*word_cnt -: 32];
                    
                    word_cnt <= word_cnt + 1;
                    
                    if (word_cnt == 11)
                        state <= START;
                end
                
                START: begin
                    cs    <= 1;
                    we    <= 1;
                    addr  <= 8'h08;
                    wdata <= 32'h02;   // next bit
                    state <= WAIT_DONE;
                end
                
                WAIT_DONE: begin
                    cs   <= 1;
                    addr <= 8'h09;
                    
                    if (rdata[1]) begin
                        word_cnt <= 0;
                        state <= READ_RESULT;
                    end
                end
                
                READ_RESULT: begin
                    cs   <= 1;
                    addr <= 8'h30 + word_cnt;
                    
                    data_out[127 - 32*word_cnt -: 32] <= rdata;
                    word_cnt <= word_cnt + 1;
                    
                    if (word_cnt == 3) begin
                        out_valid <= 1;
                        state <= IDLE;
                    end
                end
                default: begin
                    state <= IDLE;
                end
            endcase
        end
    end
    
    aes aes_inst (
        .clk(clk),
        .reset_n(reset_n),
        .cs(cs),
        .we(we),
        .address(addr),
        .write_data(wdata),
        .read_data(rdata)
    );

endmodule