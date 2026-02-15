module sha256_singleblock_wrapper #(
    parameter int MAX_BYTES = 55
)(
    input  logic         clk,
    input  logic         reset,

    input  logic [7:0]   msg_byte,
    input  logic         msg_valid,
    input  logic         msg_last,

    output logic         in_ready,
    output logic         busy,
    output logic         too_long,

    output logic [255:0] digest,
    output logic         digest_valid
);

    logic [7:0] msg_mem [0:MAX_BYTES-1];
    logic [5:0] msg_len;

    logic [7:0]   blk_b   [0:63];
    logic [511:0] block512;

    logic         sha_init;
    logic         sha_next;
    logic         sha_ready;
    logic [255:0] sha_digest;
    logic         sha_digest_valid;

    sha256_core u_sha (
        .clk          (clk),
        .reset_n      (!reset),
        .init         (sha_init),
        .next         (sha_next),
        .mode         (1'b1),
        .block        (block512),
        .ready        (sha_ready),
        .digest       (sha_digest),
        .digest_valid (sha_digest_valid)
    );

    assign sha_next = 1'b0;

    function automatic logic [63:0] bit_length(input logic [5:0] bytes);
        bit_length = {58'd0, bytes} * 64'd8;
    endfunction

    logic [5:0]  L_calc;
    logic [63:0] bl_calc;

    assign L_calc  = (msg_len <= MAX_BYTES) ? msg_len : MAX_BYTES;
    assign bl_calc = bit_length(L_calc);

    integer w;
    always_comb begin
        block512 = '0;
        for (w = 0; w < 16; w++) begin
            block512[511 - 32*w -: 32] =
                {blk_b[4*w+0], blk_b[4*w+1], blk_b[4*w+2], blk_b[4*w+3]};
        end
    end

    typedef enum logic [2:0] {S_COLLECT, S_BUILD, S_START, S_WAIT, S_DONE} state_t;
    state_t state;

    always_comb begin
        in_ready = (state == S_COLLECT);
        busy     = (state != S_COLLECT);
    end

    integer i;
    always_ff @(posedge clk) begin
        if (reset) begin
            state        <= S_COLLECT;
            msg_len      <= 6'd0;
            too_long     <= 1'b0;
            sha_init     <= 1'b0;
            digest       <= '0;
            digest_valid <= 1'b0;
            for (i = 0; i < 64; i++) blk_b[i] <= 8'h00;
        end else begin
            sha_init     <= 1'b0;
            digest_valid <= 1'b0;

            case (state)
                S_COLLECT: begin
                    if (msg_valid) begin
                        if (!msg_last) begin
                            if (msg_len < MAX_BYTES) begin
                                msg_mem[msg_len] <= msg_byte;
                                msg_len <= msg_len + 6'd1;
                            end else begin
                                too_long <= 1'b1;
                            end
                        end
                        if (msg_last) begin
                            state <= S_BUILD;
                        end
                    end
                end

                S_BUILD: begin
                    for (i = 0; i < 64; i++) blk_b[i] <= 8'h00;
                    for (i = 0; i < MAX_BYTES; i++) begin
                        if (i < L_calc) blk_b[i] <= msg_mem[i];
                    end
                    blk_b[L_calc] <= 8'h80;
                    blk_b[56] <= bl_calc[63:56];
                    blk_b[57] <= bl_calc[55:48];
                    blk_b[58] <= bl_calc[47:40];
                    blk_b[59] <= bl_calc[39:32];
                    blk_b[60] <= bl_calc[31:24];
                    blk_b[61] <= bl_calc[23:16];
                    blk_b[62] <= bl_calc[15:8];
                    blk_b[63] <= bl_calc[7:0];
                    state <= S_START;
                end

                S_START: begin
                    if (sha_ready) begin
                        sha_init <= 1'b1;
                        state    <= S_WAIT;
                    end
                end

                S_WAIT: begin
                    if (sha_digest_valid) begin
                        digest       <= sha_digest;
                        digest_valid <= 1'b1;
                        state        <= S_DONE;
                    end
                end

                S_DONE: begin
                    msg_len  <= 6'd0;
                    too_long <= 1'b0;
                    state    <= S_COLLECT;
                end

                default: state <= S_COLLECT;
            endcase
        end
    end

endmodule
