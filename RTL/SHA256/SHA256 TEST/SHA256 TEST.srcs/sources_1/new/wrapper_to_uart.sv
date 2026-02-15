module top_uart_sha256_1wrap #(
    parameter int BAUD_DIV = 868
)(
    input  logic clk,
    input  logic reset,      // active-high
    input  logic uart_rxd,
    output logic uart_txd
);

    // UART
    logic [7:0] rx_data;
    logic       rx_valid;

    logic [7:0] tx_data;
    logic       tx_start;
    logic       tx_busy;

    uart_rx #(.BAUD_DIV(BAUD_DIV)) u_rx (
        .clk(clk), .rst(reset),
        .rx(uart_rxd),
        .rx_data(rx_data),
        .rx_valid(rx_valid)
    );

    uart_tx #(.BAUD_DIV(BAUD_DIV)) u_tx (
        .clk(clk), .rst(reset),
        .tx_data(tx_data),
        .tx_start(tx_start),
        .tx(uart_txd),
        .tx_busy(tx_busy)
    );

    // SHA wrapper
    logic [7:0]   msg_byte;
    logic         msg_valid;
    logic         msg_last;

    logic         in_ready;
    logic         sha_busy;
    logic         too_long;
    logic [255:0] digest;
    logic         digest_valid;

    sha256_singleblock_wrapper u_wrap (
        .clk(clk),
        .reset(reset),
        .msg_byte(msg_byte),
        .msg_valid(msg_valid),
        .msg_last(msg_last),
        .in_ready(in_ready),
        .busy(sha_busy),
        .too_long(too_long),
        .digest(digest),
        .digest_valid(digest_valid)
    );

    // nibble -> ASCII hex
    function automatic logic [7:0] hex_char(input logic [3:0] nib);
        if (nib < 4'd10) hex_char = 8'h30 + nib;
        else             hex_char = 8'h61 + (nib - 4'd10);
    endfunction

    typedef enum logic [2:0] {
        S_COLLECT,
        S_WAIT_HASH,
        S_SEND_HEX,
        S_SEND_MARK,
        S_SEND_CR,
        S_SEND_LF
    } state_t;

    state_t state;

    logic [255:0] digest_hold;

    // print control
    logic [6:0] hex_count;
    logic [5:0] byte_idx;
    logic       nibble_lo;
    logic [2:0] mark_idx;

    // helper to extract a byte, MSB first
    function automatic logic [7:0] get_byte(input logic [255:0] d, input logic [5:0] bi);
        get_byte = d[255 - 8*bi -: 8];
    endfunction

    always_ff @(posedge clk) begin
        if (reset) begin
            state       <= S_COLLECT;
            msg_byte    <= 8'h00;
            msg_valid   <= 1'b0;
            msg_last    <= 1'b0;

            tx_data     <= 8'h00;
            tx_start    <= 1'b0;

            digest_hold <= '0;

            hex_count   <= 7'd0;
            byte_idx    <= 6'd0;
            nibble_lo   <= 1'b0;
            mark_idx    <= 3'd0;
        end else begin
            // default pulses low
            msg_valid <= 1'b0;
            msg_last  <= 1'b0;
            tx_start  <= 1'b0;

            case (state)
                S_COLLECT: begin
                    if (rx_valid && in_ready) begin
                        if (rx_data == 8'h0D || rx_data == 8'h0A) begin
                            msg_byte  <= 8'h00;
                            msg_valid <= 1'b1;
                            msg_last  <= 1'b1;
                            state     <= S_WAIT_HASH;
                        end else begin
                            msg_byte  <= rx_data;
                            msg_valid <= 1'b1;
                        end
                    end
                end

                S_WAIT_HASH: begin
                    if (digest_valid) begin
                        digest_hold <= digest;
                        hex_count   <= 7'd0;
                        byte_idx    <= 6'd0;
                        nibble_lo   <= 1'b0;
                        state       <= S_SEND_HEX;
                    end
                end

                S_SEND_HEX: begin
                    if (!tx_busy) begin
                        logic [7:0] b;
                        logic [3:0] nib;

                        b = get_byte(digest_hold, byte_idx);

                        if (!nibble_lo) nib = b[7:4];
                        else            nib = b[3:0];

                        tx_data  <= hex_char(nib);
                        tx_start <= 1'b1;

                        hex_count <= hex_count + 7'd1;

                        if (hex_count == 7'd63) begin
                            mark_idx <= 3'd0;
                            state    <= S_SEND_MARK;
                        end else begin
                            if (nibble_lo) begin
                                nibble_lo <= 1'b0;
                                byte_idx  <= byte_idx + 6'd1;
                            end else begin
                                nibble_lo <= 1'b1;
                            end
                        end
                    end
                end

                S_SEND_MARK: begin
                    if (!tx_busy) begin
                        tx_start <= 1'b1;
                        case (mark_idx)
                            3'd0: tx_data <= 8'h7C; // |
                            3'd1: tx_data <= 8'h44; // D
                            3'd2: tx_data <= 8'h4F; // O
                            3'd3: tx_data <= 8'h4E; // N
                            3'd4: tx_data <= 8'h45; // E
                            default: tx_data <= 8'h3F;
                        endcase

                        mark_idx <= mark_idx + 3'd1;
                        if (mark_idx == 3'd4) state <= S_SEND_CR;
                    end
                end

                S_SEND_CR: begin
                    if (!tx_busy) begin
                        tx_data  <= 8'h0D;
                        tx_start <= 1'b1;
                        state    <= S_SEND_LF;
                    end
                end

                S_SEND_LF: begin
                    if (!tx_busy) begin
                        tx_data  <= 8'h0A;
                        tx_start <= 1'b1;
                        state    <= S_COLLECT;
                    end
                end

                default: state <= S_COLLECT;
            endcase
        end
    end

endmodule
