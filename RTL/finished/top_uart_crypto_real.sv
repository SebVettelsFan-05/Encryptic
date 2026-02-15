// ============================================================
// top_uart_crypto.sv
// ============================================================
// SHA-256 + AES-256 over UART. No FIFO - direct RX.
//
// PROTOCOL:
//   Sabc<Enter>                -> 64 hex + |DONE\r\n
//   Emypassword<Enter>         -> KEY_OK\r\n
//   <32 hex chars>             -> 32 hex ciphertext + \r\n
//   Q                          -> exit AES mode
//   Dmypassword<Enter>         -> KEY_OK\r\n (decrypt)
// ============================================================

module top_uart_crypto #(
    parameter int BAUD_DIV  = 868,
    parameter int MAX_BYTES = 55
)(
    input  logic       clk,
    input  logic       reset,
    input  logic       uart_rxd,
    output logic       uart_txd,
    output logic    [15:0] led
);

    // --------------------------------------------------------
    // UART - direct, no FIFO
    // --------------------------------------------------------
    logic [7:0] rx_data;
    logic       rx_valid;
    logic [7:0] tx_data;
    logic       tx_start;
    logic       tx_busy;
    logic [30:0] led_counter;
    
    assign led = (tx_start || tx_busy || rx_valid) ? 16'hFFFF : 16'h0000;
    uart_rx #(.BAUD_DIV(BAUD_DIV)) u_rx (
        .clk(clk), .rst(reset),
        .rx(uart_rxd), .rx_data(rx_data), .rx_valid(rx_valid)
    );

    uart_tx #(.BAUD_DIV(BAUD_DIV)) u_tx (
        .clk(clk), .rst(reset),
        .tx_data(tx_data), .tx_start(tx_start),
        .tx(uart_txd), .tx_busy(tx_busy)
    );

    // --------------------------------------------------------
    // SHA-256
    // --------------------------------------------------------
    logic [7:0]   sha_msg_byte;
    logic         sha_msg_valid;
    logic         sha_msg_last;
    logic         sha_in_ready;
    logic         sha_busy;
    logic         sha_too_long;
    logic [255:0] sha_digest;
    logic         sha_digest_valid;

    sha256_singleblock_wrapper #(.MAX_BYTES(MAX_BYTES)) u_sha (
        .clk(clk), .reset(reset),
        .msg_byte(sha_msg_byte), .msg_valid(sha_msg_valid),
        .msg_last(sha_msg_last), .in_ready(sha_in_ready),
        .busy(sha_busy), .too_long(sha_too_long),
        .digest(sha_digest), .digest_valid(sha_digest_valid)
    );

    // --------------------------------------------------------
    // AES core
    // --------------------------------------------------------
    logic         aes_encdec;
    logic         aes_init;
    logic         aes_next;
    logic         aes_ready;
    logic [255:0] aes_key;
    logic [127:0] aes_block;
    logic [127:0] aes_result;
    logic         aes_result_valid;

    aes_core u_aes (
        .clk(clk), .reset_n(!reset),
        .encdec(aes_encdec), .init(aes_init), .next(aes_next),
        .ready(aes_ready), .key(aes_key), .keylen(1'b1),
        .block(aes_block), .result(aes_result),
        .result_valid(aes_result_valid)
    );

    // --------------------------------------------------------
    // ASCII helpers
    // --------------------------------------------------------
    function automatic logic [7:0] hex_char(input logic [3:0] nib);
        if (nib < 4'd10) hex_char = 8'h30 + nib;
        else              hex_char = 8'h61 + (nib - 4'd10);
    endfunction

    function automatic logic [3:0] hex_to_nib(input logic [7:0] ch);
        if (ch >= 8'h30 && ch <= 8'h39)      hex_to_nib = ch[3:0];
        else if (ch >= 8'h41 && ch <= 8'h46) hex_to_nib = ch[3:0] + 4'd9;
        else if (ch >= 8'h61 && ch <= 8'h66) hex_to_nib = ch[3:0] + 4'd9;
        else                                   hex_to_nib = 4'd0;
    endfunction

    function automatic logic is_hex_char(input logic [7:0] ch);
        is_hex_char = (ch >= 8'h30 && ch <= 8'h39) ||
                      (ch >= 8'h41 && ch <= 8'h46) ||
                      (ch >= 8'h61 && ch <= 8'h66);
    endfunction

    function automatic logic is_eol(input logic [7:0] ch);
        is_eol = (ch == 8'h0D) || (ch == 8'h0A);
    endfunction

    // --------------------------------------------------------
    // FSM states
    // --------------------------------------------------------
    typedef enum logic [4:0] {
        S_CMD,

        S_SHA_COLLECT,
        S_SHA_WAIT,
        S_SHA_HEX,
        S_SHA_MARK,
        S_SHA_CR,
        S_SHA_LF,

        S_AES_PASS,
        S_AES_HASH_WAIT,
        S_AES_KEY_INIT,
        S_AES_KEY_WAIT,
        S_AES_KEY_OK,

        S_AES_HEX_IN,
        S_AES_LATCH,
        S_AES_BLOCK_READY,
        S_AES_START,
        S_AES_WAIT_READY_LOW,
        S_AES_WAIT_READY_HIGH,
        S_AES_WAIT,
        S_AES_HEX_OUT,
        S_AES_CR,
        S_AES_LF,

        S_TX_PULSE,
        S_TX_WAIT_BUSY,
        S_TX_WAIT_DONE
    } state_t;

    state_t state;
    state_t tx_return_state;

    // --------------------------------------------------------
    // Shared registers
    // --------------------------------------------------------
    logic [7:0] byte_shift;
    logic       nib_lo;

    // SHA output
    logic [255:0] sha_hold;
    logic [6:0]   sha_hex_count;
    logic [5:0]   sha_byte_idx;
    logic         sha_nib_lo;
    logic [2:0]   sha_mark_idx;
    logic [7:0]   sha_cur_byte;
    logic [3:0]   sha_cur_nib;

    always_comb begin
        sha_cur_byte = sha_hold[255 - 8*sha_byte_idx -: 8];
        sha_cur_nib  = sha_nib_lo ? sha_cur_byte[3:0] : sha_cur_byte[7:4];
    end

    // AES input/output
    logic [127:0] block_shift;
    logic [5:0]   hex_in_count;
    logic [127:0] aes_hold;
    logic [5:0]   aes_hex_count;
    logic [3:0]   aes_byte_idx;
    logic         aes_nib_lo;
    logic [7:0]   aes_cur_byte;
    logic [3:0]   aes_cur_nib;
    logic [2:0]   kok_idx;

    always_comb begin
        aes_cur_byte = aes_hold[127 - 8*aes_byte_idx -: 8];
        aes_cur_nib  = aes_nib_lo ? aes_cur_byte[3:0] : aes_cur_byte[7:4];
    end

    // --------------------------------------------------------
    // FSM
    // --------------------------------------------------------
    always_ff @(posedge clk) begin
        if (reset) begin
            state           <= S_CMD;
            tx_return_state <= S_CMD;
            tx_data         <= 8'h00;
            tx_start        <= 1'b0;

            sha_msg_byte    <= 8'h00;
            sha_msg_valid   <= 1'b0;
            sha_msg_last    <= 1'b0;
            sha_hold        <= 256'd0;
            sha_hex_count   <= 7'd0;
            sha_byte_idx    <= 6'd0;
            sha_nib_lo      <= 1'b0;
            sha_mark_idx    <= 3'd0;

            aes_init        <= 1'b0;
            aes_next        <= 1'b0;
            aes_encdec      <= 1'b1;
            aes_key         <= 256'd0;
            aes_block       <= 128'd0;
            block_shift     <= 128'd0;
            hex_in_count    <= 6'd0;
            aes_hold        <= 128'd0;
            aes_hex_count   <= 6'd0;
            aes_byte_idx    <= 4'd0;
            aes_nib_lo      <= 1'b0;
            nib_lo          <= 1'b0;
            byte_shift      <= 8'd0;
            kok_idx         <= 3'd0;
            led_counter <= 1'b0;
        end else begin
            // default pulses off
            sha_msg_valid <= 1'b0;
            sha_msg_last  <= 1'b0;
            aes_init      <= 1'b0;
            aes_next      <= 1'b0;
            tx_start      <= 1'b0;
            led_counter <= led_counter + 1;
            case (state)

                // === TX FSM ===
                S_TX_PULSE: begin
                    tx_start <= 1'b1;
                    state    <= S_TX_WAIT_BUSY;
                end
                S_TX_WAIT_BUSY: begin
                    if (tx_busy)
                        state <= S_TX_WAIT_DONE;
                end
                S_TX_WAIT_DONE: begin
                    if (!tx_busy)
                        state <= tx_return_state;
                end

                // === CMD ===
                S_CMD: begin
                    if (rx_valid) begin
                        if (rx_data == 8'h53) state <= S_SHA_COLLECT; // 'S'
                        else if (rx_data == 8'h45) begin // 'E'
                            aes_encdec <= 1'b1;
                            state      <= S_AES_PASS;
                        end
                        else if (rx_data == 8'h44) begin // 'D'
                            aes_encdec <= 1'b0;
                            state      <= S_AES_PASS;
                        end
                    end
                end

                // === SHA ===
                S_SHA_COLLECT: begin
                    if (rx_valid && sha_in_ready) begin
                        if (is_eol(rx_data)) begin
                            sha_msg_byte  <= 8'h00;
                            sha_msg_valid <= 1'b1;
                            sha_msg_last  <= 1'b1;
                            state         <= S_SHA_WAIT;
                        end else begin
                            sha_msg_byte  <= rx_data;
                            sha_msg_valid <= 1'b1;
                        end
                    end
                end
                S_SHA_WAIT: begin
                    if (sha_digest_valid) begin
                        sha_hold      <= sha_digest;
                        sha_hex_count <= 7'd0;
                        sha_byte_idx  <= 6'd0;
                        sha_nib_lo    <= 1'b0;
                        state         <= S_SHA_HEX;
                    end
                end
                S_SHA_HEX: begin
                    tx_data         <= hex_char(sha_cur_nib);
                    tx_return_state <= S_SHA_HEX;
                    if (sha_hex_count == 7'd63) begin
                        sha_mark_idx    <= 3'd0;
                        tx_return_state <= S_SHA_MARK;
                    end else begin
                        sha_hex_count <= sha_hex_count + 7'd1;
                        if (sha_nib_lo) begin
                            sha_nib_lo   <= 1'b0;
                            sha_byte_idx <= sha_byte_idx + 6'd1;
                        end else
                            sha_nib_lo <= 1'b1;
                    end
                    state <= S_TX_PULSE;
                end
                S_SHA_MARK: begin
                    case (sha_mark_idx)
                        3'd0: tx_data <= 8'h7C; // '|'
                        3'd1: tx_data <= 8'h44; // D
                        3'd2: tx_data <= 8'h4F; // O
                        3'd3: tx_data <= 8'h4E; // N
                        3'd4: tx_data <= 8'h45; // E
                        default: tx_data <= 8'h3F;
                    endcase
                    if (sha_mark_idx == 3'd4) tx_return_state <= S_SHA_CR;
                    else begin
                        sha_mark_idx <= sha_mark_idx + 3'd1;
                        tx_return_state <= S_SHA_MARK;
                    end
                    state <= S_TX_PULSE;
                end
                S_SHA_CR: begin
                    tx_data <= 8'h0D;
                    tx_return_state <= S_SHA_LF;
                    state <= S_TX_PULSE;
                end
                S_SHA_LF: begin
                    tx_data <= 8'h0A;
                    tx_return_state <= S_CMD;
                    state <= S_TX_PULSE;
                end

                // === AES passphrase ===
                S_AES_PASS: begin
                    if (rx_valid && sha_in_ready) begin
                        if (is_eol(rx_data)) begin
                            sha_msg_byte  <= 8'h00;
                            sha_msg_valid <= 1'b1;
                            sha_msg_last  <= 1'b1;
                            state         <= S_AES_HASH_WAIT;
                        end else begin
                            sha_msg_byte  <= rx_data;
                            sha_msg_valid <= 1'b1;
                        end
                    end
                end
                S_AES_HASH_WAIT: begin
                    if (sha_digest_valid) begin
                        aes_key <= sha_digest;
                        state   <= S_AES_KEY_INIT;
                    end
                end
                S_AES_KEY_INIT: begin
                    if (aes_ready) begin
                        aes_init <= 1'b1;
                        state    <= S_AES_KEY_WAIT;
                    end
                end
                S_AES_KEY_WAIT: begin
                    if (aes_ready) begin
                        kok_idx <= 3'd0;
                        state   <= S_AES_KEY_OK;
                    end
                end
                S_AES_KEY_OK: begin
                    case (kok_idx)
                        3'd0: tx_data <= 8'h4B; // K
                        3'd1: tx_data <= 8'h45; // E
                        3'd2: tx_data <= 8'h59; // Y
                        3'd3: tx_data <= 8'h5F; // _
                        3'd4: tx_data <= 8'h4F; // O
                        3'd5: tx_data <= 8'h4B; // K
                        3'd6: tx_data <= 8'h0D;
                        3'd7: tx_data <= 8'h0A;
                        default: tx_data <= 8'h3F;
                    endcase
                    if (kok_idx == 3'd7) begin
                        hex_in_count    <= 6'd0;
                        block_shift     <= 128'd0;
                        tx_return_state <= S_AES_HEX_IN;
                    end else begin
                        kok_idx         <= kok_idx + 3'd1;
                        tx_return_state <= S_AES_KEY_OK;
                    end
                    state <= S_TX_PULSE;
                end

                // === AES HEX INPUT ===
                S_AES_HEX_IN: begin
                    if (rx_valid) begin
                        if (is_hex_char(rx_data)) begin
                            if (!nib_lo) begin
                                byte_shift[7:4] <= hex_to_nib(rx_data);
                                nib_lo <= 1'b1;
                            end else begin
                                byte_shift[3:0] <= hex_to_nib(rx_data);
                                nib_lo <= 1'b0;
                                block_shift <= {block_shift[119:0], 
                                    {byte_shift[7:4], hex_to_nib(rx_data)}};
                                hex_in_count <= hex_in_count + 1'b1;
                                if (hex_in_count == 15) begin
                                    hex_in_count <= 0;
                                    state <= S_AES_LATCH;
                                end
                            end
                        end else if (rx_data == 8'h51) state <= S_CMD; // 'Q'
                    end
                end
                S_AES_LATCH: begin
                    aes_block <= block_shift;
                    state     <= S_AES_BLOCK_READY;   // <--- NEW
                end
                
                S_AES_BLOCK_READY: begin
                    // give aes_block 1 full clock to settle
                    state <= S_AES_START;
                end
                
                S_AES_START: begin
                    if (aes_ready) begin
                        aes_next <= 1'b1;                 // pulse next
                        state    <= S_AES_WAIT_READY_LOW; // go wait for busy
                    end
                end
                
                S_AES_WAIT_READY_LOW: begin
                    aes_next <= 1'b0;                     // ensure 1-cycle pulse
                    if (!aes_ready) begin                 // AES started
                        state <= S_AES_WAIT_READY_HIGH;
                    end
                end 
    
                S_AES_WAIT_READY_HIGH: begin
                    if (aes_ready) begin                  // AES finished
                        aes_hold      <= aes_result;
                        aes_hex_count <= 6'd0;
                        aes_byte_idx  <= 4'd0;
                        aes_nib_lo    <= 1'b0;
                        state         <= S_AES_HEX_OUT;
                    end
                end
                S_AES_WAIT: begin
                    if (aes_result_valid) begin
                        aes_hold      <= aes_result;
                        aes_hex_count <= 6'd0;
                        aes_byte_idx  <= 4'd0;
                        aes_nib_lo    <= 1'b0;
                        state         <= S_AES_HEX_OUT;
                    end
                end
                S_AES_HEX_OUT: begin
                    tx_data         <= hex_char(aes_cur_nib);
                    tx_return_state <= S_AES_HEX_OUT;
                    if (aes_hex_count == 6'd31) tx_return_state <= S_AES_CR;
                    else begin
                        aes_hex_count <= aes_hex_count + 6'd1;
                        if (aes_nib_lo) begin
                            aes_nib_lo   <= 1'b0;
                            aes_byte_idx <= aes_byte_idx + 4'd1;
                        end else
                            aes_nib_lo <= 1'b1;
                    end
                    state <= S_TX_PULSE;
                end
                S_AES_CR: begin
                    tx_data <= 8'h0D;
                    tx_return_state <= S_AES_LF;
                    state <= S_TX_PULSE;
                end
                S_AES_LF: begin
                    tx_data         <= 8'h0A;
                    hex_in_count    <= 6'd0;
                    block_shift     <= 128'd0;
                    tx_return_state <= S_AES_HEX_IN;
                    state           <= S_TX_PULSE;
                end

                default: state <= S_CMD;
            endcase
        end
    end

endmodule
