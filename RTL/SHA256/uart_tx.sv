module uart_tx #(
    parameter int BAUD_DIV = 868
)(
    input  logic       clk,
    input  logic       rst,
    input  logic [7:0] tx_data,
    input  logic       tx_start,
    output logic       tx,
    output logic       tx_busy
);

    logic [15:0] baud_cnt;
    logic        baud_tick;
    logic [3:0]  bit_index;
    logic [9:0]  shift_reg;
    logic        running;  // internal registered busy flag

    // tx_busy is high when actively transmitting OR when tx_start is asserted
    // This ensures the caller sees busy=1 on the same cycle it pulses tx_start,
    // preventing double-fire.
    assign tx_busy = running || tx_start;

    // Baud tick generator
    always_ff @(posedge clk) begin
        if (rst) begin
            baud_cnt  <= 0;
            baud_tick <= 0;
        end else if (running) begin
            if (baud_cnt == BAUD_DIV - 1) begin
                baud_cnt  <= 0;
                baud_tick <= 1;
            end else begin
                baud_cnt  <= baud_cnt + 1;
                baud_tick <= 0;
            end
        end else begin
            baud_cnt  <= 0;
            baud_tick <= 0;
        end
    end

    // Transmit logic
    always_ff @(posedge clk) begin
        if (rst) begin
            tx        <= 1'b1;
            running   <= 1'b0;
            bit_index <= 4'd0;
        end else begin
            if (!running) begin
                tx <= 1'b1;  // idle high
                if (tx_start) begin
                    running   <= 1'b1;
                    shift_reg <= {1'b1, tx_data, 1'b0}; // stop, data[7:0], start
                    bit_index <= 4'd0;
                    tx        <= 1'b0;  // start bit immediately
                end
            end else if (baud_tick) begin
                if (bit_index == 4'd9) begin
                    running <= 1'b0;
                    tx      <= 1'b1;
                end else begin
                    shift_reg <= {1'b1, shift_reg[9:1]};
                    bit_index <= bit_index + 4'd1;
                    tx        <= shift_reg[1];
                end
            end
        end
    end

endmodule

