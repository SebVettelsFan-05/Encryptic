module uart_tx #(
    parameter int BAUD_DIV = 868
)(
    input  logic clk,
    input  logic rst,
    input  logic [7:0] tx_data,
    input  logic tx_start,
    output logic tx,
    output logic tx_busy
);

    logic [15:0] baud_cnt;
    logic baud_tick;

    logic [3:0] bit_index;
    logic [9:0] shift_reg;

    // Baud tick generator
    always_ff @(posedge clk) begin
        if (rst) begin
            baud_cnt  <= 0;
            baud_tick <= 0;
        end else if (tx_busy) begin
            if (baud_cnt == BAUD_DIV-1) begin
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
            tx       <= 1;
            tx_busy  <= 0;
            bit_index <= 0;
        end else begin

            if (!tx_busy) begin
                if (tx_start) begin
                    tx_busy  <= 1;
                    shift_reg <= {1'b1, tx_data, 1'b0}; // stop, data, start
                    bit_index <= 0;
                end
            end else if (baud_tick) begin
                tx        <= shift_reg[0];
                shift_reg <= {1'b1, shift_reg[9:1]};
                bit_index <= bit_index + 1;

                if (bit_index == 9)
                    tx_busy <= 0;
            end
        end
    end

endmodule