module uart_rx #(
    parameter int BAUD_DIV = 868
)(
    input  logic clk,
    input  logic rst,
    input  logic rx,
    output logic [7:0] rx_data,
    output logic rx_valid
);

    logic [15:0] baud_cnt;
    logic baud_tick;

    logic [3:0] bit_index;
    logic [9:0] shift_reg;
    logic busy;

    // Baud tick generator
    always_ff @(posedge clk) begin
        if (rst) begin
            baud_cnt  <= 0;
            baud_tick <= 0;
        end else if (busy) begin
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

    // Receiver state logic
    always_ff @(posedge clk) begin
        if (rst) begin
            busy      <= 0;
            bit_index <= 0;
            rx_valid  <= 0;
        end else begin
            rx_valid <= 0;

            if (!busy) begin
                if (!rx) begin  // start bit detected
                    busy      <= 1;
                    bit_index <= 0;
                end
            end else if (baud_tick) begin
                shift_reg <= {rx, shift_reg[9:1]};
                bit_index <= bit_index + 1;

                if (bit_index == 9) begin
                    busy     <= 0;
                    rx_data  <= shift_reg[8:1];
                    rx_valid <= 1;
                end
            end
        end
    end

endmodule
