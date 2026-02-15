module uart_echo (
    input  logic clk,
    input  logic reset,
    input  logic uart_rxd,
    output logic uart_txd
);

    logic [7:0] rx_data;
    logic rx_valid;

    logic [7:0] tx_data;
    logic tx_start;
    logic tx_busy;

    uart_rx uart_rx_inst (
        .clk(clk),
        .rst(reset),
        .rx(uart_rxd),
        .rx_data(rx_data),
        .rx_valid(rx_valid)
    );

    uart_tx uart_tx_inst (
        .clk(clk),
        .rst(reset),
        .tx_data(tx_data),
        .tx_start(tx_start),
        .tx(uart_txd),
        .tx_busy(tx_busy)
    );

    always_ff @(posedge clk) begin
        tx_start <= 0;

        if (rx_valid && !tx_busy) begin
            tx_data  <= rx_data;
            tx_start <= 1;
        end
    end

endmodule