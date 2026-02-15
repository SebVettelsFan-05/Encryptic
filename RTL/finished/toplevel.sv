// top_uart_crypto_basys3.sv - Basys 3 wrapper
// Toggle FF: 100 MHz -> 50 MHz, then instantiates top_uart_crypto

module top_uart_crypto_basys3 (
    input  logic clk,        // 100 MHz (W5)
    input  logic reset,      // center button (U18)
    input  logic uart_rxd,   // UART RX (B18)
    output logic uart_txd    // UART TX (A18)
);

logic clk_50m;
always_ff @(posedge clk or posedge reset) begin
    if (reset)
        clk_50m <= 1'b0;
    else
        clk_50m <= ~clk_50m;
end

    top_uart_crypto #(
        .BAUD_DIV(434)
    ) u_crypto (
        .clk      (clk_50m),
        .reset    (reset),
        .uart_rxd (uart_rxd),
        .uart_txd (uart_txd)
    );

endmodule
