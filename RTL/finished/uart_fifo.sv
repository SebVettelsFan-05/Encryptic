// rx_fifo.sv - 128-byte FIFO

module rx_fifo (
    input  logic       clk,
    input  logic       reset,

    input  logic [7:0] rx_data_in,
    input  logic       rx_valid_in,

    output logic [7:0] rx_data_out,
    output logic       rx_valid_out,
    input  logic       rx_read
);

    localparam DEPTH = 128;
    localparam AW = 7;

    logic [7:0] mem [0:DEPTH-1];
    logic [AW:0] wr_ptr, rd_ptr;

    wire [AW:0] count = wr_ptr - rd_ptr;

    assign rx_valid_out = (count != 0);
    assign rx_data_out  = mem[rd_ptr[AW-1:0]];

    always_ff @(posedge clk) begin
        if (reset) begin
            wr_ptr <= 0;
            rd_ptr <= 0;
        end else begin
            if (rx_valid_in && (count < DEPTH)) begin
                mem[wr_ptr[AW-1:0]] <= rx_data_in;
                wr_ptr <= wr_ptr + 1;
            end
            if (rx_read && (count != 0)) begin
                rd_ptr <= rd_ptr + 1;
            end
        end
    end

endmodule