module bitcoin_hash(input logic clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                     output logic done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

	enum logic [4:0]{IDLE, PREP1, PRECOMPUTE1, KCOMPUTE, COMPUTE1, POST1, PREP2, COMPUTE2, POST2, PREP3, COMPUTE3, POST3, WRITE} state;
	 
	logic [31:0] a,b,c,d,e,f,g,h; // Internal Signals for hash constants
	logic [31:0] h0,h1,h2,h3,h4,h5,h6,h7; // Init and Final Hashes
	logic [31:0] first_block_a,first_block_b,first_block_c,first_block_d,first_block_e,first_block_f,first_block_g,first_block_h; // Store First Block H's
//	logic [31:0] ai,bi,ci,di,ei,fi,gi,hi; // Store Intermediate a-h's
	logic [15:0] rc, wc; // read and write counters
	logic [31:0] w[15:0]; // word storage
	logic [6:0] t; // Store which count iteration we're on
	logic [31:0] buffer[2:0]; // Buffer to store 3 intermediate words
	logic [4:0] nonce; //nonce
	logic [31:0] p;//temp storage for precompute of k
	
	assign mem_clk = clk;
	// SHA256 K constants
	parameter int k[0:63] = '{
	  32'h428a2f98, 32'h71374491, 32'hb5c0fbcf, 32'he9b5dba5, 32'h3956c25b, 32'h59f111f1, 32'h923f82a4, 32'hab1c5ed5,
	  32'hd807aa98, 32'h12835b01, 32'h243185be, 32'h550c7dc3, 32'h72be5d74, 32'h80deb1fe, 32'h9bdc06a7, 32'hc19bf174,
	  32'he49b69c1, 32'hefbe4786, 32'h0fc19dc6, 32'h240ca1cc, 32'h2de92c6f, 32'h4a7484aa, 32'h5cb0a9dc, 32'h76f988da,
	  32'h983e5152, 32'ha831c66d, 32'hb00327c8, 32'hbf597fc7, 32'hc6e00bf3, 32'hd5a79147, 32'h06ca6351, 32'h14292967,
	  32'h27b70a85, 32'h2e1b2138, 32'h4d2c6dfc, 32'h53380d13, 32'h650a7354, 32'h766a0abb, 32'h81c2c92e, 32'h92722c85,
	  32'ha2bfe8a1, 32'ha81a664b, 32'hc24b8b70, 32'hc76c51a3, 32'hd192e819, 32'hd6990624, 32'hf40e3585, 32'h106aa070,
	  32'h19a4c116, 32'h1e376c08, 32'h2748774c, 32'h34b0bcb5, 32'h391c0cb3, 32'h4ed8aa4a, 32'h5b9cca4f, 32'h682e6ff3,
	  32'h748f82ee, 32'h78a5636f, 32'h84c87814, 32'h8cc70208, 32'h90befffa, 32'ha4506ceb, 32'hbef9a3f7, 32'hc67178f2
	};

	function logic [31:0] wtnew; // function with no inputs
		logic [31:0] s0, s1;

		s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
		s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
		wtnew = w[0] + s0 + w[9] + s1;
	endfunction

// SHA256 hash round
	function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,p,
												input logic [7:0] t);
		 logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
								 logic [31:0] next_a;
	begin

		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 ch = (e & f) ^ ((~e) & g);
		 //t1 = h + S1 + ch + k[t] + w[t];
		 t1 = ch + S1 + p;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;

								 next_a = t1 + t2;

		 // this displays the next values of a, b, c, d, e, f, g, h, just like the spreadsheet
								 $display("%2d  %x", t, next_a);
		 sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
	end
	endfunction

	// right rotation
	function logic [31:0] rightrotate(input logic [31:0] x,
												 input logic [7:0] r);
	begin
		 rightrotate = (x >> r) | (x << (32-r));
	end
	endfunction	 
	 
	 
	always_ff @(posedge clk, negedge reset_n)
	begin
		if (!reset_n) begin
			state <= IDLE;
		end else
			case (state)
				IDLE:
					if (start) begin
						done <=0;
						mem_we <= 0;
						mem_addr <= message_addr;
					   rc <= 1;
					   wc <= 0;
					   state <= PREP1;
						t <= 0;
						nonce <= 0;
					end
						
				PREP1:
				begin				
					h0 <= 32'h6a09e667;
					h1 <= 32'hbb67ae85;
					h2 <= 32'h3c6ef372;
					h3 <= 32'ha54ff53a;
					h4 <= 32'h510e527f;
					h5 <= 32'h9b05688c;
					h6 <= 32'h1f83d9ab;
					h7 <= 32'h5be0cd19;
					mem_addr <= message_addr+rc;
					rc	<= rc + 16'd1;
					state <= PRECOMPUTE1;
					
				end
				
				PRECOMPUTE1: 
				begin
					a <= h0;
					b <= h1;
					c <= h2;
					d <= h3;
					e <= h4;
					f <= h5;
					g <= h6;
					h <= h7;
					w[15] <= mem_read_data;
					mem_addr <= message_addr+rc;
					rc <= rc + 1;
					state <= KCOMPUTE;
				end
				
				KCOMPUTE: 
				begin
					p <= h7 + w[15] + k[0];
					w[14] <= w[15];
					mem_addr <= message_addr+rc;
					rc <= rc + 1;
					w[15] <= mem_read_data;
					state <= COMPUTE1;					
				end
				
				COMPUTE1:
				begin
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[14], p, t);
					for(int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
					if(t < 14) begin
						w[15] <= mem_read_data;
						mem_addr <= message_addr + rc;
						rc	<= rc + 1;
					end
					else begin
						w[15] <= wtnew();
							// buffers data
							if(t==14) begin
								buffer[0] = mem_read_data;
								mem_addr <= message_addr + rc;
								rc <= rc + 1;
							end
							if(t==15) begin
								buffer[1] = mem_read_data;
							end
							if(t==16) begin
								buffer[2] = mem_read_data;
							end
					end
					if(t < 63) begin
						t <= t + 1;
						p <= g+w[15]+k[t+1];
						//state <= COMPUTE1;
					end
					else begin
						state <= POST1;
					end
				end
				
				POST1:
				begin
					h0 <= h0 + a;
					h1 <= h1 + b;
					h2 <= h2 + c;
					h3 <= h3 + d;
					h4 <= h4 + e;
					h5 <= h5 + f;
					h6 <= h6 + g;
					h7 <= h7 + h;
//					w[15] <= buffer[0];				
					t <= 0;
					state <= PREP2;
					
				end
				
				PREP2:
				begin
					a <= h0;
					b <= h1;
					c <= h2;
					d <= h3;
					e <= h4;
					f <= h5;
					g <= h6;
					h <= h7;
					first_block_a <= h0;
					first_block_b <= h1;
					first_block_c <= h2;
					first_block_d <= h3;
					first_block_e <= h4;
					first_block_f <= h5;
					first_block_g <= h6;
					first_block_h <= h7;	
					w[14] <= buffer[0];
					w[15] <= buffer[1];
					p <= h7+buffer[0]+k[0];				
					state <= COMPUTE2;
					
				end
				
//				INTERMEDIATE1:
//				begin	
//					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], t);
//					for(int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
//					if (t == 0) w[15] <= buffer[1];
//				   else w[15] <= buffer[2];
//					if(t < 1) begin
//						//state <= INTERMEDIATE1;
//					end 
//					else state <= INTERMEDIATE2;
//					t <= t + 1;
//				end
//				
//				INTERMEDIATE2:
//				begin
//				ai <= a;
//				bi <= b;
//				ci <= c;
//				di <= d;
//				ei <= e;
//				fi <= f;
//				gi <= g;
//				hi <= h;
//				state <= COMPUTE2;
//				end
				
				COMPUTE2:
				begin

					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[14], p, t);
					for(int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires
					if(t < 14) begin
//						if(t == 0) begin
//							w[15] <= buffer[1];
//						end
						if(t == 0) w[15] <= buffer[2];
						else if (t == 1) w[15] <= nonce;
						else if (t == 2) w[15] <= 32'h80000000;
						else if(t > 2 && t < 13) w[15] <= 32'h00000000;
						else w[15] <= 32'd640;
					end
					else begin
						w[15] <= wtnew();
					end
					if(t < 63) begin
						t <= t + 1;
						p <= g+w[15]+k[t+1];						
						//state <= COMPUTE2;
					end
					else begin
						state <= POST2;
					end
					
				end
				
				POST2:
				begin
					h0 <= h0 + a;
					h1 <= h1 + b;
					h2 <= h2 + c;
					h3 <= h3 + d;
					h4 <= h4 + e;
					h5 <= h5 + f;
					h6 <= h6 + g;
					h7 <= h7 + h;
//					w[15] <= h0;
					t <= 0;
					state <= PREP3;
				end
				
				PREP3:
				begin
					a <= 32'h6a09e667;
					b <= 32'hbb67ae85;
					c <= 32'h3c6ef372;
					d <= 32'ha54ff53a;
					e <= 32'h510e527f;
					f <= 32'h9b05688c;
					g <= 32'h1f83d9ab;
					h <= 32'h5be0cd19;
					w[14] <= h0;					
					p <= 32'h5be0cd19+h0+k[0];
					w[15] <= h1;
					$display("COMPUTE3");	
					state <= COMPUTE3;
					
				end
				
				COMPUTE3:
				begin
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[14], p, t);
					for(int n = 0; n < 15; n++) w[n] <= w[n+1]; // just wires				
					if(t < 14)
					begin
						case (t)
							0: w[15] <= h2;
							1: w[15] <= h3;
							2: w[15] <= h4;
							3: w[15] <= h5;
							4: w[15] <= h6;
							5: w[15] <= h7;
							6: w[15] <= 32'h80000000;
							13: w[15] <= 32'd256;
							default: w[15] <= 32'h00000000;	
						endcase
					end
					else begin
						w[15] <= wtnew();
						
					end					
					
					if(t < 63) begin
						t <= t + 1;
						p <= g+w[15]+k[t+1];						
						//state <= COMPUTE3;
					end
					else begin
						state <= POST3;
					end					
					
				end
				
				POST3:
				begin
					h0 <= 32'h6a09e667 + a;
					h1 <= 32'hbb67ae85 + b;
					h2 <= 32'h3c6ef372 + c;
					h3 <= 32'ha54ff53a + d;
					h4 <= 32'h510e527f + e;
					h5 <= 32'h9b05688c + f;
					h6 <= 32'h1f83d9ab + g;
					h7 <= 32'h5be0cd19 + h;
					state <= WRITE;
				end
				
				WRITE:
				begin
				//$display("h0 = %h, h1 = %h, h2 = %h, h3 = %h, h4 = %h, h5 = %h, h6 = %h, h7 = %h", h0, h1, h2, h3, h4, h5, h6, h7);
					if(nonce < 16) begin
						mem_write_data <= h0;
						mem_we <= 1;
						mem_addr <= output_addr + wc;
						wc <= wc + 1;
						
//						a <= ai; 
//						b <= bi;
//						c <= ci; 
//						d <= di;
//						e <= ei;
//						f <= fi;
//						g <= gi;
//						h <= hi;
						h0 <= first_block_a;
						h1 <= first_block_b;
						h2 <= first_block_c;
						h3 <= first_block_d;
						h4 <= first_block_e;
						h5 <= first_block_f;
						h6 <= first_block_g;
						h7 <= first_block_h;

						a <= first_block_a;
						b <= first_block_b;
						c <= first_block_c;
						d <= first_block_d;
						e <= first_block_e;
						f <= first_block_f;
						g <= first_block_g;
						h <= first_block_h;						
						t <= 0;
						w[14] <= buffer[0];
						w[15] <= buffer[1];
						p <= first_block_h+buffer[0]+k[0];
						nonce <= nonce + 1;						
						state <= COMPUTE2;
					end				
					else done <= 1;
				end
			
		endcase
	end
endmodule

