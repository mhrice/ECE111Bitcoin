module bitcoin_hash(input logic clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                     output logic done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

	enum logic [4:0]{IDLE, PREP1, PRECOMPUTE1, KCOMPUTE, COMPUTE1, POST1, PREP2, INTERMEDIATE1, INTERMEDIATE2, COMPUTE2, POST2, PREP3, COMPUTE3, POST3, WRITE, DONE} state;
	parameter NUM_NONCES = 16;
	logic [31:0] a,b,c,d,e,f,g,h; // Internal Signals for hash constants
	logic [31:0] A[NUM_NONCES], B[NUM_NONCES], C[NUM_NONCES], D[NUM_NONCES], E[NUM_NONCES], F[NUM_NONCES], G[NUM_NONCES], H[NUM_NONCES];
	//logic [31:0] h0,h1,h2,h3,h4,h5,h6,h7; // Init and Final Hashes
	logic [31:0] H0[15:0],H1[15:0],H2[15:0],H3[15:0],H4[15:0],H5[15:0], H6[15:0],H7[15:0]; // Init and Final Hashes
	//logic [31:0] first_block_a,first_block_b,first_block_c,first_block_d,first_block_e,first_block_f,first_block_g,first_block_h; // Store First Block H's
//	logic [31:0] ai,bi,ci,di,ei,fi,gi,hi; // Store Intermediate a-h's
	logic [15:0] rc, wc; // read and write counters
	//logic [31:0] w[15:0]; // word storage
	logic [31:0] w[15:0][15:0];
	logic [6:0] t; // Store which count iteration we're on
	logic [31:0] buffer[2:0]; // Buffer to store 3 intermediate words
	//logic [4:0] nonce; //nonce
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

	function logic [31:0] wtnew(input logic [4:0] nonce); // function with no inputs
		logic [31:0] s0, s1;
		s0 = rightrotate(w[nonce][1],7)^rightrotate(w[nonce][1],18)^(w[nonce][1]>>3);
		s1 = rightrotate(w[nonce][14],17)^rightrotate(w[nonce][14],19)^(w[nonce][14]>>10);
		wtnew = w[nonce][0] + s0 + w[nonce][9] + s1;
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

	// SHA256 hash round
	function logic [255:0] sha256_old_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
												input logic [7:0] t);
		 logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
								 logic [31:0] next_a;
	begin

		 S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
		 ch = (e & f) ^ ((~e) & g);
		 t1 = h + S1 + ch + k[t] + w;
		 S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
		 maj = (a & b) ^ (a & c) ^ (b & c);
		 t2 = S0 + maj;

							 next_a = t1 + t2;

		 // this displays the next values of a, b, c, d, e, f, g, h, just like the spreadsheet
								 $display("%2d  %x", t, next_a);
		 sha256_old_op = {t1 + t2, a, b, c, d + t1, e, f, g};
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

					end

				PREP1:
				begin
					H0[0] <= 32'h6a09e667;
					H1[0] <= 32'hbb67ae85;
					H2[0] <= 32'h3c6ef372;
					H3[0] <= 32'ha54ff53a;
					H4[0] <= 32'h510e527f;
					H5[0] <= 32'h9b05688c;
					H6[0] <= 32'h1f83d9ab;
					H7[0] <= 32'h5be0cd19;
					mem_addr <= message_addr+rc;
					rc	<= rc + 16'd1;
					state <= PRECOMPUTE1;

				end

				PRECOMPUTE1:
				begin
					a <= H0[0];
					b <= H1[0];
					c <= H2[0];
					d <= H3[0];
					e <= H4[0];
					f <= H5[0];
					g <= H6[0];
					h <= H7[0];
					w[0][15] <= mem_read_data;
					mem_addr <= message_addr+rc;
					rc <= rc + 16'b1;
					state <= KCOMPUTE;
				end

				KCOMPUTE:
				begin
					p <= H7[0] + w[0][15] + k[0];
					w[0][14] <= w[0][15];
					mem_addr <= message_addr+rc;
					rc <= rc + 16'b1;;
					w[0][15] <= mem_read_data;
					state <= COMPUTE1;
				end

				COMPUTE1:
				begin
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[0][14], p, t);
					for(int n = 0; n < 15; n++) w[0][n] <= w[0][n+1]; // just wires
					if(t < 14) begin
						w[0][15] <= mem_read_data;
						mem_addr <= message_addr + rc;
						rc	<= rc + 16'b1;
					end
					else begin
						w[0][15] <= wtnew(0);
							// buffers data
							if(t==14) begin
								buffer[0] = mem_read_data;
								mem_addr <= message_addr + rc;
								rc <= rc + 16'b1;
							end
							if(t==15) begin
								buffer[1] = mem_read_data;
							end
							if(t==16) begin
								buffer[2] = mem_read_data;
							end
					end
					if(t < 63) begin
						t <= t + 7'b1;
						p <= g+w[0][15]+k[t+1];
						//state <= COMPUTE1;
					end
					else begin
						state <= POST1;
					end

				end

				POST1:
				begin
					H0[0] <= H0[0] + a;
					H1[0] <= H1[0] + b;
					H2[0] <= H2[0] + c;
					H3[0] <= H3[0] + d;
					H4[0] <= H4[0] + e;
					H5[0] <= H5[0] + f;
					H6[0] <= H6[0] + g;
					H7[0] <= H7[0] + h;
					//w[0][15] <= buffer[0];
					t <= 0;
					p <= h+H7[0]+buffer[0]+k[0];
					state <= PREP2;

				end

				PREP2:
				begin
//					a <= h0;
//					b <= h1;
//					c <= h2;
//					d <= h3;
//					e <= h4;
//					f <= h5;
//					g <= h6;
//					h <= h7;
					{a, b, c, d, e, f, g, h} <= sha256_op(H0[0], H1[0], H2[0], H3[0], H4[0], H5[0], H6[0], H7[0], buffer[0], p, t);
//					w[0][14] <= w[0][15];
					p <= H6[0]+buffer[1]+k[t+1];
					//w[0][15] <= buffer[1];
					t <= t + 7'b1;

//					first_block_a <= h0;
//					first_block_b <= h1;
//					first_block_c <= h2;
//					first_block_d <= h3;
//					first_block_e <= h4;
//					first_block_f <= h5;
//					first_block_g <= h6;

//					first_block_h <= h7;
//					A[0] <= h0;
//					B[0] <= h1;
//					C[0] <= h2;
//					D[0] <= h3;
//					E[0] <= h4;
//					F[0] <= h5;
//					G[0] <= h6;
//					H[0] <= h7;

//					for (int n = 0; n < NUM_NONCES; n++) begin
//						A[n] <= h0;
//						B[n] <= h1;
//						C[n] <= h2;
//						D[n] <= h3;
//						E[n] <= h4;
//						F[n] <= h5;
//						G[n] <= h6;
//						H[n] <= h7;
//					end
//					w[14] <= buffer[0];
//					for (int n = 0; n < NUM_NONCES; n++) begin
//						w[n][15] <= buffer[0];
//					end;
					state <= INTERMEDIATE1;

				end

				INTERMEDIATE1:
				begin
					{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, buffer[1], p, t);

					for (int n = 0; n < NUM_NONCES; n++) begin
					w[n][13] <= buffer[0];
					w[n][14] <= buffer[1];
				   w[n][15] <= buffer[2];
					end
					state <= INTERMEDIATE2;
					t <= t + 7'b1;
				end
//
				INTERMEDIATE2:
				begin
					for (int n = 0; n < NUM_NONCES; n++) begin
						A[n] <= a;
						B[n] <= b;
						C[n] <= c;
						D[n] <= d;
						E[n] <= e;
						F[n] <= f;
						G[n] <= g;
						H[n] <= h;
					end
				state <= COMPUTE2;
				end

				COMPUTE2:
				begin
					for (int n = 0; n < NUM_NONCES; n++) begin
						{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= sha256_old_op(A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n], w[n][15], t);

//					//{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[14], p, t);

					//{A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0]} <= sha256_op(A[0], B[0], C[0], D[0], E[0], F[0], G[0], H[0], w[14], p, t);
						for(int i = 0; i < 15; i++) w[n][i] <= w[n][i+1]; // just wires
						if(t < 15) begin
							//if(t == 0) w[n][15] <= buffer[1];
							//else if(t == 1) w[n][15] <= buffer[2];
							if (t == 2) w[n][15] <= n;
							else if (t == 3) w[n][15] <= 32'h80000000;
							else if(t > 3 && t < 14) w[n][15] <= 32'h00000000;
							else w[n][15] <= 32'd640;
						end
						else begin
							w[n][15] <= wtnew(n);
						end
					end
					if(t < 63) begin
						t <= t + 7'b1;
						//p <= G[n]+w[15]+k[t+1];

						//state <= COMPUTE2;
					end
					else begin
						state <= POST2;
					end

				end

				POST2:
				begin
//					h0 <= h0 + a;
//					h1 <= h1 + b;
//					h2 <= h2 + c;
//					h3 <= h3 + d;
//					h4 <= h4 + e;
//					h5 <= h5 + f;
//					h6 <= h6 + g;
//					h7 <= h7 + h;
//					w[15] <= h0;
					for (int n = 0; n < NUM_NONCES; n++) begin
							H0[n] <= H0[0] + A[n];
							H1[n] <= H1[0] + B[n];
							H2[n] <= H2[0] + C[n];
							H3[n] <= H3[0] + D[n];
							H4[n] <= H4[0] + E[n];
							H5[n] <= H5[0] + F[n];
							H6[n] <= H6[0] + G[n];
							H7[n] <= H7[0] + H[n];
					end
					t <= 0;
					state <= PREP3;

				end

				PREP3:
				begin
//					a <= 32'h6a09e667;
//					b <= 32'hbb67ae85;
//					c <= 32'h3c6ef372;
//					d <= 32'ha54ff53a;
//					e <= 32'h510e527f;
//					f <= 32'h9b05688c;
//					g <= 32'h1f83d9ab;
//					h <= 32'h5be0cd19;
					//p <= 32'h5be0cd19+h0+k[0];
					//w[14] <= h0;
					//w[15] <= h1;
					for (int n = 0; n < NUM_NONCES; n++) begin
						w[n][15] <= H0[n];
						A[n] <= 32'h6a09e667;
						B[n] <= 32'hbb67ae85;
						C[n] <= 32'h3c6ef372;
						D[n] <= 32'ha54ff53a;
						E[n] <= 32'h510e527f;
						F[n] <= 32'h9b05688c;
						G[n] <= 32'h1f83d9ab;
						H[n] <= 32'h5be0cd19;
					end

					state <= COMPUTE3;

				end

				COMPUTE3:
				begin
					for (int n = 0; n < NUM_NONCES; n++) begin
						{A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n]} <= sha256_old_op(A[n], B[n], C[n], D[n], E[n], F[n], G[n], H[n], w[n][15], t);
						for(int i = 0; i < 15; i++) w[n][i] <= w[n][i+1]; // just wires
						if(t < 15)
						begin
							case (t)
								0: w[n][15] <= H1[n];
								1: w[n][15] <= H2[n];
								2: w[n][15] <= H3[n];
								3: w[n][15] <= H4[n];
								4: w[n][15] <= H5[n];
								5: w[n][15] <= H6[n];
								6: w[n][15] <= H7[n];
								7: w[n][15] <= 32'h80000000;
								14: w[n][15] <= 32'd256;
								default: w[n][15] <= 32'h00000000;
							endcase
						end
						else begin
							w[n][15] <= wtnew(n);

						end
					end
					if(t < 63) begin
						t <= t + 7'b1;
						//p <= g+w[15]+k[t+1];
					end
					else begin
						state <= POST3;
					end

				end

				POST3:
				begin
				for (int n = 0; n < NUM_NONCES; n++) begin
					H0[n] <= 32'h6a09e667 + A[n];
					H1[n] <= 32'hbb67ae85 + B[n];
					H2[n] <= 32'h3c6ef372 + C[n];
					H3[n] <= 32'ha54ff53a + D[n];
					H4[n] <= 32'h510e527f + E[n];
					H5[n] <= 32'h9b05688c + F[n];
					H6[n] <= 32'h1f83d9ab + G[n];
					H7[n] <= 32'h5be0cd19 + H[n];
				end
					t <= 0;
					state <= WRITE;

				end

				WRITE:
				begin

					if(t < 15) begin
						t <= t + 7'b1;
						mem_write_data <= H0[t];
						mem_we <= 1;
						mem_addr <= output_addr + wc;
						wc <= wc + 16'b1;
						state <= WRITE;

					end
					else begin
						mem_write_data <= H0[15];
						mem_addr <= output_addr + wc;
						state <= DONE;
					end

				end
				DONE:
				done<=1;

		endcase
	end
endmodule
