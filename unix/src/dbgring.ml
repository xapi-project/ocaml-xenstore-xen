(*
 * Copyright (C) Citrix Systems Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 only. with the special
 * exception on linking described in file LICENSE.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *)
let xenstored_proc_port = "/proc/xen/xsd_port"
let xenstored_proc_kva = "/proc/xen/xsd_kva"

let page_size = 4096 (* xenstore doesn't support anything else *)

let open_ring0 () =
	let fd = Unix.openfile xenstored_proc_kva [ Unix.O_RDWR ] 0o600 in
	let page_opt = Xenstore.map_fd fd page_size in
	Unix.close fd;
	match page_opt with
	| Some page -> Cstruct.of_bigarray page
	| None -> failwith "Failed to map dom0's xenbus ring"

let open_ringU domid mfn =
	let xc = Xenctrl.interface_open () in
	let len = 4096 in
	let m = Xenctrl.map_foreign_range xc domid page_size mfn in
	(* We copy the contents out (twice) to fix the types *)
	let ba = Bigarray.(Array1.create char c_layout page_size) in
	let c = Cstruct.of_bigarray ba in
	let s = Xenmmap.read m 0 page_size in
	Cstruct.blit_from_string s 0 c 0 page_size;
	c

let open_ring domid mfn : Cstruct.t =
	if domid = 0
	then open_ring0 ()
	else open_ringU domid mfn

let load_ring filename : Cstruct.t =
	let ba = Bigarray.(Array1.create char c_layout page_size) in
	let c = Cstruct.of_bigarray ba in
	let s = String.make page_size '\000' in
	let f = Unix.openfile filename [ Unix.O_RDONLY ] 0o0 in
	let n = Unix.read f s 0 page_size in
	if n <> page_size
	then failwith (Printf.sprintf "Failed to read a page of data from %s" filename);
	Unix.close f;
	Cstruct.blit_from_string s 0 c 0 page_size;
	c

let save_ring ring filename =
	let f = Unix.openfile filename [ Unix.O_WRONLY; Unix.O_CREAT ] 0o644 in
	let s = String.make 4096 '\000' in
	Cstruct.blit_to_string ring 0 s 0 (String.length s);
	Unix.write f s 0 (String.length s);
	Unix.close f

cstruct ring {
	uint8_t output[1024];
	uint8_t input[1024];
	uint32_t output_cons;
	uint32_t output_prod;
	uint32_t input_cons;
	uint32_t input_prod
} as little_endian

module MemIO = struct
	type 'a t = 'a
	let return x = x
	let ( >>= ) x f = f x
	type channel = {
		mutable mem: Cstruct.t;
	}
	let of_cstruct x = { mem = x }
	let read channel buf ofs len =
		let avail = min (Cstruct.len channel.mem) len in
		Cstruct.blit_to_string channel.mem 0 buf ofs avail;
		channel.mem <- Cstruct.shift channel.mem avail;
		avail
	let write _ _ _ _ = failwith "MemIO is read/only"
end
module MemPS = Xs_protocol.PacketStream(MemIO)

cstruct header {
	uint32_t ty;
	uint32_t rid;
	uint32_t tid;
	uint32_t len
} as little_endian

exception Corrupt

let count_packets c =
	let rec follow c =
		if Cstruct.len c < sizeof_header
		then 0
		else begin
			if Xs_protocol.Op.of_int32 (get_header_ty c) = None
			then raise Corrupt;
			(* demand request ids are unique? *)
			let len = Int32.to_int (get_header_len c) in
			if len > 4096 || len < 0 then raise Corrupt;
			let next = Cstruct.shift c (sizeof_header + len) in
			1 + (follow next)
		end in
	try
		follow c
	with Corrupt -> 0

let fold_over_packets f init c =
	let open Xs_protocol in
	let s = MemPS.make (MemIO.of_cstruct c) in
	let rec inner acc = match MemPS.recv s with
	| Exception _ -> acc
	| Ok p -> inner (f acc p) in
	inner init

let count_packets c = List.length (fold_over_packets (fun acc p -> p :: acc) [] c)

(*
let hexify s =
	let hexseq_of_char c = Printf.sprintf "%02x" (Char.code c) in
	let hs = String.create (String.length s * 2) in
	for i = 0 to String.length s - 1
	do
		let seq = hexseq_of_char s.[i] in
		hs.[i * 2] <- seq.[0];
		hs.[i * 2 + 1] <- seq.[1];
	done;
	hs

let ring_size = 1024

let alpha ~req_cons ~req_prod ~rsp_cons ~rsp_prod s =
	let s = String.copy s in
	for i = 0 to String.length s - 1
	do
		if (i < 2*ring_size && i >= req_cons && i <= req_prod) ||
		   (i < 4*ring_size && i >= rsp_cons && i <= rsp_prod)
		then s.[i] <- '$'
		else if (s.[i] >= 'a' && s.[i] <= 'z') ||
		   (s.[i] >= 'A' && s.[i] <= 'Z') ||
		   (s.[i] >= '0' && s.[i] <= '9') ||
		   s.[i] = '/' || s.[i] = '-' || s.[i] = '@' then
		   	()
		else
			s.[i] <- '+'
	done;
	s

let int_from_page ss n =
	let b1 = String.sub ss n 2 in
	let b2 = String.sub ss (n+2) 2 in
	int_of_string ("0x"^ b2 ^ b1) mod ring_size
*)

let printable = function 
	| 'a' .. 'z'
	| 'A' .. 'Z'
	| '0' .. '9'
	| '!' | '@' | '#' | '$' | '%' | '^' | '&' | '*' | '(' | ')'
	| '~' | '`' | '_' | '+' | '-' | '=' | ';' | ':' | '{' | '}'
	| '<' | '>' | ',' | '.' | '?' | '/' | '|' | '\\'| '[' | ']'
		-> true
	| _ -> false

let escape_string s =
	let result = Buffer.create (String.length s) in
	for i = 0 to String.length s - 1 do
		if printable s.[i]
		then Buffer.add_char result s.[i]
		else Buffer.add_string result (Printf.sprintf "\\%d" (int_of_char s.[i]))
	done;
	Buffer.contents result

module HexPrinter = struct
	(* Accumulate bytes into lines based on a given output width,
	   and print hex and printable ASCII *)
	type t = {
		accumulator: char option array;
		bytes_per_line: int;
		mutable next_index: int;
		mutable start_of_line_offset_in_stream: int;
		on_line_complete: int -> string -> unit;
	}

	let per_byte_overhead = 4 (* 2 nibbles + space + ascii *)
	let print_line t =
		let chars = Array.to_list t.accumulator in
		let hex = List.map (function
		| None -> "   "
		| Some c -> Printf.sprintf "%02x " (int_of_char c)
		) chars in
		let ascii = List.map (function
		| None -> " "
		| Some c -> if printable c then String.make 1 c else "."
		) chars in
		String.concat "" (hex @ ascii)

	let default_on_line_complete offset string =
		Printf.printf "%8x   %s\n" offset string

	let make
		?(terminal_width=80)
		?(on_line_complete=default_on_line_complete)
		?(start_of_line_offset_in_stream=0)
		() =
		let max_bytes_per_line = terminal_width / per_byte_overhead in
		(* round down to a power of 2 for sanity *)
		let bytes_per_line =
			let i = ref 1 in
			while !i lsl 1 < max_bytes_per_line do
				i := !i lsl 1
			done;
			!i in
		let accumulator = Array.create bytes_per_line None in
		let next_index = 0 in
		{ accumulator; bytes_per_line; next_index; on_line_complete;
		  start_of_line_offset_in_stream }

	let write_byte t x =
		t.accumulator.(t.next_index) <- x;
		if t.next_index = t.bytes_per_line - 1 then begin
			t.on_line_complete t.start_of_line_offset_in_stream (print_line t);
			t.start_of_line_offset_in_stream <- t.start_of_line_offset_in_stream + t.bytes_per_line;
		end;
		t.next_index <- (t.next_index + 1) mod t.bytes_per_line

	let write_cstruct t c =
		for i = 0 to Cstruct.len c - 1 do
			write_byte t (Some (Cstruct.get_char c i))
		done

	let write_string t s =
		for i = 0 to String.length s - 1 do
			write_byte t (Some s.[i])
		done

	let flush t =
		for i = t.next_index to t.bytes_per_line - 1 do
			t.accumulator.(i) <- None
		done;
		t.on_line_complete t.start_of_line_offset_in_stream (print_line t);
		for i = 0 to t.next_index - 1 do
			t.accumulator.(i) <- None
		done
end

let ring_size = 1024

let analyse ring =
	let input_cons = get_ring_input_cons ring in
	let input_prod = get_ring_input_prod ring in
	let output_cons = get_ring_output_cons ring in
	let output_prod = get_ring_output_prod ring in
	let input_cons' = Int32.to_int input_cons mod ring_size in
	let input_prod' = Int32.to_int input_prod mod ring_size in
	let output_cons' = Int32.to_int output_cons mod ring_size in
	let output_prod' = Int32.to_int output_prod mod ring_size in
	Printf.printf "replies to the guest\n";
	Printf.printf "====================\n";
	Printf.printf "* consumer = 0x%04lx (mod 0x%x = 0x%04x)\n"
		input_cons ring_size input_cons';
	Printf.printf "* producer = 0x%04lx (mod 0x%x = 0x%04x)\n"
		input_prod ring_size input_prod';
	let input_ba = Bigarray.(Array1.create char c_layout ring_size) in
	let input = Cstruct.of_bigarray input_ba in
	Cstruct.blit (get_ring_input ring) input_prod' input 0 (ring_size - input_prod');
	Cstruct.blit (get_ring_input ring) 0 input (ring_size - input_prod') input_prod';
	(* Cstruct.hexdump input; *)
	let scores = ref [] in
	for off = 0 to ring_size - 1 do
		let input' = Cstruct.shift input off in
		let n = count_packets input' in
		scores := (off, n) :: !scores
	done;
	match List.stable_sort (fun a b -> compare (snd b) (snd a)) !scores with
	| [] -> Printf.printf "Failed to discover any packet boundaries.\n"
	| (off, n) :: _ ->
		Printf.printf "* %d valid packets detected.\n" n;
		Printf.printf "* offset: producer (0x%04lx) + 0x%04x mod 0x%x = 0x%04lx mod 0x%x = 0x%04x\n\n" input_prod off ring_size (Int32.(add input_prod (of_int off))) ring_size ((Int32.to_int input_prod + off) mod ring_size);
		let preamble = Cstruct.sub input 0 off in
		let printer = HexPrinter.make () in
		HexPrinter.write_cstruct printer preamble;
		HexPrinter.flush printer;
		Printf.printf "-- remainder of overwritten old packet (%d bytes)\n\n" (Cstruct.len preamble);
		let packets = fold_over_packets (fun acc p -> p :: acc) [] (Cstruct.shift input off) in
		List.iter (fun p ->
			let open Xs_protocol in
			let d = get_data p in
			HexPrinter.write_string printer (to_string p);
			HexPrinter.flush printer;
			Printf.printf "-- rid = %08lx; tid = %08lx; %s len = %04d \"%s\"\n\n%!"
			(get_rid p) (get_tid p) (Op.to_string (get_ty p))
			(String.length d) (escape_string d);

		) packets;
		()

let _ =
(*
	let domid, mfn = 
		try int_of_string Sys.argv.(1), Nativeint.of_string Sys.argv.(2)
		with _ -> 0, Nativeint.zero
	in
	let ring = open_ring domid mfn in

	Printf.printf "input_cons = %ld input_prod = %ld output_cons = %ld output_prod = %ld\n" input_cons input_prod output_cons output_prod;

*)
	let ring = load_ring Sys.argv.(1) in
	analyse ring;
	(* for each direction *)
	(* consumed *)

	(* unconsumed *)


	()
(*
	let sz = Xenmmap.getpagesize () - 1024 - 512 in
	let intf = open_ring domid mfn in
	let s = Xenmmap.read intf 0 sz in
	let ss = (hexify s) in

	let req_cons = int_from_page ss (4*ring_size) in
	let req_prod = int_from_page ss (8 + 4*ring_size) in
	let rsp_cons = ring_size + int_from_page ss (16 + 4*ring_size) in
	let rsp_prod = ring_size + int_from_page ss (24 + 4*ring_size) in

	let ss2 = alpha ~req_cons ~req_prod ~rsp_cons ~rsp_prod s in

	Printf.printf "req-cons=%i \t req-prod=%i \t rsp-cons=%i \t rsp-prod=%i\n" req_cons req_prod (rsp_cons-ring_size) (rsp_prod-ring_size);

	Printf.printf "==== requests ====\n";
	for i = 0 to (sz / 64) - 1
	do
		if i = ring_size/64 then
			Printf.printf "==== replied ====\n";
		if i = 2*ring_size/64 then
			Printf.printf "==== other ====\n";

		let x = String.sub ss (i * 128) (128) in
		Printf.printf "%.4d " (i * 64);
		for j = 0 to (128 / 4) - 1
		do
			Printf.printf "%s " (String.sub x (j * 4) 4)
		done;
		Printf.printf "%s" (String.sub ss2 (i * 64) 64);
		Printf.printf "\n";
	done
*)
