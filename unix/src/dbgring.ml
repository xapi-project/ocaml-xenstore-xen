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
	let one_direction cons prod ring =
		let cons' = Int32.to_int cons mod ring_size in
		let prod' = Int32.to_int prod mod ring_size in
		Printf.printf "* consumer = 0x%04lx (mod 0x%x = 0x%04x)\n"
			cons ring_size cons';
		Printf.printf "* producer = 0x%04lx (mod 0x%x = 0x%04x)\n"
			prod ring_size prod';
		let bytes_ba = Bigarray.(Array1.create char c_layout ring_size) in
		let bytes = Cstruct.of_bigarray bytes_ba in
		Cstruct.blit ring prod' bytes 0 (ring_size - prod');
		Cstruct.blit ring 0 bytes (ring_size - prod') prod';
		let scores = ref [] in
		for off = 0 to ring_size - 1 do
			let bytes' = Cstruct.shift bytes off in
			let n = count_packets bytes' in
			scores := (off, n) :: !scores
		done;
		match List.stable_sort (fun a b -> compare (snd b) (snd a)) !scores with
		| [] -> Printf.printf "Failed to discover any packet boundaries.\n"
		| (off, n) :: _ ->
			Printf.printf "* %d valid packets detected.\n" n;
			Printf.printf "* offset: producer (0x%04lx) + 0x%04x mod 0x%x = 0x%04lx mod 0x%x = 0x%04x\n\n" prod off ring_size (Int32.(add prod (of_int off))) ring_size ((Int32.to_int prod + off) mod ring_size);
			let preamble = Cstruct.sub bytes 0 off in
			let printer = HexPrinter.make () in
			HexPrinter.write_cstruct printer preamble;
			HexPrinter.flush printer;
			Printf.printf "-- remainder of overwritten old packet (%d bytes)\n\n" (Cstruct.len preamble);
			let packets = fold_over_packets (fun acc p -> p :: acc) [] (Cstruct.shift bytes off) in
			let total_packet_length = List.fold_left (+) 0 (List.map (fun x -> String.length (Xs_protocol.get_data x) + sizeof_header) packets) in
			let postamble = Cstruct.shift bytes (off + total_packet_length) in
			List.iter (fun p ->
				let open Xs_protocol in
				let d = get_data p in
				HexPrinter.write_string printer (to_string p);
				HexPrinter.flush printer;
				Printf.printf "-- rid = %08lx; tid = %08lx; %s len = %04d \"%s\"\n\n%!"
				(get_rid p) (get_tid p) (Op.to_string (get_ty p))
				(String.length d) (escape_string d);

			) packets;
			HexPrinter.write_cstruct printer postamble;
			HexPrinter.flush printer;
			Printf.printf "-- partially written new packets (%d bytes)\n\n" (Cstruct.len postamble);
			(* Need to highlight consumer pointer position *)
			() in

	let input_cons = get_ring_input_cons ring in
	let input_prod = get_ring_input_prod ring in
	let output_cons = get_ring_output_cons ring in
	let output_prod = get_ring_output_prod ring in
	Printf.printf "replies to the guest\n";
	Printf.printf "====================\n";
	one_direction input_cons input_prod (get_ring_input ring);
	Printf.printf "requests from the guest\n";
	Printf.printf "=======================\n";
	one_direction output_cons output_prod (get_ring_output ring)

let dump domid filename =
	Printf.fprintf stderr "attempting to map ring for domid %d\n" domid;
	let ring =
		if domid = 0
		then open_ring0 ()
		else
			let module Client = Xs_client_unix.Client(Xs_transport_unix_client) in
			let client = Client.make () in
			let mfn = Client.with_xs client (fun h -> Client.read h (Printf.sprintf "/local/domain/%d/store/ring-ref" domid)) in
			Printf.fprintf stderr "store mfn = %s\n" mfn;
			open_ringU domid (Nativeint.of_string mfn) in
	Printf.fprintf stderr "saving to %s\n" filename;
	save_ring ring filename;
	`Ok ()

let analyse filename =
	let ring = load_ring filename in
	analyse ring;
	`Ok ()

let project_url = "http://github.com/djs55/ocaml-xenstore-xen"

open Cmdliner

module Common = struct
	type t = bool
	let make x = x
end

let _common_options = "COMMON OPTIONS"

(* Options common to all commands *)
let common_options_t = 
	let docs = _common_options in 
	let debug = 
		let doc = "Give only debug output." in
		Arg.(value & flag & info ["debug"] ~docs ~doc) in
	Term.(pure Common.make $ debug)

let help = [
	`S _common_options;
	`P "These options are common to all commands.";
	`S "MORE HELP";
	`P "Use `$(mname) $(i,COMMAND) --help' for help on a single command."; `Noblank;
	`S "BUGS"; `P (Printf.sprintf "Check bug reports at %s" project_url);
]

let dump_cmd =
	let doc = "save a snapshot of a domain's xenstore ring to disk" in
	let man = [
		`S "DESCRIPTION";
		`P "Maps an existing domain's xenstore ring and save a snapshot to disk for offline analysis.";
	] in
	let domid =
		let doc = "Domain id to snapshot" in
		Arg.(value & pos 0 int 0 & info [] ~doc) in
	let filename =
		let doc = "Path to save the snapshot to" in
		Arg.(value & pos 1 string "ring.dump" & info [] ~doc) in
	Term.(ret(pure dump $ domid $ filename)),
	Term.info "dump" ~sdocs:_common_options ~doc ~man

let analyse_cmd =
	let doc = "analyse a snapshot of a xenstore ring" in
	let man = [
		`S "DESCRIPTION";
		`P "Loads a ring snapshot from disk and prints an analysis of its contents.";
	] in
	let filename =
		let doc = "Path of saved snapshot" in
		Arg.(value & pos 0 file "ring.dump" & info [] ~doc) in
	Term.(ret(pure analyse $ filename)),
	Term.info "analyse" ~sdocs:_common_options ~doc ~man

let default_cmd = 
	let doc = "analyse xenstore rings" in 
	let man = help in
	Term.(ret (pure (fun _ -> `Help (`Pager, None)) $ common_options_t)),
	Term.info "dbgring" ~version:"1.0.0" ~sdocs:_common_options ~doc ~man
       
let cmds = [ dump_cmd; analyse_cmd ]

let _ =
	match Term.eval_choice default_cmd cmds with
	| `Error _ -> exit 1
	| _ -> exit 0

