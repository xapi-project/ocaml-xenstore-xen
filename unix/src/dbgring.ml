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

cstruct ring {
	uint8_t output[1024];
	uint8_t input[1024];
	uint32_t output_cons;
	uint32_t output_prod;
	uint32_t input_cons;
	uint32_t input_prod
} as little_endian

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

let consumed cons prod len = match compare cons prod with
	| 0  -> if cons = 0
		then [ 0, len ]
		else [ prod, len - prod; 0, prod ]
	| -1 -> if (prod - cons) = len
		then []
		else [ prod, len - prod; 0, cons ]
	| 1  -> if (cons - prod) = len
		then [ 0, len ]
		else [ prod, cons - prod ]

let invert len xs =
	snd (List.fold_left (fun (start, acc) (next, next_l) ->
		next + next_l, (if start = next then acc else (start, next - start) :: acc)
	) (0, []) (xs @ [ len, 0 ]))

let size xs = List.fold_left (fun acc (_, l) -> acc + l) 0 xs

let _ =
	let domid, mfn = 
		try int_of_string Sys.argv.(1), Nativeint.of_string Sys.argv.(2)
		with _ -> 0, Nativeint.zero
	in
	let ring = open_ring domid mfn in
	let input_cons = get_ring_input_cons ring in
	let input_prod = get_ring_input_prod ring in
	let output_cons = get_ring_output_cons ring in
	let output_prod = get_ring_output_prod ring in
	Printf.printf "input_cons = %ld input_prod = %ld output_cons = %ld output_prod = %ld\n" input_cons input_prod output_cons output_prod;

	let f = Unix.openfile "/tmp/ring.dump" [ Unix.O_WRONLY; Unix.O_CREAT ] 0o644 in
	let s = String.make 4096 '\000' in
	Cstruct.blit_to_string ring 0 s 0 (String.length s);
	Unix.write f s 0 (String.length s);
	Unix.close f;

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
