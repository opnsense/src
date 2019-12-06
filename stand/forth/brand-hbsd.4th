\ Copyright (c) 2006-2015 Devin Teske <dteske@FreeBSD.org>
\ Copyright (c) 2015-2016 Oliver Pinter <op@HardenedBSD.org>
\ All rights reserved.
\ 
\ Redistribution and use in source and binary forms, with or without
\ modification, are permitted provided that the following conditions
\ are met:
\ 1. Redistributions of source code must retain the above copyright
\    notice, this list of conditions and the following disclaimer.
\ 2. Redistributions in binary form must reproduce the above copyright
\    notice, this list of conditions and the following disclaimer in the
\    documentation and/or other materials provided with the distribution.
\ 
\ THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
\ ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
\ IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
\ ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
\ FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
\ DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
\ OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
\ HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
\ LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
\ OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
\ SUCH DAMAGE.
\ 
\ $FreeBSD$

7 brandX ! 1 brandY ! \ Initialize brand placement defaults

: brand+ ( x y c-addr/u -- x y' )
	2swap 2dup at-xy 2swap \ position the cursor
	type \ print to the screen
	1+ \ increase y for next time we're called
;

: brand ( x y -- ) \ "FreeBSD" [wide] logo in B/W (6 rows x 67 columns)

	s"  _    _               _                     _ ____   _____ _____  " brand+
	s" | |  | |             | |                   | |  _ \ / ____|  __ \ " brand+
	s" | |__| | __ _ _ __ __| | ___ _ __   ___  __| | |_) | (___ | |  | |" brand+
	s" |  __  |/ _` | '__/ _` |/ _ \ '_ \ / _ \/ _` |  _ < \___ \| |  | |" brand+
	s" | |  | | (_| | | | (_| |  __/ | | |  __/ (_| | |_) |____) | |__| |" brand+
	s" |_|  |_|\__,_|_|  \__,_|\___|_| |_|\___|\__,_|____/|_____/|_____/ " brand+

	2drop
;

