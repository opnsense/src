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

46 logoX ! 9 logoY ! \ Initialize logo placement defaults

: logo+ ( x y c-addr/u -- x y' )
	2swap 2dup at-xy 2swap \ position the cursor
	type \ print to the screen
	1+ \ increase y for next time we're called
;

: logo ( x y -- ) \ B/W HardenedBSD mascot (15 rows x 33 columns)

	s" uKOS2qsmkfe38kEuXLimP+7XoBiuIt5k" logo+
	s" BMHardenedBSDxfOL9QwvfA6yxGHkNMG" logo+
	s" 2I7ADmw7Mp/P8Y4wjnBFDNKvNzdZa/uu" logo+
	s" 7jx0/j28DcHs1oTUiFxDezXj0+bYBAjk" logo+
	s" M/WeI4vOFPUZQcUiqAhCItlLY/1/YsdU" logo+
	s" bYCu3JOWsOA/Ctw0oVmHA+jY6Z8RJnsT" logo+
	s" NTm3YVdJVYQ+O2ltoSwHardenedBSDVD" logo+
	s" vji9p89gQvsPgS9hh9ekUCw/0TnSeQ1W" logo+
	s" NHcmBLfiNO7mU9D4rCxiSQfifcIZzC78" logo+
	s" uwaNYp+XGq+qEt7pQ+aX2nsJ2juBCGai" logo+
	s" fTclPrFDFBNSqyrmOEI3Lrkn3eudPbJU" logo+
	s" NlHardenedBSDvCOXT59dcSRw9mB3bOl" logo+
	s" gEcyCwdlh1xWKOu9qGWcmsAhOVReHec4" logo+

	2drop
;
