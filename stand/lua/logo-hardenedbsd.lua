--
-- SPDX-License-Identifier: BSD-2-Clause-FreeBSD
--
-- Copyright (c) 2018 Oliver Pinter <oliver.pinter@HardenedBSD.org>
--
-- Redistribution and use in source and binary forms, with or without
-- modification, are permitted provided that the following conditions
-- are met:
-- 1. Redistributions of source code must retain the above copyright
--    notice, this list of conditions and the following disclaimer.
-- 2. Redistributions in binary form must reproduce the above copyright
--    notice, this list of conditions and the following disclaimer in the
--    documentation and/or other materials provided with the distribution.
--
-- THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
-- ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
-- IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
-- ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
-- FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
-- DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
-- OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
-- HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
-- LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
-- OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
-- SUCH DAMAGE.
--
-- $FreeBSD$
--

local drawer = require("drawer")

local hardenedbsd_color = {
"\027[muKOS2qsmkfe38kEuXLimP+7XoBiuIt5k",
"BM\027[36mHardened\027[34mBSD\027[mxfOL9QwvfA6yxGHkNMG",
"2I7ADmw7Mp/P8Y4wjnBFDNKvNzdZa/uu",
"7jx0/j28DcHs1oTUiFxDezXj0+bYBAjk",
"M/WeI4vOFPUZQcUiqAhCItlLY/1/YsdU",
"bYCu3JOWsOA/Ctw0oVmHA+jY6Z8RJnsT",
"NTm3YVdJVYQ+O2ltoSw\027[36mHardened\027[34mBSD\027[mVD",
"vji9p89gQvsPgS9hh9ekUCw/0TnSeQ1W",
"NHcmBLfiNO7mU9D4rCxiSQfifcIZzC78",
"uwaNYp+XGq+qEt7pQ+aX2nsJ2juBCGai",
"fTclPrFDFBNSqyrmOEI3Lrkn3eudPbJU",
"Nl\027[36mHardened\027[34mBSD\027[mvCOXT59dcSRw9mB3bOl",
"gEcyCwdlh1xWKOu9qGWcmsAhOVReHec4"
}

drawer.addLogo("hardenedbsd", {
	requires_color = true,
	graphic = hardenedbsd_color,
	shift = {x = 1, y = 5},
})

return true
