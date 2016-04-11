/*
 * Copyright (c) 2015, ARM Limited and Contributors. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of ARM nor the names of its contributors may be used
 * to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "tbbr/tbb_key.h"

/*
 * Keys used to establish the chain of trust
 *
 * The order of the keys must follow the enumeration specified in tbb_key.h
 */
static key_t tbb_keys[] = {
	[ROT_KEY] = {
		.id = ROT_KEY,
		.opt = "rot-key",
		.help_msg = "Root Of Trust key (input/output file)",
		.desc = "Root Of Trust key"
	},
	[TRUSTED_WORLD_KEY] = {
		.id = TRUSTED_WORLD_KEY,
		.opt = "trusted-world-key",
		.help_msg = "Trusted World key (input/output file)",
		.desc = "Trusted World key"
	},
	[NON_TRUSTED_WORLD_KEY] = {
		.id = NON_TRUSTED_WORLD_KEY,
		.opt = "non-trusted-world-key",
		.help_msg = "Non Trusted World key (input/output file)",
		.desc = "Non Trusted World key"
	},
	[SCP_FW_CONTENT_CERT_KEY] = {
		.id = SCP_FW_CONTENT_CERT_KEY,
		.opt = "scp-fw-key",
		.help_msg = "SCP Firmware Content Certificate key (input/output file)",
		.desc = "SCP Firmware Content Certificate key"
	},
	[SOC_FW_CONTENT_CERT_KEY] = {
		.id = SOC_FW_CONTENT_CERT_KEY,
		.opt = "soc-fw-key",
		.help_msg = "SoC Firmware Content Certificate key (input/output file)",
		.desc = "SoC Firmware Content Certificate key"
	},
	[TRUSTED_OS_FW_CONTENT_CERT_KEY] = {
		.id = TRUSTED_OS_FW_CONTENT_CERT_KEY,
		.opt = "tos-fw-key",
		.help_msg = "Trusted OS Firmware Content Certificate key (input/output file)",
		.desc = "Trusted OS Firmware Content Certificate key"
	},
	[NON_TRUSTED_FW_CONTENT_CERT_KEY] = {
		.id = NON_TRUSTED_FW_CONTENT_CERT_KEY,
		.opt = "nt-fw-key",
		.help_msg = "Non Trusted Firmware Content Certificate key (input/output file)",
		.desc = "Non Trusted Firmware Content Certificate key"
	}
};

REGISTER_KEYS(tbb_keys);
