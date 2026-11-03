/* SPDX-License-Identifier: GPL-2.0 */
#include "budget.h"
/* Compile-only ISA probe, NEVER loaded: proves the compiler emits atomics,
 * not that the Linux verifier accepts the full patched traceloop program. */
int budget_isa_probe(struct asservat_argument_budget *budget)
{
	return asservat_reserve_probe(budget, 512, 1);
}
