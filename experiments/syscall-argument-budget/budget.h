/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ASSERVAT_ARGUMENT_BUDGET_H
#define ASSERVAT_ARGUMENT_BUDGET_H

/* Shared by every CPU and mount namespace of ONE admitted whole-pod session.
 * The loader must initialize once and freeze the map before attaching programs.
 * Zero initialization denies. No refill/reset API is part of this experiment. */
struct asservat_argument_budget {
	unsigned long long events_left;
	unsigned long long bytes_left;
	unsigned long long stopped;
	unsigned long long deadline_boot_ns;
	unsigned long long max_probe_bytes;
	unsigned long long rate_next_ns;
	unsigned long long rate_interval_ns;
	unsigned long long rate_burst_ns;
};

/* Atomic reads use CMPXCHG as well, so the host model has no C data races.
 * Bounded retries may stop early under contention; they never borrow capacity.
 * Do not use bpf_spin_lock: these are raw_tracepoint programs. */
static __inline__ __attribute__((always_inline)) int
asservat_take(unsigned long long *left, unsigned long long amount)
{
	unsigned long long before = __sync_val_compare_and_swap(left, 0, 0);
#ifdef __BPF__
#pragma unroll
#endif
	for (int i = 0; i < 8; i++) {
		if (!amount || before < amount)
			return 0;
		unsigned long long actual = __sync_val_compare_and_swap(
			left, before, before - amount);
		if (actual == before)
			return 1;
		before = actual;
	}
	return 0;
}

/* One shared virtual-time bucket. A probe advances by ceil(1s/rate); the
 * initial burst is rate probes. Excess stops, never sleeps or starts a new
 * window. All namespaces and CPUs share the same atomic next timestamp. */
static __inline__ __attribute__((always_inline)) int
asservat_take_rate(struct asservat_argument_budget *b, unsigned long long now)
{
	unsigned long long interval = b->rate_interval_ns;
	unsigned long long burst = b->rate_burst_ns;
	if (interval < 10000 || interval > 1000000000ULL ||
	    burst > 1000100000ULL || now > ~0ULL - burst - interval)
		return 0;
	unsigned long long before = __sync_val_compare_and_swap(&b->rate_next_ns, 0, 0);
#ifdef __BPF__
#pragma unroll
#endif
	for (int i = 0; i < 8; i++) {
		if (before > now + burst)
			return 0;
		unsigned long long next = (before > now ? before : now) + interval;
		unsigned long long actual = __sync_val_compare_and_swap(&b->rate_next_ns, before, next);
		if (actual == before)
			return 1;
		before = actual;
	}
	return 0;
}

/* Reserve the entire probe's worst-case reads BEFORE its first user-memory
 * helper. Event reservation is intentionally not refunded if bytes fail. */
static __inline__ __attribute__((always_inline)) int
asservat_reserve_probe(struct asservat_argument_budget *b,
		      unsigned long long bytes, unsigned long long boot_ns)
{
	if (!b)
		return 0;
	if (__sync_val_compare_and_swap(&b->stopped, 0, 0))
		return 0;
	if (!boot_ns || boot_ns >= b->deadline_boot_ns || bytes < 256 ||
	    bytes > 1792 || bytes > b->max_probe_bytes ||
	    !asservat_take_rate(b, boot_ns) || !asservat_take(&b->events_left, 1) ||
	    !asservat_take(&b->bytes_left, bytes)) {
		__sync_val_compare_and_swap(&b->stopped, 0, 1);
		return 0;
	}
	/* A concurrently refused probe may have stopped this session. Charges
	 * already taken remain spent even when this final check denies. */
	return !__sync_val_compare_and_swap(&b->stopped, 0, 0);
}
#endif
