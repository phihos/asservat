/* SPDX-License-Identifier: GPL-2.0 */
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include "budget.h"

static struct asservat_argument_budget new_budget(unsigned long long events,
						 unsigned long long bytes)
{
	return (struct asservat_argument_budget){events, bytes, 0, 1000, 1792, 0, 10000, 999990000};
}

static void boundaries(void)
{
	struct asservat_argument_budget b = new_budget(2, 768);
	assert(asservat_reserve_probe(&b, 512, 1));
	assert(b.events_left == 1 && b.bytes_left == 256);
	assert(asservat_reserve_probe(&b, 256, 999));
	assert(!asservat_reserve_probe(&b, 256, 999));
	assert(b.events_left == 0 && b.bytes_left == 0 && b.stopped == 1);
	/* A failed byte debit consumes the event, never wraps bytes or refunds. */
	b = new_budget(2, 511);
	assert(!asservat_reserve_probe(&b, 512, 1));
	assert(b.events_left == 1 && b.bytes_left == 511 && b.stopped == 1);
	assert(!asservat_reserve_probe(&b, 256, 1));
	/* Namespace addition does not reset b; every source uses this same cell. */
	b = new_budget(1, 512);
	assert(asservat_reserve_probe(&b, 256, 1));
	assert(!asservat_reserve_probe(&b, 256, 1));
	b = new_budget(ULLONG_MAX, ULLONG_MAX);
	assert(asservat_reserve_probe(&b, 1792, 1));
	assert(b.events_left == ULLONG_MAX - 1 && b.bytes_left == ULLONG_MAX - 1792);
	assert(!asservat_reserve_probe(&b, 1793, 1));
	assert(!asservat_reserve_probe(NULL, 256, 1));
	b = (struct asservat_argument_budget){0};
	assert(!asservat_reserve_probe(&b, 256, 1));
	b = new_budget(2, 512);
	assert(!asservat_reserve_probe(&b, 256, 1000));
	assert(b.events_left == 2 && b.bytes_left == 512);
	b = new_budget(2, 512);
	b.max_probe_bytes = 256;
	assert(!asservat_reserve_probe(&b, 512, 1));
	assert(b.events_left == 2 && b.bytes_left == 512);
}

static void rate_boundaries(void)
{
	struct asservat_argument_budget b = new_budget(1000, 1000000);
	b.deadline_boot_ns = 100000000000ULL;
	b.rate_interval_ns = 333333334; /* rate=3, rounded DOWN throughput */
	b.rate_burst_ns = 2 * b.rate_interval_ns;
	assert(asservat_reserve_probe(&b, 256, 1));
	assert(asservat_reserve_probe(&b, 256, 1));
	assert(asservat_reserve_probe(&b, 256, 1));
	assert(!asservat_reserve_probe(&b, 256, 1));
	assert(b.events_left == 997 && b.bytes_left == 1000000 - 3*256);
	/* Idle time cannot restart an exhausted/stopped instance. */
	assert(!asservat_reserve_probe(&b, 256, 1000000001));
	b = new_budget(1000, 1000000);
	b.deadline_boot_ns = 100000000000ULL;
	b.rate_interval_ns = 1000000000;
	b.rate_burst_ns = 0; /* one probe per second, burst one */
	assert(asservat_reserve_probe(&b, 256, 1));
	assert(asservat_reserve_probe(&b, 256, 1000000001));
	assert(!asservat_reserve_probe(&b, 256, 1000000001));
	b = new_budget(1000, 1000000);
	b.deadline_boot_ns = ~0ULL;
	assert(!asservat_reserve_probe(&b, 256, ~0ULL - 100));
	assert(b.events_left == 1000);
}

static struct asservat_argument_budget shared;
static unsigned long long admitted, charged, reads;
static pthread_barrier_t barrier;
static void *race(void *unused)
{
	(void)unused;
	pthread_barrier_wait(&barrier);
	for (int n = 0; n < 10000; n++) {
		unsigned long long cost = 256 + (n % 7) * 256;
		if (asservat_reserve_probe(&shared, cost, 1)) {
			/* A synthetic helper counter, not evidence of actual kernel reads. */
			__sync_fetch_and_add(&admitted, 1);
			__sync_fetch_and_add(&charged, cost);
			__sync_fetch_and_add(&reads, cost - 256);
		}
	}
	return NULL;
}

int main(void)
{
	boundaries();
	rate_boundaries();
	unsigned long long minimum = ULLONG_MAX, maximum = 0;
	for (int iteration = 0; iteration < 30; iteration++) {
		pthread_t workers[16];
		shared = new_budget(10000, 2000000);
		admitted = charged = reads = 0;
		assert(!pthread_barrier_init(&barrier, NULL, 16));
		for (int n = 0; n < 16; n++) assert(!pthread_create(&workers[n], NULL, race, NULL));
		for (int n = 0; n < 16; n++) assert(!pthread_join(workers[n], NULL));
		assert(!pthread_barrier_destroy(&barrier));
		assert(admitted > 0 && admitted <= 10000);
		assert(charged <= 2000000);
		assert(reads + admitted * 256 == charged);
		assert(admitted <= 10000 - shared.events_left);
		assert(charged <= 2000000 - shared.bytes_left);
		assert(shared.events_left <= 10000 && shared.bytes_left <= 2000000);
		if (admitted < minimum) minimum = admitted;
		if (admitted > maximum) maximum = admitted;
	}
	/* Same initial timestamp, many CPUs: no fixed-window rollover or
	 * per-CPU burst can admit more than the single shared64-probe burst. */
	{
		pthread_t workers[16];
		shared = new_budget(10000, 2000000);
		shared.rate_interval_ns = 15625000;
		shared.rate_burst_ns = 63 * shared.rate_interval_ns;
		admitted = charged = reads = 0;
		assert(!pthread_barrier_init(&barrier, NULL, 16));
		for (int n = 0; n < 16; n++) assert(!pthread_create(&workers[n], NULL, race, NULL));
		for (int n = 0; n < 16; n++) assert(!pthread_join(workers[n], NULL));
		assert(!pthread_barrier_destroy(&barrier));
		assert(admitted > 0 && admitted <= 64);
		assert(10000 - shared.events_left <= 64 && shared.stopped == 1);
	}
	printf("Host race admitted probes: min=%llu max=%llu; early contention stop is permitted\n", minimum, maximum);
	puts("PASS: boundary checks and 30 x 16-thread shared-budget races (host C model only)");
}
