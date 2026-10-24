# native69 — approved query admitted, worker audited/Job/bound, request expired at permit

First get_file_excerpt admitted the query and launched/bound the shared worker,
then re-ran the full SQL fence (PermitQuery) while the worker Pod was still
enrolling and refused at `prepare/permit/topology` with <1 s left. The pending
reply now skips the permit; it runs before a read.
