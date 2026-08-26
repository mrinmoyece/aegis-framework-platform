# Durable freshness response

Compare accepted ledger cursor, outbox status, Temporal task queue, and projection
checkpoint. Reclaim only expired claims with the same operation identity. Verify both
hash chains before rebuilding.
