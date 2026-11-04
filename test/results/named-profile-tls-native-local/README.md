# Named profile TLS: local native-fixture preparation

The signed fixture patch `c64e5b1ff9bfa9a8ebc325e32067d6f09c02339d`
was cherry-picked as `ff41e19263f87cb3cf635bc7130ecf3e810ffa8e`.
Stable patch IDs and all fourteen changed file hashes match. This preparation
adds one independently approved TLS CPU capture and one separately approved
wrong-server-name refusal to the existing installed fixture; it changes no
product code, permissions, resource ceilings or 18m/20m limits.

Local fixture/component races and all 35 selector tests pass. The original
unknown-alias RED and initial fixture compile failure are retained explicitly.
The ten original logs and handoff are deterministically compressed and read back
byte-for-byte. The handoff distinguishes earlier affected checks from the final
TLS check after adding only public certificate fingerprint logging.

These are local tests using synthetic app keys, Kubernetes doubles and existing
capacity compilers. No installed TLS run occurred. Actual node/netns handshake,
publication, native download and wrong-peer zero-GET/retained-spend qualification
remain pending. CPU expiry/busy/missing/Stop and heap/trace/browser/heavy paths are
not newly qualified under TLS. Core preflight evidence is in the separate
`named-profile-tls-core-local` archive and predates this fixture addition.
