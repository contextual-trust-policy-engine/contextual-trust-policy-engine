---- MODULE DenyByDefault ----
EXTENDS Naturals, FiniteSets, TLC
CONSTANTS Agents, TTL, MaxTime
VARIABLES now, svid, attest, abac, rebac, trust, revoked, cache
vars == <<now, svid, attest, abac, rebac, trust, revoked, cache>>
CacheRec == [agent: Agents, ok: BOOLEAN, expiry: 0..(MaxTime + TTL)]
Good(a) == svid[a] /\ attest[a] /\ abac[a] /\ rebac[a] /\ trust[a] /\ ~revoked[a]
Init == /\ now = 0 /\ svid \in [Agents -> BOOLEAN] /\ attest \in [Agents -> BOOLEAN] /\ abac \in [Agents -> BOOLEAN] /\ rebac \in [Agents -> BOOLEAN] /\ trust \in [Agents -> BOOLEAN] /\ revoked = [a \in Agents |-> FALSE] /\ cache = {}
Decide(a) == /\ Good(a) /\ cache' = cache \cup {[agent |-> a, ok |-> TRUE, expiry |-> now + TTL]} /\ UNCHANGED <<now, svid, attest, abac, rebac, trust, revoked>>
Deny(a) == /\ ~Good(a) /\ cache' = cache \cup {[agent |-> a, ok |-> FALSE, expiry |-> now]} /\ UNCHANGED <<now, svid, attest, abac, rebac, trust, revoked>>
TrustDrop(a) == /\ trust[a] /\ trust' = [trust EXCEPT ![a] = FALSE] /\ UNCHANGED <<now, svid, attest, abac, rebac, revoked, cache>>
Revoke(a) == /\ ~revoked[a] /\ revoked' = [revoked EXCEPT ![a] = TRUE] /\ UNCHANGED <<now, svid, attest, abac, rebac, trust, cache>>
Advance == /\ now < MaxTime /\ now' = now + 1 /\ cache' = {c \in cache: now' <= c.expiry} /\ UNCHANGED <<svid, attest, abac, rebac, trust, revoked>>
Next == Advance \/ \E a \in Agents: Decide(a) \/ Deny(a) \/ TrustDrop(a) \/ Revoke(a)
TypeOK == /\ now \in 0..MaxTime /\ svid \in [Agents -> BOOLEAN] /\ attest \in [Agents -> BOOLEAN] /\ abac \in [Agents -> BOOLEAN] /\ rebac \in [Agents -> BOOLEAN] /\ trust \in [Agents -> BOOLEAN] /\ revoked \in [Agents -> BOOLEAN] /\ cache \subseteq CacheRec
AllowImpliesCachedDecisionOK == \A c \in cache: c.ok => c.expiry <= now + TTL
NoCachedAllowBeyondTTLAfterRevocation == \A a \in Agents: revoked[a] => ~\E c \in cache: c.agent = a /\ c.ok /\ now > c.expiry
Spec == Init /\ [][Next]_vars
====
