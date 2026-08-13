------------------------ MODULE MailEdgeRegressions ------------------------
EXTENDS MailEdge

(***************************************************************************
Each action below is an intentionally broken implementation change.  The
regression runner selects one and requires TLC to produce a counterexample to
the corresponding unchanged safety invariant.
***************************************************************************)

CONSTANT Regression

OtherAdapter(adapter) ==
    IF adapter = "primary" THEN "fallback" ELSE "primary"

BadAmbiguousResend(i) ==
    /\ Regression = "ambiguous-resend"
    /\ deliveryStatus[i] = "unknown"
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "submitting"]
    /\ submitCount' = [submitCount EXCEPT ![i] = @ + 1]
    /\ submissionAdapter' =
        [submissionAdapter EXCEPT ![i] = OtherAdapter(frozenAdapter[i])]
    /\ adaptersUsed' =
        [adaptersUsed EXCEPT ![i] = @ \cup {OtherAdapter(frozenAdapter[i])}]
    /\ UNCHANGED <<deliveryLease, deliveryCrashCount, deliveryBlobPresent,
                    retryCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    submissionGeneration, deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

BadDuplicateEventApply(e) ==
    /\ Regression = "duplicate-event"
    /\ eventStatus[e] = "leased"
    /\ EventKey(e) \in processedEventKeys
    /\ eventStatus' = [eventStatus EXCEPT ![e] = "applied"]
    /\ eventLease' = [eventLease EXCEPT ![e] = NoLease]
    /\ eventApplyCount' =
        [eventApplyCount EXCEPT ![EventKey(e)] = @ + 1]
    /\ UNCHANGED <<eventCrashCount, processedEventKeys, appliedEventKeys>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars

BadDualActive(d, direction, new) ==
    /\ Regression = "dual-active-generation"
    /\ bindingPhase[d][direction][new] = "inactive"
    /\ bindingPhase' = [bindingPhase EXCEPT ![d][direction][new] = "active"]
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

BadRerouteSubmission(i, current) ==
    /\ Regression = "reroute-submission"
    /\ deliveryStatus[i] = "leased"
    /\ current \in ActiveGenerations(DeliveryDomain(i), "outbound")
    /\ AdapterFor(current) # frozenAdapter[i]
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "submitting"]
    /\ submitCount' = [submitCount EXCEPT ![i] = @ + 1]
    /\ submissionGeneration' = [submissionGeneration EXCEPT ![i] = current]
    /\ submissionAdapter' =
        [submissionAdapter EXCEPT ![i] = AdapterFor(current)]
    /\ adaptersUsed' =
        [adaptersUsed EXCEPT ![i] = @ \cup {AdapterFor(current)}]
    /\ UNCHANGED <<deliveryLease, deliveryCrashCount, deliveryBlobPresent,
                    retryCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

BadReinjectProcessedIngress(i) ==
    /\ Regression = "reinject-processed"
    /\ ingressStatus[i] = "processed"
    /\ ingressInjectionCount' = [ingressInjectionCount EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<ingressStatus, ingressLease, ingressCrashCount,
                    ingressBlobPresent, ingressGeneration>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

BadDefaultUnknownRoute(i) ==
    /\ Regression = "default-unknown-route"
    /\ DeliveryDomain(i) = UnknownDomain
    /\ deliveryStatus[i] = "new"
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "queued"]
    /\ frozenGeneration' = [frozenGeneration EXCEPT ![i] = 1]
    /\ frozenAdapter' = [frozenAdapter EXCEPT ![i] = AdapterFor(1)]
    /\ UNCHANGED <<deliveryLease, deliveryCrashCount, deliveryBlobPresent,
                    retryCount, submitCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, submissionGeneration, submissionAdapter,
                    adaptersUsed, deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

BadEarlyBlobDelete(i) ==
    /\ Regression = "early-blob-delete"
    /\ deliveryStatus[i] = "queued"
    /\ deliveryBlobPresent[i]
    /\ deliveryBlobPresent' = [deliveryBlobPresent EXCEPT ![i] = FALSE]
    /\ UNCHANGED <<deliveryStatus, deliveryLease, deliveryCrashCount,
                    retryCount, submitCount, ambiguitySeen,
                    ambiguitySubmitCount, ambiguityCause, frozenGeneration,
                    frozenAdapter, submissionGeneration, submissionAdapter,
                    adaptersUsed, deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

RegressionAction ==
    \/ \E i \in Deliveries : BadAmbiguousResend(i)
    \/ \E e \in Events : BadDuplicateEventApply(e)
    \/ \E d \in KnownDomains, direction \in Directions,
          new \in Generations : BadDualActive(d, direction, new)
    \/ \E i \in Deliveries, current \in Generations :
          BadRerouteSubmission(i, current)
    \/ \E i \in IngressItems : BadReinjectProcessedIngress(i)
    \/ \E i \in Deliveries : BadDefaultUnknownRoute(i)
    \/ \E i \in Deliveries : BadEarlyBlobDelete(i)

RegressionNext == Next \/ RegressionAction
RegressionSpec == Init /\ [][RegressionNext]_vars

=============================================================================
