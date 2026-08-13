------------------------------ MODULE MailEdge ------------------------------
EXTENDS Naturals, FiniteSets, TLC

(***************************************************************************
The model is intentionally provider-neutral.  It describes the durable
reducers and versioned bindings at the modular mail edge, not SMTP, MIME, or
any provider API.

The constants are finite TLC bounds.  Item zero is reserved as "not found";
known domains, generations, ingress items, deliveries, and events start at 1.
***************************************************************************)

CONSTANTS
    DomainCount,
    GenerationCount,
    IngressCount,
    DeliveryCount,
    EventCount,
    IncludeUnknownItems,
    IncludeUnknownEvent,
    MaxCrashes,
    MaxRetries,
    AllowAmbiguity

ASSUME
    /\ DomainCount \in Nat \ {0}
    /\ GenerationCount \in Nat \ {0}
    /\ IngressCount \in Nat \ {0}
    /\ DeliveryCount \in Nat \ {0}
    /\ EventCount \in Nat \ {0}
    /\ MaxCrashes \in Nat
    /\ MaxRetries \in Nat
    /\ IncludeUnknownItems \in BOOLEAN
    /\ IncludeUnknownEvent \in BOOLEAN
    /\ AllowAmbiguity \in BOOLEAN

KnownDomains == 1..DomainCount
UnknownDomain == 0
DomainSpace == KnownDomains \cup {UnknownDomain}
Directions == {"inbound", "outbound"}
Generations == 1..GenerationCount
IngressItems == 1..IngressCount
Deliveries == 1..DeliveryCount
Events == 1..EventCount

Adapters == {"primary", "fallback"}
NoAdapter == "no-adapter"
NoGeneration == 0
NoLease == "no-lease"
WorkerLease == "worker-lease"
NoDelivery == 0

BindingPhases == {"inactive", "active", "draining", "retired"}
IngressStates == {"new", "queued", "leased", "processed", "quarantined", "rejected"}
DeliveryStates ==
    {"new", "queued", "leased", "submitting", "unknown",
     "accepted", "rejected", "quarantined"}
EventStates == {"new", "queued", "leased", "applied", "duplicate", "quarantined"}
AmbiguityCauses == {"none", "smtp-data-ack-lost", "provider-submission-timeout"}
FeedbackKinds == {"delayed", "delivered", "hard-bounce"}

IngressDefinitive == {"processed", "quarantined", "rejected"}
DeliveryDefinitive == {"accepted", "rejected", "quarantined"}
EventDefinitive == {"applied", "duplicate", "quarantined"}

IngressDomain(i) ==
    IF IncludeUnknownItems /\ i = IngressCount
    THEN UnknownDomain
    ELSE 1 + ((i - 1) % DomainCount)

DeliveryDomain(i) ==
    IF IncludeUnknownItems /\ i = DeliveryCount
    THEN UnknownDomain
    ELSE 1 + ((i - 1) % DomainCount)

AdapterFor(g) == IF g % 2 = 1 THEN "primary" ELSE "fallback"

(***************************************************************************
Event 3 deliberately reuses event 1's provider ID in dedupe configurations.
Events 1 and 2 are delayed and delivered feedback for the same delivery, so
TLC explores both arrival orders.  An optional final event is uncorrelated.
***************************************************************************)
EventKey(e) == IF ~IncludeUnknownEvent /\ e = 3 THEN 1 ELSE e
EventKeys == {EventKey(e) : e \in Events}
EventKind(e) ==
    CASE EventKey(e) = 1 -> "delayed"
      [] EventKey(e) = 2 -> "delivered"
      [] OTHER -> "hard-bounce"
EventDelivery(e) ==
    IF IncludeUnknownEvent /\ e = EventCount
    THEN NoDelivery
    ELSE 1 + ((EventKey(e) - 1) % DeliveryCount)

VARIABLES
    bindingPhase,

    ingressStatus,
    ingressLease,
    ingressCrashCount,
    ingressBlobPresent,
    ingressInjectionCount,
    ingressGeneration,

    deliveryStatus,
    deliveryLease,
    deliveryCrashCount,
    deliveryBlobPresent,
    retryCount,
    submitCount,
    ambiguitySeen,
    ambiguitySubmitCount,
    ambiguityCause,
    frozenGeneration,
    frozenAdapter,
    submissionGeneration,
    submissionAdapter,
    adaptersUsed,
    deliveryFeedback,

    eventStatus,
    eventLease,
    eventCrashCount,
    processedEventKeys,
    appliedEventKeys,
    eventApplyCount

bindingVars == <<bindingPhase>>
ingressVars ==
    <<ingressStatus, ingressLease, ingressCrashCount, ingressBlobPresent,
      ingressInjectionCount, ingressGeneration>>
deliveryVars ==
    <<deliveryStatus, deliveryLease, deliveryCrashCount, deliveryBlobPresent,
      retryCount, submitCount, ambiguitySeen, ambiguitySubmitCount,
      ambiguityCause, frozenGeneration, frozenAdapter, submissionGeneration,
      submissionAdapter, adaptersUsed, deliveryFeedback>>
eventVars ==
    <<eventStatus, eventLease, eventCrashCount, processedEventKeys,
      appliedEventKeys, eventApplyCount>>
vars == <<bindingPhase,
          ingressStatus, ingressLease, ingressCrashCount, ingressBlobPresent,
          ingressInjectionCount, ingressGeneration,
          deliveryStatus, deliveryLease, deliveryCrashCount,
          deliveryBlobPresent, retryCount, submitCount, ambiguitySeen,
          ambiguitySubmitCount, ambiguityCause, frozenGeneration,
          frozenAdapter, submissionGeneration, submissionAdapter, adaptersUsed,
          deliveryFeedback,
          eventStatus, eventLease, eventCrashCount, processedEventKeys,
          appliedEventKeys, eventApplyCount>>

ActiveGenerations(d, direction) ==
    {g \in Generations : bindingPhase[d][direction][g] = "active"}

HasActiveGeneration(d, direction) ==
    d \in KnownDomains /\ ActiveGenerations(d, direction) # {}

ActiveGeneration(d, direction) ==
    CHOOSE g \in Generations : bindingPhase[d][direction][g] = "active"

IngressOutstanding(d, g) ==
    \E i \in IngressItems :
        /\ IngressDomain(i) = d
        /\ ingressGeneration[i] = g
        /\ ingressStatus[i] \notin IngressDefinitive

DeliveryOutstanding(d, g) ==
    \E i \in Deliveries :
        /\ DeliveryDomain(i) = d
        /\ frozenGeneration[i] = g
        /\ deliveryStatus[i] \notin DeliveryDefinitive

GenerationOutstanding(d, direction, g) ==
    IF direction = "inbound"
    THEN IngressOutstanding(d, g)
    ELSE DeliveryOutstanding(d, g)

Init ==
    /\ bindingPhase =
        [d \in KnownDomains |->
            [direction \in Directions |->
                [g \in Generations |-> IF g = 1 THEN "active" ELSE "inactive"]]]

    /\ ingressStatus = [i \in IngressItems |-> "new"]
    /\ ingressLease = [i \in IngressItems |-> NoLease]
    /\ ingressCrashCount = [i \in IngressItems |-> 0]
    /\ ingressBlobPresent = [i \in IngressItems |-> TRUE]
    /\ ingressInjectionCount = [i \in IngressItems |-> 0]
    /\ ingressGeneration = [i \in IngressItems |-> NoGeneration]

    /\ deliveryStatus = [i \in Deliveries |-> "new"]
    /\ deliveryLease = [i \in Deliveries |-> NoLease]
    /\ deliveryCrashCount = [i \in Deliveries |-> 0]
    /\ deliveryBlobPresent = [i \in Deliveries |-> TRUE]
    /\ retryCount = [i \in Deliveries |-> 0]
    /\ submitCount = [i \in Deliveries |-> 0]
    /\ ambiguitySeen = [i \in Deliveries |-> FALSE]
    /\ ambiguitySubmitCount = [i \in Deliveries |-> 0]
    /\ ambiguityCause = [i \in Deliveries |-> "none"]
    /\ frozenGeneration = [i \in Deliveries |-> NoGeneration]
    /\ frozenAdapter = [i \in Deliveries |-> NoAdapter]
    /\ submissionGeneration = [i \in Deliveries |-> NoGeneration]
    /\ submissionAdapter = [i \in Deliveries |-> NoAdapter]
    /\ adaptersUsed = [i \in Deliveries |-> {}]
    /\ deliveryFeedback = [i \in Deliveries |-> {}]

    /\ eventStatus = [e \in Events |-> "new"]
    /\ eventLease = [e \in Events |-> NoLease]
    /\ eventCrashCount = [e \in Events |-> 0]
    /\ processedEventKeys = {}
    /\ appliedEventKeys = {}
    /\ eventApplyCount = [k \in EventKeys |-> 0]

(***************************************************************************
Binding generations are independent by domain and direction.  Cutover freezes
the old active generation as draining, drain waits for its work, and rollback
atomically swaps an active and a draining generation.
***************************************************************************)
Cutover(d, direction, old, new) ==
    /\ bindingPhase[d][direction][old] = "active"
    /\ bindingPhase[d][direction][new] = "inactive"
    /\ old # new
    /\ bindingPhase' =
        [bindingPhase EXCEPT
            ![d][direction][old] = "draining",
            ![d][direction][new] = "active"]
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

DrainGeneration(d, direction, g) ==
    /\ bindingPhase[d][direction][g] = "draining"
    /\ ~GenerationOutstanding(d, direction, g)
    /\ bindingPhase' = [bindingPhase EXCEPT ![d][direction][g] = "retired"]
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

Rollback(d, direction, current, previous) ==
    /\ bindingPhase[d][direction][current] = "active"
    /\ bindingPhase[d][direction][previous] = "draining"
    /\ current # previous
    /\ bindingPhase' =
        [bindingPhase EXCEPT
            ![d][direction][current] = "draining",
            ![d][direction][previous] = "active"]
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

(***************************************************************************
Durable ingress reducer.  A crash or expired lease returns only leased work to
the queue.  Injection and the transition to processed are one atomic action.
***************************************************************************)
RouteIngress(i) ==
    /\ ingressStatus[i] = "new"
    /\ IF HasActiveGeneration(IngressDomain(i), "inbound")
       THEN
           /\ ingressStatus' = [ingressStatus EXCEPT ![i] = "queued"]
           /\ ingressGeneration' =
               [ingressGeneration EXCEPT
                   ![i] = ActiveGeneration(IngressDomain(i), "inbound")]
       ELSE
           /\ ingressStatus' = [ingressStatus EXCEPT ![i] = "rejected"]
           /\ ingressGeneration' = [ingressGeneration EXCEPT ![i] = NoGeneration]
    /\ UNCHANGED <<ingressLease, ingressCrashCount, ingressBlobPresent,
                    ingressInjectionCount>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

LeaseIngress(i) ==
    /\ ingressStatus[i] = "queued"
    /\ ingressStatus' = [ingressStatus EXCEPT ![i] = "leased"]
    /\ ingressLease' = [ingressLease EXCEPT ![i] = WorkerLease]
    /\ UNCHANGED <<ingressCrashCount, ingressBlobPresent,
                    ingressInjectionCount, ingressGeneration>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

RecoverIngressLease(i) ==
    /\ ingressStatus[i] = "leased"
    /\ ingressCrashCount[i] < MaxCrashes
    /\ ingressStatus' = [ingressStatus EXCEPT ![i] = "queued"]
    /\ ingressLease' = [ingressLease EXCEPT ![i] = NoLease]
    /\ ingressCrashCount' = [ingressCrashCount EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<ingressBlobPresent, ingressInjectionCount, ingressGeneration>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

ProcessIngress(i) ==
    /\ ingressStatus[i] = "leased"
    /\ ingressStatus' = [ingressStatus EXCEPT ![i] = "processed"]
    /\ ingressLease' = [ingressLease EXCEPT ![i] = NoLease]
    /\ ingressInjectionCount' = [ingressInjectionCount EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<ingressCrashCount, ingressBlobPresent, ingressGeneration>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

QuarantineIngress(i) ==
    /\ ingressStatus[i] \in {"queued", "leased"}
    /\ ingressStatus' = [ingressStatus EXCEPT ![i] = "quarantined"]
    /\ ingressLease' = [ingressLease EXCEPT ![i] = NoLease]
    /\ UNCHANGED <<ingressCrashCount, ingressBlobPresent,
                    ingressInjectionCount, ingressGeneration>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

DeleteIngressBlob(i) ==
    /\ ingressStatus[i] \in IngressDefinitive
    /\ ingressBlobPresent[i]
    /\ ingressBlobPresent' = [ingressBlobPresent EXCEPT ![i] = FALSE]
    /\ UNCHANGED <<ingressStatus, ingressLease, ingressCrashCount,
                    ingressInjectionCount, ingressGeneration>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED deliveryVars
    /\ UNCHANGED eventVars

(***************************************************************************
Durable outbound reducer.  Route fields are captured exactly once before the
first lease.  A retry is possible only after a definitive retry response.
Timeouts after submission and SMTP DATA acknowledgement loss both enter the
same terminal-for-automation unknown state.
***************************************************************************)
RouteDelivery(i) ==
    /\ deliveryStatus[i] = "new"
    /\ IF HasActiveGeneration(DeliveryDomain(i), "outbound")
       THEN LET g == ActiveGeneration(DeliveryDomain(i), "outbound") IN
           /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "queued"]
           /\ frozenGeneration' = [frozenGeneration EXCEPT ![i] = g]
           /\ frozenAdapter' = [frozenAdapter EXCEPT ![i] = AdapterFor(g)]
       ELSE
           /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "quarantined"]
           /\ frozenGeneration' = [frozenGeneration EXCEPT ![i] = NoGeneration]
           /\ frozenAdapter' = [frozenAdapter EXCEPT ![i] = NoAdapter]
    /\ UNCHANGED <<deliveryLease, deliveryCrashCount, deliveryBlobPresent,
                    retryCount, submitCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, submissionGeneration, submissionAdapter,
                    adaptersUsed, deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

LeaseDelivery(i) ==
    /\ deliveryStatus[i] = "queued"
    /\ ~ambiguitySeen[i]
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "leased"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = WorkerLease]
    /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent, retryCount,
                    submitCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    submissionGeneration, submissionAdapter, adaptersUsed,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

RecoverDeliveryLease(i) ==
    /\ deliveryStatus[i] = "leased"
    /\ deliveryCrashCount[i] < MaxCrashes
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "queued"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = NoLease]
    /\ deliveryCrashCount' = [deliveryCrashCount EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<deliveryBlobPresent, retryCount, submitCount,
                    ambiguitySeen, ambiguitySubmitCount, ambiguityCause,
                    frozenGeneration, frozenAdapter, submissionGeneration,
                    submissionAdapter, adaptersUsed, deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

BeginSubmission(i) ==
    /\ deliveryStatus[i] = "leased"
    /\ ~ambiguitySeen[i]
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "submitting"]
    /\ submitCount' = [submitCount EXCEPT ![i] = @ + 1]
    /\ submissionGeneration' =
        [submissionGeneration EXCEPT ![i] = frozenGeneration[i]]
    /\ submissionAdapter' = [submissionAdapter EXCEPT ![i] = frozenAdapter[i]]
    /\ adaptersUsed' =
        [adaptersUsed EXCEPT ![i] = @ \cup {frozenAdapter[i]}]
    /\ UNCHANGED <<deliveryLease, deliveryCrashCount, deliveryBlobPresent,
                    retryCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

SubmitAccepted(i) ==
    /\ deliveryStatus[i] = "submitting"
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "accepted"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = NoLease]
    /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent, retryCount,
                    submitCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    submissionGeneration, submissionAdapter, adaptersUsed,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

SubmitRejected(i) ==
    /\ deliveryStatus[i] = "submitting"
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "rejected"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = NoLease]
    /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent, retryCount,
                    submitCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    submissionGeneration, submissionAdapter, adaptersUsed,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

SubmitRetry(i) ==
    /\ deliveryStatus[i] = "submitting"
    /\ retryCount[i] < MaxRetries
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "queued"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = NoLease]
    /\ retryCount' = [retryCount EXCEPT ![i] = @ + 1]
    /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent, submitCount,
                    ambiguitySeen, ambiguitySubmitCount, ambiguityCause,
                    frozenGeneration, frozenAdapter, submissionGeneration,
                    submissionAdapter, adaptersUsed, deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

MarkUnknown(i, cause) ==
    /\ AllowAmbiguity
    /\ deliveryStatus[i] = "submitting"
    /\ cause \in {"smtp-data-ack-lost", "provider-submission-timeout"}
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "unknown"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = NoLease]
    /\ ambiguitySeen' = [ambiguitySeen EXCEPT ![i] = TRUE]
    /\ ambiguitySubmitCount' =
        [ambiguitySubmitCount EXCEPT ![i] = submitCount[i]]
    /\ ambiguityCause' = [ambiguityCause EXCEPT ![i] = cause]
    /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent, retryCount,
                    submitCount, frozenGeneration, frozenAdapter,
                    submissionGeneration, submissionAdapter, adaptersUsed,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

QuarantineDelivery(i) ==
    /\ deliveryStatus[i] \in {"queued", "leased", "unknown"}
    /\ deliveryStatus' = [deliveryStatus EXCEPT ![i] = "quarantined"]
    /\ deliveryLease' = [deliveryLease EXCEPT ![i] = NoLease]
    /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent, retryCount,
                    submitCount, ambiguitySeen, ambiguitySubmitCount,
                    ambiguityCause, frozenGeneration, frozenAdapter,
                    submissionGeneration, submissionAdapter, adaptersUsed,
                    deliveryFeedback>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED eventVars

DeleteDeliveryBlob(i) ==
    /\ deliveryStatus[i] \in DeliveryDefinitive
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

(***************************************************************************
Provider notices first enter a durable queue.  The reducer records each
provider event key before either applying or quarantining it.  Feedback facts
form a set, so delayed and definitive feedback commute when delivered out of
order.  Definitive feedback can reconcile an in-flight or unknown submission.
***************************************************************************)
EnqueueEvent(e) ==
    /\ eventStatus[e] = "new"
    /\ eventStatus' = [eventStatus EXCEPT ![e] = "queued"]
    /\ UNCHANGED <<eventLease, eventCrashCount, processedEventKeys,
                    appliedEventKeys, eventApplyCount>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars

LeaseEvent(e) ==
    /\ eventStatus[e] = "queued"
    /\ eventStatus' = [eventStatus EXCEPT ![e] = "leased"]
    /\ eventLease' = [eventLease EXCEPT ![e] = WorkerLease]
    /\ UNCHANGED <<eventCrashCount, processedEventKeys,
                    appliedEventKeys, eventApplyCount>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars

RecoverEventLease(e) ==
    /\ eventStatus[e] = "leased"
    /\ eventCrashCount[e] < MaxCrashes
    /\ eventStatus' = [eventStatus EXCEPT ![e] = "queued"]
    /\ eventLease' = [eventLease EXCEPT ![e] = NoLease]
    /\ eventCrashCount' = [eventCrashCount EXCEPT ![e] = @ + 1]
    /\ UNCHANGED <<processedEventKeys, appliedEventKeys, eventApplyCount>>
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars
    /\ UNCHANGED deliveryVars

FeedbackDisposition(e, i) ==
    IF deliveryStatus[i] \in {"submitting", "unknown"}
       /\ EventKind(e) = "delivered"
    THEN "accepted"
    ELSE IF deliveryStatus[i] \in {"submitting", "unknown"}
            /\ EventKind(e) = "hard-bounce"
         THEN "rejected"
         ELSE deliveryStatus[i]

ReduceEvent(e) ==
    /\ eventStatus[e] = "leased"
    /\ IF EventKey(e) \in processedEventKeys
       THEN
           /\ eventStatus' = [eventStatus EXCEPT ![e] = "duplicate"]
           /\ eventLease' = [eventLease EXCEPT ![e] = NoLease]
           /\ UNCHANGED <<eventCrashCount, processedEventKeys,
                           appliedEventKeys, eventApplyCount>>
           /\ UNCHANGED deliveryVars
       ELSE IF EventDelivery(e) = NoDelivery
                 \/ submitCount[EventDelivery(e)] = 0
            THEN
                /\ eventStatus' = [eventStatus EXCEPT ![e] = "quarantined"]
                /\ eventLease' = [eventLease EXCEPT ![e] = NoLease]
                /\ processedEventKeys' =
                    processedEventKeys \cup {EventKey(e)}
                /\ UNCHANGED <<eventCrashCount, appliedEventKeys,
                                eventApplyCount>>
                /\ UNCHANGED deliveryVars
            ELSE LET i == EventDelivery(e) IN
                /\ eventStatus' = [eventStatus EXCEPT ![e] = "applied"]
                /\ eventLease' = [eventLease EXCEPT ![e] = NoLease]
                /\ processedEventKeys' =
                    processedEventKeys \cup {EventKey(e)}
                /\ appliedEventKeys' =
                    appliedEventKeys \cup {EventKey(e)}
                /\ eventApplyCount' =
                    [eventApplyCount EXCEPT ![EventKey(e)] = @ + 1]
                /\ deliveryStatus' =
                    [deliveryStatus EXCEPT ![i] = FeedbackDisposition(e, i)]
                /\ deliveryLease' =
                    [deliveryLease EXCEPT
                        ![i] = IF FeedbackDisposition(e, i)
                                    \in DeliveryDefinitive
                                THEN NoLease
                                ELSE @]
                /\ deliveryFeedback' =
                    [deliveryFeedback EXCEPT ![i] = @ \cup {EventKind(e)}]
                /\ UNCHANGED <<deliveryCrashCount, deliveryBlobPresent,
                                retryCount, submitCount, ambiguitySeen,
                                ambiguitySubmitCount, ambiguityCause,
                                frozenGeneration, frozenAdapter,
                                submissionGeneration, submissionAdapter,
                                adaptersUsed>>
                /\ UNCHANGED eventCrashCount
    /\ UNCHANGED bindingVars
    /\ UNCHANGED ingressVars

BindingNext ==
    \/ \E d \in KnownDomains, direction \in Directions,
          old \in Generations, new \in Generations :
          Cutover(d, direction, old, new)
    \/ \E d \in KnownDomains, direction \in Directions, g \in Generations :
          DrainGeneration(d, direction, g)
    \/ \E d \in KnownDomains, direction \in Directions,
          current \in Generations, previous \in Generations :
          Rollback(d, direction, current, previous)

IngressNext ==
    \E i \in IngressItems :
        \/ RouteIngress(i)
        \/ LeaseIngress(i)
        \/ RecoverIngressLease(i)
        \/ ProcessIngress(i)
        \/ QuarantineIngress(i)
        \/ DeleteIngressBlob(i)

DeliveryNext ==
    \E i \in Deliveries :
        \/ RouteDelivery(i)
        \/ LeaseDelivery(i)
        \/ RecoverDeliveryLease(i)
        \/ BeginSubmission(i)
        \/ SubmitAccepted(i)
        \/ SubmitRejected(i)
        \/ SubmitRetry(i)
        \/ MarkUnknown(i, "smtp-data-ack-lost")
        \/ MarkUnknown(i, "provider-submission-timeout")
        \/ QuarantineDelivery(i)
        \/ DeleteDeliveryBlob(i)

EventNext ==
    \E e \in Events :
        \/ EnqueueEvent(e)
        \/ LeaseEvent(e)
        \/ RecoverEventLease(e)
        \/ ReduceEvent(e)

Next == BindingNext \/ IngressNext \/ DeliveryNext \/ EventNext
Spec == Init /\ [][Next]_vars

(***************************************************************************
Safety properties.  These names intentionally match the architecture claims
and are also the properties targeted by counterexample regressions.
***************************************************************************)
TypeOK ==
    /\ bindingPhase \in
        [KnownDomains -> [Directions -> [Generations -> BindingPhases]]]
    /\ ingressStatus \in [IngressItems -> IngressStates]
    /\ ingressLease \in [IngressItems -> {NoLease, WorkerLease}]
    /\ ingressCrashCount \in [IngressItems -> 0..MaxCrashes]
    /\ ingressBlobPresent \in [IngressItems -> BOOLEAN]
    /\ ingressInjectionCount \in [IngressItems -> 0..1]
    /\ ingressGeneration \in [IngressItems -> Generations \cup {NoGeneration}]
    /\ deliveryStatus \in [Deliveries -> DeliveryStates]
    /\ deliveryLease \in [Deliveries -> {NoLease, WorkerLease}]
    /\ deliveryCrashCount \in [Deliveries -> 0..MaxCrashes]
    /\ deliveryBlobPresent \in [Deliveries -> BOOLEAN]
    /\ retryCount \in [Deliveries -> 0..MaxRetries]
    /\ submitCount \in [Deliveries -> 0..(MaxRetries + 1)]
    /\ ambiguitySeen \in [Deliveries -> BOOLEAN]
    /\ ambiguitySubmitCount \in [Deliveries -> 0..(MaxRetries + 1)]
    /\ ambiguityCause \in [Deliveries -> AmbiguityCauses]
    /\ frozenGeneration \in [Deliveries -> Generations \cup {NoGeneration}]
    /\ frozenAdapter \in [Deliveries -> Adapters \cup {NoAdapter}]
    /\ submissionGeneration \in
        [Deliveries -> Generations \cup {NoGeneration}]
    /\ submissionAdapter \in [Deliveries -> Adapters \cup {NoAdapter}]
    /\ adaptersUsed \in [Deliveries -> SUBSET Adapters]
    /\ deliveryFeedback \in [Deliveries -> SUBSET FeedbackKinds]
    /\ eventStatus \in [Events -> EventStates]
    /\ eventLease \in [Events -> {NoLease, WorkerLease}]
    /\ eventCrashCount \in [Events -> 0..MaxCrashes]
    /\ processedEventKeys \subseteq EventKeys
    /\ appliedEventKeys \subseteq processedEventKeys
    /\ eventApplyCount \in [EventKeys -> 0..1]

AtMostOneActiveGeneration ==
    \A d \in KnownDomains, direction \in Directions :
        Cardinality(ActiveGenerations(d, direction)) <= 1

AmbiguousSendIsNeverResentOrRerouted ==
    \A i \in Deliveries :
        ambiguitySeen[i] =>
            /\ submitCount[i] = ambiguitySubmitCount[i]
            /\ adaptersUsed[i] \subseteq {frozenAdapter[i]}
            /\ deliveryStatus[i] \notin {"queued", "leased", "submitting"}

ProviderEventAppliedAtMostOnce ==
    \A k \in EventKeys : eventApplyCount[k] <= 1

SubmissionKeepsFrozenRoute ==
    \A i \in Deliveries :
        submitCount[i] > 0 =>
            /\ frozenGeneration[i] \in Generations
            /\ frozenAdapter[i] = AdapterFor(frozenGeneration[i])
            /\ submissionGeneration[i] = frozenGeneration[i]
            /\ submissionAdapter[i] = frozenAdapter[i]
            /\ adaptersUsed[i] \subseteq {frozenAdapter[i]}

ProcessedIngressIsNotReinjected ==
    \A i \in IngressItems :
        /\ ingressInjectionCount[i] <= 1
        /\ (ingressStatus[i] = "processed" => ingressInjectionCount[i] = 1)

UnknownDomainsHaveNoDefaultRoute ==
    /\ \A i \in IngressItems :
        IngressDomain(i) \notin KnownDomains =>
            /\ ingressGeneration[i] = NoGeneration
            /\ ingressStatus[i] \notin {"queued", "leased", "processed"}
    /\ \A i \in Deliveries :
        DeliveryDomain(i) \notin KnownDomains =>
            /\ frozenGeneration[i] = NoGeneration
            /\ frozenAdapter[i] = NoAdapter
            /\ submitCount[i] = 0
            /\ adaptersUsed[i] = {}

QueuedBytesRetainedUntilDefinitiveDisposition ==
    /\ \A i \in IngressItems :
        ~ingressBlobPresent[i] => ingressStatus[i] \in IngressDefinitive
    /\ \A i \in Deliveries :
        ~deliveryBlobPresent[i] => deliveryStatus[i] \in DeliveryDefinitive

(***************************************************************************
Liveness is checked only with AllowAmbiguity = FALSE and MaxCrashes = 0.
Weak fairness is justified for continuously enabled reducer work: durable
workers are assumed to keep being scheduled, and the adapter is assumed to
return retry at most MaxRetries times before accepted or rejected.  No fairness
is assumed for an ambiguous submission; it intentionally requires operator or
feedback reconciliation.
***************************************************************************)
IngressFairness ==
    \A i \in IngressItems :
        /\ WF_vars(RouteIngress(i))
        /\ WF_vars(LeaseIngress(i))
        /\ WF_vars(ProcessIngress(i) \/ QuarantineIngress(i))

DeliveryFairness ==
    \A i \in Deliveries :
        /\ WF_vars(RouteDelivery(i))
        /\ WF_vars(LeaseDelivery(i))
        /\ WF_vars(BeginSubmission(i))
        /\ WF_vars(SubmitAccepted(i) \/ SubmitRejected(i) \/ SubmitRetry(i))

FairSpec == Spec /\ IngressFairness /\ DeliveryFairness

KnownIngressEventuallyReduced ==
    \A i \in IngressItems :
        IngressDomain(i) \in KnownDomains =>
            (ingressStatus[i] = "new")
                ~> (ingressStatus[i] \in IngressDefinitive)

NonAmbiguousRetryableDeliveryEventuallyDefinitive ==
    \A i \in Deliveries :
        DeliveryDomain(i) \in KnownDomains =>
            (deliveryStatus[i] = "new")
                ~> (deliveryStatus[i] \in DeliveryDefinitive)

=============================================================================
