; This creates a pod using a pod from bob and one from charlie, themselves made out of pods
[createpod alice-pod
    [define
        [gb1-user
         b-attest-user
         known-attestors-b]
        [from @bob pod?
            [define [gb1-user gb1-signer] [pod? [user] [_signer]]]
            [define [b-attest-user b-attest-signer] [pod? [user :constraints [eq @alice]] [_signer]]]
            [gb1-user]
            [b-attest-user]
            [known-attestors :constrains [eq 0xROOT]]
            [assert [contains known-attestors gb1-signer]]
            [assert [eq gb1-user b-attest-signer]]]]
    [define
        [gb3-user
         c-attest-user
         known-attestors-c]
        [from @charlie pod?
            [define [gb3-user gb3-signer] [pod? [user] [_signer]]]
            [define [c-attest-user c-attest-signer] [pod? [user :constraints [eq @alice]] [_signer]]]
            [gb3-user]
            [c-attest-user]
            [known-attestors :constrains [eq 0xROOT]]
            [assert [contains known-attestors gb3-signer]]
            [assert [eq gb3-user c-attest-signer]]]]
    known-attestors "0xROOT"
    [assert [eq known-attestors-c known-attestors]]
    [assert [eq known-attestors-b known-attestors]]
    b-attest-user b-attest-user
    c-attest-user c-attest-user
    [assert [superset known-attestors known-attestors-c]]
]
; this is what the POD that bob would send over the network would look like
; "meta" gets put together using the statements (which are constraints) in the pod
[defpod bob-response
    gb1-user "0xBOB"
    b-attest-user "0xALICE"
    known-attestors "0xROOT"
    :meta [
        [define [gb1-user gb1-signer] [pod? [user] [_signer]]]
        [define [b-attest-user b-attest-signer] [pod? [user] [_signer]]]
        [assert [contains known-attestors gb1-signer]]
        [assert [eq gb1-user b-attest-signer]]]]
    ]
]
