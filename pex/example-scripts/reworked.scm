[createpod alice-pod
    [define
        [gb1-user
         b-attest-user
         known-attestors-b]
        [from @bob pod?
            [define [gb1-user gb1-signer] [pod? [user] [_signer]]]
            [define [b-attest-user b-attest-signer] [pod? [user :where [eq @alice]] [_signer]]]
            [gb1-user]
            [b-attest-user]
            [known-attestors :where [eq 0xROOT]]
            [constraints [contains known-attestors gb1-signer]]
            [constraints [eq gb1-user b-attest-signer]]]]
    [define
        [gb3-user
         c-attest-user
         known-attestors-c]
        [from @charlie pod?
            [define [gb3-user gb3-signer] [pod? [user] [_signer]]]
            [define [c-attest-user c-attest-signer] [pod? [user :where [eq @alice]] [_signer]]]
            [gb3-user]
            [c-attest-user]
            [known-attestors :constrains [eq 0xROOT]]
            [constraints [contains known-attestors gb3-signer]]
            [constraints [eq gb3-user c-attest-signer]]]]
    known-attestors "0xROOT"
    b-attest-user b-attest-user
    c-attest-user c-attest-user
    [constraints [superset known-attestors known-attestors-c]]
    [constraints [eq known-attestors-c known-attestors]]
    [constraints [eq known-attestors-b known-attestors]]
]