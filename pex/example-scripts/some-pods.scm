; Some examples of creating pods and then printing them
; I added some somewhat broken Rust that describes the list of operation (in the style of pod2-scratch) that create this POD, along with the
; statements in the resulting POD

[createpod simple-pod-1  ; Alice's first pod
  x 10
  y 20]
; Rust operations:
; vec![
;     (Operation::NewEntry, Origin::Self, "x", Some(&Entry::new("x", ScalarOrVec::Scalar(GoldilocksField(10))))),
;     (Operation::NewEntry, Origin::Self, "y", Some(&Entry::new("y", ScalarOrVec::Scalar(GoldilocksField(20)))))
; ]
; Resulting statements:
; 1. ValueOf(Origin::Self, "x", 10)
; 2. ValueOf(Origin::Self, "y", 20)

[createpod simple-pod-2  ; Alice's second pod
  z 15
  w 25]
; Rust operations:
; vec![
;     (Operation::NewEntry, Origin::Self, "z", Some(&Entry::new("z", ScalarOrVec::Scalar(GoldilocksField(15))))),
;     (Operation::NewEntry, Origin::Self, "w", Some(&Entry::new("w", ScalarOrVec::Scalar(GoldilocksField(25)))))
; ]
; Resulting statements:
; 1. ValueOf(Origin::Self, "z", 15)
; 2. ValueOf(Origin::Self, "w", 25)

[createpod simple-pod-3  ; Bob's pod
  a 30
  b 40]
; Rust operations:
; vec![
;     (Operation::NewEntry, Origin::Self, "a", Some(&Entry::new("a", ScalarOrVec::Scalar(GoldilocksField(30))))),
;     (Operation::NewEntry, Origin::Self, "b", Some(&Entry::new("b", ScalarOrVec::Scalar(GoldilocksField(40)))))
; ]
; Resulting statements:
; 1. ValueOf(Origin::Self, "a", 30)
; 2. ValueOf(Origin::Self, "b", 40)

[createpod simple-pod-4  ; Charlie's pod
  local-value 100]
; Rust operations:
; vec![
;     (Operation::NewEntry, Origin::Self, "local-value" Some(&Entry::new("local-value" ScalarOrVec::Scalar(GoldilocksField(100))))),
; ]
; Resulting statements:
; 1. ValueOf(Origin::Self, "local-value") 100

[createpod sum-pod  ; Alice's sum pod
  result [+ [pod? [x]]    ; Get x from Alice's simple-pod-1
            [pod? [z]]]]  ; Get z from Alice's simple-pod-2
; Rust operations:
; Notice we need to compute the 10 + 15 outside the statement.
; Pex guides us by actually doing the sum here (summing the x key of the first pod and the z key of the second one) and can then stub in the
; statements emitted
; vec![
;     (Operation::NewEntry, Origin::Self, "result", Some(&Entry::new("result", ScalarOrVec::Scalar(GoldilocksField(25)))))
;     (Operation::Add, Origin::External("simple-pod-1"), "x", Origin::External("simple-pod-2"), "z", Origin::Self, "result"),
; ]
; Resulting statements:
; 1. Add(Origin::External("simple-pod-1"), "x", Origin::External("simple-pod-2"), "z", Origin::Self, "result")
; 2. ValueOf(Origin::Self, "result", 25)
; Notice that this POD doesn't reveal the value of x and z! it just claims that we have two numbers coming from two different PODs that sum to 25

[createpod product-pod  ; Bob's product pod
  result [* [pod? [a]]    ; Get a from Bob's simple-pod-3
            [pod? [b]]]]  ; Get b from Bob's simple-pod-3
; Rust operations:
; vec![
;     (Operation::NewEntry, Origin::Self, "result", Some(&Entry::new("result", ScalarOrVec::Scalar(GoldilocksField(1200)))))
;     (Operation::Multiply, Origin::External("simple-pod-3"), "a", Origin::External("simple-pod-3"), "b", Origin::Self, "result"),
; ]
; Resulting statements:
; 1. Multiply(Origin::External("simple-pod-3"), "a", Origin::External("simple-pod-3"), "b", Origin::Self, "result")
; 2. ValueOf(Origin::Self, "result", 1200)

; An alternative world here would be where we want "a" from simple-pod-3 to be revealed, but not b. this is of course not a great example
; because if you know result = a * b; and you know a; then you know b. but let's roll anyway.
; In order to do that, we would ask one more key from our first pod? and add it as a key to our new pod

[createpod product-pod-2
  [define a [pod? [a]]] ; create a named expression called a
  result [* a
            [pod? [b]]] ; we multiply previously bound a and b from a pod that matches the query
  a                     ; we reveal the entry
]
; Rust operations:
; vec![
;     (Operation::CopyStatement, Origin::External("simple-pod-3"), "a", None, None),
;     (Operation::NewEntry, Origin::Self, "result", Some(&Entry::new("result", ScalarOrVec::Scalar(GoldilocksField(1200)))))
;     (Operation::Multiply, Origin::External("simple-pod-3"), "a", Origin::External("simple-pod-3"), "b", Origin::Self, "result"),
; ]
; Resulting statements:
; 1. ValueOf(Origin::External("simple-pod-3", "a", 30)
; 2. Multiply(Origin::External("simple-pod-3"), "a", Origin::External("simple-pod-3"), "b", Origin::Self, "result")
; 3. ValueOf(Origin::Self, "result", 1200)
; One issue with this define as a way to re-use a twice is that it's going to be tricky to query on that. Need more ideas here.


; For this POD, we are going to compute one key -- remote-max -- from two PODs that come from other people
; then we'll compute one key with one of Charlie's POD
; then we'll end with adding a statement about the overall max of these two max
[createpod final-pod  ; Charlie's pod (multiplayer execution from Alice and Bob)
  remote-max [max [from @alice [pod? [result [+ [pod? [x]] [pod? [z]]]]]]
                  [from @bob [pod? [result [* [pod? [a]] [pod? [b]]]]]]]

  local-sum [+ [pod? [local-value]] 42]

  overall-max [max remote-max
                   local-sum]]
; Rust operations:
; vec![
;     (Operation::NewEntry, Origin::Self, "remote-max", Some(&Entry::new("remote-max", ScalarOrVec::Scalar(GoldilocksField(1200)))))
;     (Operation::Max, Origin::External("sum-pod"), "result", Origin::External("product-pod"), "result", Origin::Self, "remote-max"),
;     (Operation::NewEntry, Origin::Self, "42", Some(&Entry::new("42", ScalarOrVec::Scalar(GoldilocksField(42)))))
;     (Operation::NewEntry, Origin::Self, "local-sum", Some(&Entry::new("local-sum", ScalarOrVec::Scalar(GoldilocksField(142)))))
;     (Operation::Add, Origin::External("simple-pod-4"), "local-value", Origin::Self, "42", Origin::Self, "local-sum"),
;     (Operation::NewEntry, Origin::Self, "overall-max", Some(&Entry::new("overall-max", ScalarOrVec::Scalar(GoldilocksField(1200)))))
;     (Operation::Max, Origin::Self, "remote-max", Origin::Self, "local-sum", Origin::Self, "overall-max"),
;     // We also copy statements from "sum-pod" and "product-pod" in order to show that these pods were the sum and product of pods (without revelaing the values)
;     // This is where it became clear we need statements to be keyed too (not just entries). And in fact kill entries all together as first class citizen
;     // and instead think of entries as ValueOf statements when in the clear; and as absent statements when Zero-Knowledged
;     // A little bit like remote-max points to the result entry of product pod even if that ValueOf statement cannot be found in this pod
;     // Below we'd need something in the effect of copying a statement based on a key; so we could copy the Add statement from sum-pod
;     // and Multiply statement from product-pod
;     (Operation::CopyStatement, Origin::External("sum-pod"), "add-statement"),
;     (Operation::CopyStatement, Origin::External("product-pod"), "product-statement"),
; ]
; Resulting statements:
; 1. ValueOf(Origin::Self, "remote-max", 1200)
; 3. Max(Origin::External("sum-pod"), "result", Origin::External("product-pod"), "result", Origin::Self, "remote-max")
; 4. ValueOf(Origin::Self, "42", 42)
; 5. ValueOf(Origin::Self, "local-sum", 142)
; 8. Add(Origin::External("simple-pod-4"), "local-value", Origin::Self, "42", Origin::Self, "local-sum")
; 9. ValueOf(Origin::Self, "overall-max", 1200)
; 11. Max(Origin::Self, "remote-max", Origin::Self, "local-sum", Origin::Self, "overall-max")
; These were carried over from previous PODs to reveal some structure on how the two "results" were computed
; 12. Multiply(Origin::External("simple-pod-3"), "a", Origin::External("simple-pod-3"), "b", Origin::External("product-pod"), "result")
; 13. Add(Origin::External("simple-pod-1"), "x", Origin::External("simple-pod-2"), "z", Origin::External("sum-pod"), "result")

; Serialized PODs with metadata
[defpod simple-pod-1
  x 10
  y 20
  :meta [[user @alice]]]

[defpod simple-pod-2
  z 15
  w 25
  :meta [[user @alice]]]

[defpod simple-pod-3
  a 30
  b 40
  :meta [[user @bob]]]

[defpod sum-pod
  result 25
  :meta [[user @alice]
         [result [+ [pod? [x]] [pod? [z]]]]]]

[defpod product-pod
  result 1200
  :meta [[user @bob]
         [result [* [pod? [a]] [pod? [b]]]]]]

[defpod product-pod-2
  result 1200
  a 30
  :meta [[user @bob]
         [define a [pod? [a]]]
         [result [* a [pod? [b]]]]]]

[defpod final-pod
  remote-max 1200
  local-sum 142
  overall-max 1200
  :meta [[user @charlie]
         [remote-max [max [pod? [result [+ [pod? [x]] [pod? [z]]]]]
                          [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
         [local-sum [+ [pod? [local-value]] 42]]
         [overall-max [max local-sum
                           custom-sum]]]]
