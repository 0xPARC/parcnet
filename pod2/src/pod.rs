use std::collections::HashMap;

use anyhow::anyhow;
use anyhow::Result;
//use circuit::pod2_circuit;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;

use crate::schnorr::SchnorrPublicKey;
use crate::schnorr::SchnorrSecretKey;
use crate::schnorr::SchnorrSignature;
use crate::schnorr::SchnorrSigner;

use entry::Entry;
use gadget::GadgetID;
use payload::{HashablePayload, PODPayload};
use value::ScalarOrVec;

use operation::OperationCmd as OpCmd;

use statement::Statement;

//mod circuit;
mod entry;
mod gadget;
mod operation;
mod origin;
mod payload;
mod statement;
mod util;
mod value;

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum PODProof {
    Schnorr(SchnorrSignature),
    Oracle(SchnorrSignature),
}

#[derive(Clone, Debug, PartialEq)]
pub struct POD {
    pub payload: PODPayload,
    proof: PODProof,
    pub proof_type: GadgetID,
}

impl POD {
    pub fn verify(&self) -> Result<bool> {
        match self.proof {
            PODProof::Schnorr(p) => {
                if self.proof_type != GadgetID::SCHNORR16 {
                    return Err(anyhow!("Proof and POD proofType mismatch"));
                }

                let payload_hash = self.payload.hash_payload();
                let payload_hash_vec = vec![payload_hash];
                let protocol = SchnorrSigner::new();

                let pk: GoldilocksField = self
                    .payload
                    .statements_map
                    .get("VALUEOF:_signer")
                    .ok_or(anyhow!("No signer found in payload"))
                    .and_then(|s| match s {
                        Statement::ValueOf(_, ScalarOrVec::Scalar(v)) => Ok(*v),
                        _ => Err(anyhow!("Invalid signer entry in payload")),
                    })?;

                Ok(protocol.verify(&p, &payload_hash_vec, &SchnorrPublicKey { pk }))
            }

            PODProof::Oracle(p) => {
                if self.proof_type != GadgetID::ORACLE {
                    return Err(anyhow!("Proof and POD proofType mismatch"));
                }

                let payload_hash = self.payload.hash_payload();
                let payload_hash_vec = vec![payload_hash];
                let protocol = SchnorrSigner::new();

                Ok(protocol.verify(
                    &p,
                    &payload_hash_vec,
                    &protocol.keygen(&SchnorrSecretKey { sk: 0 }), // hardcoded secret key
                ))
            }
        }
    }

    pub fn execute_schnorr_gadget(entries: &Vec<Entry>, sk: &SchnorrSecretKey) -> Self {
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();

        let mut kv_pairs = entries.clone();
        kv_pairs.push(Entry {
            key: "_signer".to_string(),
            value: ScalarOrVec::Scalar(protocol.keygen(sk).pk),
        });
        let statement_map: HashMap<String, Statement> = kv_pairs
            .iter()
            .map(|entry| {
                (
                    format!("VALUEOF:{}", entry.key),
                    Statement::from_entry(entry, GadgetID::SCHNORR16),
                )
            })
            .collect();

        let payload = PODPayload::new(&statement_map);
        let payload_hash = payload.hash_payload();
        let payload_hash_vec = vec![payload_hash];
        let proof = protocol.sign(&payload_hash_vec, sk, &mut rng);
        Self {
            payload,
            proof: PODProof::Schnorr(proof),
            proof_type: GadgetID::SCHNORR16,
        }
    }

    pub fn execute_oracle_gadget(input: &GPGInput, cmds: &[OpCmd]) -> Result<Self> {
        let mut statements = input.remap_origin_ids_by_name()?;
        statements.insert("_SELF".to_string(), HashMap::new());
        for cmd in cmds {
            let OpCmd(op, output_name) = cmd;
            let new_statement = op.execute(GadgetID::ORACLE, &statements)?;
            statements.get_mut("_SELF").unwrap().insert(
                format!("{}:{}", new_statement.predicate(), output_name),
                new_statement,
            );
        }
        let out_statements = statements.get("_SELF").unwrap();
        let out_payload = PODPayload::new(out_statements);
        let mut rng: rand::rngs::ThreadRng = rand::thread_rng();
        let protocol = SchnorrSigner::new();
        let payload_hash = out_payload.hash_payload();
        let payload_hash_vec = vec![payload_hash];

        // signature is a hardcoded skey (currently 0)
        // todo is to build a limited version of this with a ZKP
        // would start by making it so that the ZKP only allows
        // a max number of input PODs, max number of entries/statements per input POD,
        // max number of statements for output POD, and some max number of each type of operation
        let proof = protocol.sign(&payload_hash_vec, &SchnorrSecretKey { sk: 0 }, &mut rng);
        Ok(Self {
            payload: out_payload,
            proof: PODProof::Oracle(proof),
            proof_type: GadgetID::ORACLE,
        })
    }
}

#[derive(Clone, Debug)]
pub struct GPGInput {
    /// ORDERED list of pods, ordered by names
    pub pods_list: Vec<(String, POD)>,

    /// map from (pod name, old origin name) to new origin name
    pub origin_renaming_map: HashMap<(String, String), String>,
}

impl GPGInput {
    pub fn new(
        named_pods: HashMap<String, POD>,
        origin_renaming_map: HashMap<(String, String), String>,
    ) -> Self {
        let mut pods_and_names_list = Vec::new();
        let mut origin_renaming_map_clone = origin_renaming_map.clone();
        for (name, pod) in named_pods.iter() {
            pods_and_names_list.push((name.clone(), pod.clone()));
            origin_renaming_map_clone.insert((name.clone(), "_SELF".to_string()), name.clone());
        }
        pods_and_names_list.sort_by(|a, b| a.0.cmp(&b.0));

        Self {
            pods_list: pods_and_names_list,
            origin_renaming_map: origin_renaming_map_clone,
        }
    }

    /// returns a map from input POD name to (map from statement name to statement)
    /// the inner statements have their old origin names and IDs are replaced with
    /// the new origin names as specified by inputs.origin_renaming_map
    /// and with new origin IDs which correspond to the lexicographic order of the new origin names
    fn remap_origin_ids_by_name(&self) -> Result<HashMap<String, HashMap<String, Statement>>> {
        // Sorted new origin name list
        let mut new_origin_name_list = self
            .origin_renaming_map
            .iter()
            .map(|(_, new_name)| new_name)
            .collect::<Vec<_>>();
        new_origin_name_list.sort();

        // New origin name -> new origin ID map
        let new_origin_name_to_id_map = new_origin_name_list
            .iter()
            .enumerate()
            .map(
                |(idx, new_name)| (*new_name, idx + 2), // 0 reserved for none, 1 reserved for _SELF
            )
            .collect::<HashMap<&String, usize>>();

        // Iterate through all statements, leaving parent names intact
        // and replacing statement names with their new names
        // (according to `origin_renaming_map`) and replacing origin
        // IDs according to `new_origin_name_to_id_map`.
        let statements_with_renamed_origins = self
            .pods_list
            .iter()
            .map(|(pod_name, pod)| {
                let origin_remapper = Box::new(|origin_name: &str| {
                    let new_origin_name = self
                        .origin_renaming_map
                        .get(&(pod_name.clone(), origin_name.to_string()))
                        .ok_or(anyhow!(
                            "Couldn't find new origin name for origin {}.{}.",
                            pod_name,
                            origin_name
                        ))?;
                    let new_origin_id =
                        new_origin_name_to_id_map
                            .get(new_origin_name)
                            .ok_or(anyhow!(
                                "Couldn't find ID for new origin {}.",
                                new_origin_name
                            ))?;
                    Ok((
                        new_origin_name.clone(),
                        GoldilocksField::from_canonical_u64(*new_origin_id as u64),
                    ))
                });
                Ok((
                    pod_name.to_string(),
                    pod.payload
                        .statements_map
                        .iter()
                        .map(|(statement_name, statement)| {
                            Ok((
                                statement_name.to_string(),
                                statement.remap_origins(&origin_remapper)?,
                            ))
                        })
                        .collect::<Result<HashMap<String, Statement>>>()?,
                ))
            })
            .collect::<Result<HashMap<String, HashMap<_, _>>>>();

        statements_with_renamed_origins
    }
}

#[cfg(test)]
mod tests {
    use operation::Operation as Op;
    use statement::StatementRef;

    use super::*;
    #[test]
    fn op_test() -> Result<()> {
        // Start with some values.
        let scalar1 = GoldilocksField(36);
        let scalar2 = GoldilocksField(52);
        let scalar3 = GoldilocksField(16);
        let vector_value = vec![scalar1, scalar2];

        // Create entries
        let entry1 = Entry::new_from_scalar("some key", scalar1);
        let entry2 = Entry::new_from_scalar("some other key", scalar2);
        let entry3 = Entry::new_from_vec("vector entry", vector_value.clone());
        let entry4 = Entry::new_from_scalar("another scalar1", scalar1);
        let entry5 = Entry::new_from_scalar("yet another scalar1", scalar1);
        let entry6 = Entry::new_from_scalar("scalar3", scalar3);

        // Create entry statements.
        let entry_statement1 = Statement::from_entry(&entry1, GadgetID::NONE);
        let entry_statement2 = Statement::from_entry(&entry2, GadgetID::NONE);
        let entry_statement3 = Statement::from_entry(&entry3, GadgetID::NONE);
        let entry_statement4 = Statement::from_entry(&entry4, GadgetID::NONE);
        let entry_statement5 = Statement::from_entry(&entry5, GadgetID::NONE);
        let entry_statement6 = Statement::from_entry(&entry6, GadgetID::NONE);

        // Anchored keys for later reference
        let anchkeys1 = entry_statement1.anchored_keys();
        let anchkeys2 = entry_statement2.anchored_keys();
        let _anchkeys3 = entry_statement3.anchored_keys();
        let anchkeys4 = entry_statement4.anchored_keys();
        let _anchkeys5 = entry_statement5.anchored_keys();
        let anchkeys6 = entry_statement6.anchored_keys();

        // Entry 2's value = entry 1's value + entry 6's value
        let sum_of_statement = Op::SumOf(
            entry_statement2.clone(),
            entry_statement1.clone(),
            entry_statement6.clone(),
        )
        .eval_with_gadget_id(GadgetID::ORACLE)?;

        assert!(
            sum_of_statement
                == Statement::SumOf(
                    anchkeys2[0].clone(),
                    anchkeys1[0].clone(),
                    anchkeys6[0].clone()
                )
        );

        let entries = [&entry_statement1, &entry_statement2, &entry_statement3];

        // Copy statements and check for equality of entries.
        entries.into_iter().try_for_each(|statement| {
            let copy = Op::CopyStatement(statement.clone()).eval_with_gadget_id(GadgetID::NONE)?;
            assert!(&copy == statement);
            anyhow::Ok(())
        })?;

        // Equality checks
        assert!(
            Op::EqualityFromEntries(entry_statement1.clone(), entry_statement4.clone())
                .eval_with_gadget_id(GadgetID::NONE)?
                == Statement::Equal(anchkeys1[0].clone(), anchkeys4[0].clone())
        );

        entries.into_iter().try_for_each(|statement| {
            assert!(
                Op::EqualityFromEntries(statement.clone(), statement.clone())
                    .eval_with_gadget_id(GadgetID::NONE)?
                    == Statement::Equal(
                        statement.anchored_keys()[0].clone(),
                        statement.anchored_keys()[0].clone()
                    )
            );
            anyhow::Ok(())
        })?;
        assert!(
            Op::NonequalityFromEntries(entry_statement1.clone(), entry_statement2.clone())
                .eval_with_gadget_id(GadgetID::NONE)?
                == Statement::NotEqual(anchkeys1[0].clone(), anchkeys2[0].clone())
        );
        assert!(
            Op::EqualityFromEntries(entry_statement1.clone(), entry_statement2.clone())
                .eval_with_gadget_id(GadgetID::NONE)
                .is_err()
        );

        // Gt check
        let gt_statement = Op::GtFromEntries(entry_statement2.clone(), entry_statement1.clone())
            .eval_with_gadget_id(GadgetID::NONE)?;
        assert!(gt_statement == Statement::Gt(anchkeys2[0].clone(), anchkeys1[0].clone()));

        // Eq transitivity check
        let eq_statement1 =
            Op::EqualityFromEntries(entry_statement4.clone(), entry_statement1.clone())
                .eval_with_gadget_id(GadgetID::NONE)?;

        let eq_statement2 =
            Op::EqualityFromEntries(entry_statement1.clone(), entry_statement5.clone())
                .eval_with_gadget_id(GadgetID::NONE)?;

        let eq_statement3 =
            Op::EqualityFromEntries(entry_statement4.clone(), entry_statement5.clone())
                .eval_with_gadget_id(GadgetID::NONE)?;

        assert!(
            Op::TransitiveEqualityFromStatements(eq_statement1.clone(), eq_statement2.clone())
                .eval_with_gadget_id(GadgetID::NONE)?
                == eq_statement3
        );

        // Gt->Nonequality conversion check
        let gt_anchkeys = gt_statement.anchored_keys();
        assert!(
            Op::GtToNonequality(gt_statement.clone()).eval_with_gadget_id(GadgetID::NONE)?
                == Statement::NotEqual(gt_anchkeys[0].clone(), gt_anchkeys[1].clone())
        );
        Ok(())
    }

    #[test]
    fn schnorr_pod_test() -> Result<()> {
        // Start with some values.
        let scalar1 = GoldilocksField(36);
        let scalar2 = GoldilocksField(52);
        let vector_value = vec![scalar1, scalar2];

        let entry1 = Entry::new_from_scalar("some key", scalar1);
        let entry2 = Entry::new_from_scalar("some other key", scalar2);
        let entry3 = Entry::new_from_vec("vector entry", vector_value.clone());

        let other_entry = Entry::new_from_scalar("some key", GoldilocksField(37));
        let other_statement = Statement::from_entry(&other_entry, GadgetID::SCHNORR16);

        let schnorr_pod1 = POD::execute_schnorr_gadget(
            &vec![entry1.clone(), entry2.clone()],
            &SchnorrSecretKey { sk: 25 },
        );

        let schnorr_pod2 = POD::execute_schnorr_gadget(
            &vec![entry2.clone(), entry3.clone()],
            &SchnorrSecretKey { sk: 42 },
        );

        assert!(schnorr_pod1.verify()?);
        assert!(schnorr_pod2.verify()?);

        let mut schnorr_pod3 =
            POD::execute_schnorr_gadget(&vec![entry1.clone()], &SchnorrSecretKey { sk: 25 });

        // modify the internal value of the valueOf statement in schnorrPOD3
        schnorr_pod3
            .payload
            .statements_map
            .insert("VALUEOF:some key".to_string(), other_statement.clone());
        schnorr_pod3.payload.statements_list[1].1 = other_statement;

        // now signature shouldn't verify
        assert!(!(schnorr_pod3.verify()?));

        // // ZK verification of SchnorrPOD 3.
        // let (builder, targets) = pod2_circuit(1, 2, 0, 0)?;

        // // Assign witnesses
        // const D: usize = 2;
        // type C = PoseidonGoldilocksConfig;
        // type F = <C as GenericConfig<D>>::F;
        // let mut pw: PartialWitness<F> = PartialWitness::new();
        // pw.set_target(targets.input_is_schnorr[0], GoldilocksField(1))?;
        // pw.set_target(targets.input_is_gpg[0], GoldilocksField::ZERO)?;
        // pw.set_target(
        //     targets.input_payload_hash[0],
        //     schnorrPOD3.payload.hash_payload(),
        // )?;
        // pw.set_target(targets.pk_index[0], GoldilocksField(1))?;
        // targets.input_proof[0].set_witness(&mut pw, &schnorrPOD3.proof)?;
        // targets.input_entries[0][0].set_witness(&mut pw, &schnorrPOD3.payload[0])?;
        // targets.input_entries[0][1].set_witness(&mut pw, &schnorrPOD3.payload[1])?;
        // let data = builder.build::<C>();
        // let proof = data.prove(pw)?;

        Ok(())
    }

    // i haven't written asserts yet to check the correctness of oracle and oracle2 pods
    // but i've manually inspected output and it looks good
    #[test]
    fn oracle_pod_from_schnorr_test() -> Result<()> {
        println!("oracle_pod_from_schnorr_test");
        // Start with some values.
        let scalar1 = GoldilocksField(36);
        let scalar2 = GoldilocksField(52);
        let scalar3 = GoldilocksField(88);
        let vector_value = vec![scalar1, scalar2];

        // make entries
        let entry1 = Entry::new_from_scalar("apple", scalar1);
        let entry2 = Entry::new_from_scalar("banana", scalar2);
        let entry3 = Entry::new_from_vec("vector entry", vector_value.clone());
        let entry4 = Entry::new_from_scalar("scalar entry", scalar2);
        let entry5 = Entry::new_from_scalar("foo", GoldilocksField(100));
        let entry6 = Entry::new_from_scalar("baz", GoldilocksField(120));
        let entry7 = Entry::new_from_scalar("bar", scalar2);
        let entry9 = Entry::new_from_scalar("claimed sum", scalar3);

        // three schnorr pods
        let schnorr_pod1 = POD::execute_schnorr_gadget(
            &vec![entry1.clone(), entry2.clone()],
            &SchnorrSecretKey { sk: 25 },
        );

        let schnorr_pod2 = POD::execute_schnorr_gadget(
            &vec![entry3.clone(), entry4.clone()],
            &SchnorrSecretKey { sk: 42 },
        );
        // make an OraclePOD using from_pods called on the two schnorr PODs

        // first make the GPG input

        // make a map of named POD inputs
        let mut named_input_pods = HashMap::new();
        named_input_pods.insert("p1".to_string(), schnorr_pod1.clone());
        named_input_pods.insert("schnorrPOD2".to_string(), schnorr_pod2.clone());

        // make a map of (pod name, old origin name) to new origin name
        let origin_renaming_map = HashMap::new();
        // all the inputs are schnorr PODs whose only referenced origin is _SELF
        // _SELF is taken care of automatically so origin_renaming_map can be empty

        let gpg_input = GPGInput::new(named_input_pods, origin_renaming_map);

        // make a list of the operations we want to call
        let ops = vec![
            OpCmd(
                Op::CopyStatement(StatementRef("p1", "VALUEOF:apple")),
                "p1-apple",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("p1", "VALUEOF:banana")),
                "p1-banana",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("p1", "VALUEOF:_signer")),
                "p1-signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("schnorrPOD2", "VALUEOF:vector entry")),
                "schnorrPOD2-vec-entry",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("schnorrPOD2", "VALUEOF:scalar entry")),
                "a scalar entry",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("schnorrPOD2", "VALUEOF:_signer")),
                "schnorrPOD2-signer",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("p1", "VALUEOF:banana"),
                    StatementRef("schnorrPOD2", "VALUEOF:scalar entry"),
                ),
                "eq1",
            ),
            OpCmd(
                Op::GtFromEntries(
                    StatementRef("p1", "VALUEOF:banana"),
                    StatementRef("p1", "VALUEOF:apple"),
                ),
                "apple banana comparison",
            ),
            // this operation creates a statement on top of a statement
            // created by an earlier operation
            OpCmd(
                Op::ContainsFromEntries(
                    StatementRef("_SELF", "VALUEOF:schnorrPOD2-vec-entry"),
                    StatementRef("p1", "VALUEOF:apple"),
                ),
                "CONTAINS:contains1",
            ),
        ];

        let oracle_pod = POD::execute_oracle_gadget(&gpg_input, &ops).unwrap();
        assert!(oracle_pod.verify()? == true);

        // make another oracle POD which takes that oracle POD and a schnorr POD

        let schnorr_pod3 = POD::execute_schnorr_gadget(
            &vec![entry5.clone(), entry6.clone(), entry7.clone()],
            &SchnorrSecretKey { sk: 83 },
        );

        // make the GPG input

        // make a map of named POD inputs
        let mut named_input_pods2 = HashMap::new();
        named_input_pods2.insert("oraclePODParent".to_string(), oracle_pod.clone());
        named_input_pods2.insert("p3".to_string(), schnorr_pod3.clone());

        // make a map of (pod name, old origin name) to new origin name
        let mut origin_renaming_map2 = HashMap::new();
        // let's keep the name of the first origin and shorten the name of the second origin
        origin_renaming_map2.insert(
            ("oraclePODParent".to_string(), "p1".to_string()),
            "p1".to_string(),
        );
        origin_renaming_map2.insert(
            ("oraclePODParent".to_string(), "schnorrPOD2".to_string()),
            "p2".to_string(),
        );

        let gpg_input = GPGInput::new(named_input_pods2, origin_renaming_map2);

        // make a list of the operations we want to call

        let ops = vec![
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("oraclePODParent", "VALUEOF:a scalar entry"),
                    StatementRef("p3", "VALUEOF:bar"),
                ),
                "eq2",
            ),
            OpCmd(
                Op::TransitiveEqualityFromStatements(
                    StatementRef("oraclePODParent", "EQUAL:eq1"),
                    StatementRef("_SELF", "EQUAL:eq2"),
                ),
                "EQUAL:transitive eq",
            ),
            OpCmd(Op::NewEntry(entry9.clone()), "entry for claimed sum"),
            OpCmd(
                Op::SumOf(
                    StatementRef("_SELF", "VALUEOF:entry for claimed sum"),
                    StatementRef("oraclePODParent", "VALUEOF:p1-apple"),
                    StatementRef("oraclePODParent", "VALUEOF:a scalar entry"),
                ),
                "sumof entry",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef(
                    "oraclePODParent",
                    "VALUEOF:schnorrPOD2-signer",
                )),
                "p2-signer",
            ),
            OpCmd(
                Op::GtToNonequality(StatementRef(
                    "oraclePODParent",
                    "GT:apple banana comparison",
                )),
                "apple banana nonequality",
            ),
        ];

        let oracle_pod2 = POD::execute_oracle_gadget(&gpg_input, &ops).unwrap();
        for statement in oracle_pod2.payload.statements_list.iter() {
            println!("{:?}", statement);
        }
        assert!(oracle_pod2.verify()? == true);
        Ok(())
    }

    #[test]
    fn goodboy_test() -> Result<()> {
        // A HackMD detailing execution and how each statement gets deduced is available here https://hackmd.io/@gubsheep/B1Rajmik1g

        let protocol = SchnorrSigner::new();

        let alice_sk = SchnorrSecretKey { sk: 25 };
        let alice_pk = protocol.keygen(&alice_sk).pk;
        let bob_sk = SchnorrSecretKey { sk: 26 };
        let bob_pk = protocol.keygen(&bob_sk).pk;
        let charlie_sk = SchnorrSecretKey { sk: 27 };
        let charlie_pk = protocol.keygen(&charlie_sk).pk;

        let goog_sk = SchnorrSecretKey { sk: 28 };
        let goog_pk = protocol.keygen(&goog_sk).pk;
        let msft_sk = SchnorrSecretKey { sk: 29 };
        let msft_pk = protocol.keygen(&msft_sk).pk;
        let fb_sk = SchnorrSecretKey { sk: 30 };
        let fb_pk = protocol.keygen(&fb_sk).pk;

        let known_attestors = vec![goog_pk, msft_pk, fb_pk];

        let gb1_user = Entry::new_from_scalar("user", bob_pk);
        let gb1_age = Entry::new_from_scalar("age", GoldilocksField(27));
        let gb1 = POD::execute_schnorr_gadget(&vec![gb1_user.clone(), gb1_age.clone()], &goog_sk);

        let gb2_user = Entry::new_from_scalar("user", bob_pk);
        let gb2 = POD::execute_schnorr_gadget(&vec![gb2_user.clone()], &msft_sk);

        let gb3_user = Entry::new_from_scalar("user", charlie_pk);
        let gb3_age = Entry::new_from_scalar("age", GoldilocksField(18));
        let gb3 = POD::execute_schnorr_gadget(&vec![gb3_user.clone(), gb3_age.clone()], &msft_sk);

        let gb4_user = Entry::new_from_scalar("user", charlie_pk);
        let gb4 = POD::execute_schnorr_gadget(&vec![gb4_user.clone()], &fb_sk);

        let alice_user_entry = Entry::new_from_scalar("user", alice_pk);
        let known_attestors_entry = Entry::new_from_vec("known_attestors", known_attestors.clone());

        let bob_alice = POD::execute_schnorr_gadget(&vec![alice_user_entry.clone()], &bob_sk);
        let charlie_alice =
            POD::execute_schnorr_gadget(&vec![alice_user_entry.clone()], &charlie_sk);

        // make the "bob trusted friend" POD
        let mut bob_tf_input_pods = HashMap::new();
        bob_tf_input_pods.insert("bob-gb1".to_string(), gb1.clone());
        bob_tf_input_pods.insert("bob-gb2".to_string(), gb2.clone());
        bob_tf_input_pods.insert("bob-alice".to_string(), bob_alice.clone());

        let bob_tf_input = GPGInput::new(bob_tf_input_pods, HashMap::new());

        let bob_tf_ops = vec![
            OpCmd(
                Op::CopyStatement(StatementRef("bob-alice", "VALUEOF:_signer")),
                "bob-alice signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("bob-alice", "VALUEOF:user")),
                "bob-alice user",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("bob-gb1", "VALUEOF:age")),
                "bob age",
            ),
            OpCmd(
                Op::NewEntry(known_attestors_entry.clone()),
                "known_attestors",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("bob-alice", "VALUEOF:_signer"),
                    StatementRef("bob-gb1", "VALUEOF:user"),
                ),
                "gb1 attests to correct user",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("bob-alice", "VALUEOF:_signer"),
                    StatementRef("bob-gb2", "VALUEOF:user"),
                ),
                "gb2 attests to correct user",
            ),
            OpCmd(
                Op::NonequalityFromEntries(
                    StatementRef("bob-gb1", "VALUEOF:_signer"),
                    StatementRef("bob-gb2", "VALUEOF:_signer"),
                ),
                "gb1 and gb2 are different",
            ),
            OpCmd(
                Op::ContainsFromEntries(
                    StatementRef("_SELF", "VALUEOF:known_attestors"),
                    StatementRef("bob-gb1", "VALUEOF:_signer"),
                ),
                "gb1 has known signer",
            ),
            OpCmd(
                Op::ContainsFromEntries(
                    StatementRef("_SELF", "VALUEOF:known_attestors"),
                    StatementRef("bob-gb2", "VALUEOF:_signer"),
                ),
                "gb2 has known signer",
            ),
        ];

        let bob_tf = POD::execute_oracle_gadget(&bob_tf_input, &bob_tf_ops).unwrap();
        assert!(bob_tf.verify()? == true);

        // make the "bob trusted friend" POD
        let mut charlie_tf_input_pods = HashMap::new();
        charlie_tf_input_pods.insert("charlie-gb3".to_string(), gb3.clone());
        charlie_tf_input_pods.insert("charlie-gb4".to_string(), gb4.clone());
        charlie_tf_input_pods.insert("charlie-alice".to_string(), charlie_alice.clone());

        let charlie_tf_input = GPGInput::new(charlie_tf_input_pods, HashMap::new());

        let charlie_tf_ops = vec![
            OpCmd(
                Op::CopyStatement(StatementRef("charlie-alice", "VALUEOF:_signer")),
                "charlie-alice signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("charlie-alice", "VALUEOF:user")),
                "charlie-alice user",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("charlie-gb3", "VALUEOF:age")),
                "charlie age",
            ),
            OpCmd(
                Op::NewEntry(known_attestors_entry.clone()),
                "known_attestors",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("charlie-alice", "VALUEOF:_signer"),
                    StatementRef("charlie-gb3", "VALUEOF:user"),
                ),
                "gb3 attests to correct user",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("charlie-alice", "VALUEOF:_signer"),
                    StatementRef("charlie-gb4", "VALUEOF:user"),
                ),
                "gb4 attests to correct user",
            ),
            OpCmd(
                Op::NonequalityFromEntries(
                    StatementRef("charlie-gb3", "VALUEOF:_signer"),
                    StatementRef("charlie-gb4", "VALUEOF:_signer"),
                ),
                "gb3 and gb4 are different",
            ),
            OpCmd(
                Op::ContainsFromEntries(
                    StatementRef("_SELF", "VALUEOF:known_attestors"),
                    StatementRef("charlie-gb3", "VALUEOF:_signer"),
                ),
                "gb3 has known signer",
            ),
            OpCmd(
                Op::ContainsFromEntries(
                    StatementRef("_SELF", "VALUEOF:known_attestors"),
                    StatementRef("charlie-gb4", "VALUEOF:_signer"),
                ),
                "gb4 has known signer",
            ),
        ];

        let charlie_tf = POD::execute_oracle_gadget(&charlie_tf_input, &charlie_tf_ops).unwrap();
        assert!(charlie_tf.verify()? == true);

        // make the "great boy" POD
        let age_bound_entry = Entry::new_from_scalar("known_attestors", GoldilocksField(17));
        let age_sum_entry = Entry::new_from_scalar("age_sum", GoldilocksField(45));
        let mut grb_input_pods = HashMap::new();
        grb_input_pods.insert("friend1".to_string(), bob_tf.clone());
        grb_input_pods.insert("friend2".to_string(), charlie_tf.clone());

        // make a map of (pod name, old origin name) to new origin name
        let mut grb_origin_rename_map = HashMap::new();
        // let's keep the name of the first origin and shorten the name of the second origin
        grb_origin_rename_map.insert(
            ("friend1".to_string(), "bob-gb1".to_string()),
            "gb1".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend1".to_string(), "bob-gb2".to_string()),
            "gb2".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend1".to_string(), "bob-alice".to_string()),
            "friend1-attest".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend2".to_string(), "charlie-gb3".to_string()),
            "gb3".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend2".to_string(), "charlie-gb4".to_string()),
            "gb4".to_string(),
        );
        grb_origin_rename_map.insert(
            ("friend2".to_string(), "charlie-alice".to_string()),
            "friend2-attest".to_string(),
        );

        let grb_input = GPGInput::new(grb_input_pods, grb_origin_rename_map);

        let grb_ops = vec![
            OpCmd(
                Op::CopyStatement(StatementRef("friend1", "VALUEOF:bob-alice user")),
                "friend1 attested user",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("friend2", "VALUEOF:charlie-alice user")),
                "friend2 attested user",
            ),
            OpCmd(Op::NewEntry(age_bound_entry.clone()), "age_bound"),
            OpCmd(Op::NewEntry(age_sum_entry.clone()), "age_sum"),
            OpCmd(
                Op::NewEntry(known_attestors_entry.clone()),
                "known_attestors",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("friend1", "VALUEOF:known_attestors"),
                    StatementRef("_SELF", "VALUEOF:known_attestors"),
                ),
                "friend1 known_attestors same as _SELF",
            ),
            OpCmd(
                Op::EqualityFromEntries(
                    StatementRef("friend2", "VALUEOF:known_attestors"),
                    StatementRef("_SELF", "VALUEOF:known_attestors"),
                ),
                "friend2 known_attestors same as _SELF",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("friend1", "EQUAL:gb1 attests to correct user")),
                "gb1 attests to correct user",
            ),
            OpCmd(
                Op::RenameContainedBy(
                    StatementRef("friend1", "CONTAINS:gb1 has known signer"),
                    StatementRef("_SELF", "EQUAL:friend1 known_attestors same as _SELF"),
                ),
                "gb1 has known signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("friend1", "EQUAL:gb2 attests to correct user")),
                "gb2 attests to correct user",
            ),
            OpCmd(
                Op::RenameContainedBy(
                    StatementRef("friend1", "CONTAINS:gb2 has known signer"),
                    StatementRef("_SELF", "EQUAL:friend1 known_attestors same as _SELF"),
                ),
                "gb2 has known signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef(
                    "friend1",
                    "NOTEQUAL:gb1 and gb2 are different",
                )),
                "gb1 and gb2 are different",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("friend2", "EQUAL:gb3 attests to correct user")),
                "gb3 attests to correct user",
            ),
            OpCmd(
                Op::RenameContainedBy(
                    StatementRef("friend2", "CONTAINS:gb3 has known signer"),
                    StatementRef("_SELF", "EQUAL:friend2 known_attestors same as _SELF"),
                ),
                "gb3 has known signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef("friend2", "EQUAL:gb4 attests to correct user")),
                "gb4 attests to correct user",
            ),
            OpCmd(
                Op::RenameContainedBy(
                    StatementRef("friend2", "CONTAINS:gb4 has known signer"),
                    StatementRef("_SELF", "EQUAL:friend2 known_attestors same as _SELF"),
                ),
                "gb4 has known signer",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef(
                    "friend2",
                    "NOTEQUAL:gb3 and gb4 are different",
                )),
                "gb4 attests to correct user",
            ),
            OpCmd(
                Op::NonequalityFromEntries(
                    StatementRef("friend1", "VALUEOF:bob-alice signer"),
                    StatementRef("friend2", "VALUEOF:charlie-alice signer"),
                ),
                "friend1 and friend2 are different",
            ),
            OpCmd(
                Op::GtFromEntries(
                    StatementRef("friend1", "VALUEOF:bob age"),
                    StatementRef("_SELF", "VALUEOF:age_bound"),
                ),
                "friend1 is at least 18",
            ),
            OpCmd(
                Op::GtFromEntries(
                    StatementRef("friend2", "VALUEOF:charlie age"),
                    StatementRef("_SELF", "VALUEOF:age_bound"),
                ),
                "friend2 is at least 18",
            ),
            OpCmd(
                Op::SumOf(
                    StatementRef("_SELF", "VALUEOF:age_sum"),
                    StatementRef("friend1", "VALUEOF:bob age"),
                    StatementRef("friend2", "VALUEOF:charlie age"),
                ),
                "sum of friend1 and friend2 ages",
            ),
        ];

        let alice_grb = POD::execute_oracle_gadget(&grb_input, &grb_ops).unwrap();
        assert!(alice_grb.verify()? == true);

        for statement in alice_grb.payload.statements_list {
            println!("{:?}", statement);
        }

        Ok(())
    }

    #[test]
    fn final_pod_test() -> Result<()> {
        // In this test we will execute this PEX script below and generate final-pod using
        // The oracle gadget on 4 different SchnorrPOD assigned to Alice, Bob, and Charlie

        // [createpod final-pod  ; Charlie's pod (multiplayer execution from Alice and Bob)
        //  remote-max [max [from @alice [pod? [result [+ [pod? [x]] [pod? [z]]]]]]
        //                  [from @bob [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
        //
        //  local-sum [+ [pod? [local-value]] 42]
        //
        //  overall-max [max remote-max
        //                   local-sum]]

        let alice_sk = SchnorrSecretKey { sk: 25 };
        let bob_sk = SchnorrSecretKey { sk: 26 };
        let charlie_sk = SchnorrSecretKey { sk: 27 };
        // Let's create simple-pod-1

        // [createpod simple-pod-1  ; Alice's first pod
        //   x 10
        //   y 20]

        let simple_pod_1_x = Entry::new_from_scalar("x", GoldilocksField(10));
        let simple_pod_1_y = Entry::new_from_scalar("y", GoldilocksField(20));

        let simple_pod_1 = POD::execute_schnorr_gadget(
            &vec![simple_pod_1_x.clone(), simple_pod_1_y.clone()],
            &alice_sk,
        );

        // ^
        // [defpod simple-pod-1
        //   x 10
        //   y 20
        //   :meta [[user @alice]]]

        // Let's create simple-pod-2

        // [createpod simple-pod-2  ; Alice's second pod
        //   z 15
        //   w 25]

        let simple_pod_2_z = Entry::new_from_scalar("z", GoldilocksField(15));
        let simple_pod_2_w = Entry::new_from_scalar("w", GoldilocksField(25));

        let simple_pod_2 = POD::execute_schnorr_gadget(
            &vec![simple_pod_2_z.clone(), simple_pod_2_w.clone()],
            &alice_sk,
        );

        // [defpod simple-pod-2
        //   z 15
        //   w 25
        //   :meta [[user @alice]]]

        // Let's create simple-pod-3

        // [createpod simple-pod-3  ; Bob's pod
        //   a 30
        //   b 40]

        let simple_pod_3_a = Entry::new_from_scalar("a", GoldilocksField(30));
        let simple_pod_3_b = Entry::new_from_scalar("b", GoldilocksField(40));

        let simple_pod_3 = POD::execute_schnorr_gadget(
            &vec![simple_pod_3_a.clone(), simple_pod_3_b.clone()],
            &bob_sk,
        );

        // [defpod simple-pod-3
        //   a 30
        //   b 40
        //   :meta [[user @bob]]]

        // Let's create Charlie's local pod

        // [createpod simple-pod-4  ; Charlie's pod
        //   local-value 100]

        let simple_pod_4_local_value = Entry::new_from_scalar("local-value", GoldilocksField(100));

        let simple_pod_4 =
            POD::execute_schnorr_gadget(&vec![simple_pod_4_local_value.clone()], &charlie_sk);

        // Now let's create the sum-pod using the Oracle gadget

        // [createpod sum-pod  ; Alice's sum pod
        //   result [+ [pod? [x]]    ; Get x from Alice's simple-pod-1
        //             [pod? [z]]]]  ; Get z from Alice's simple-pod-2

        let mut sum_pod_input_pods = HashMap::new();
        sum_pod_input_pods.insert("pod-1".to_string(), simple_pod_1.clone());
        sum_pod_input_pods.insert("pod-2".to_string(), simple_pod_2.clone());

        // No need to do origin remapping because it's all SELF
        let sum_pod_input = GPGInput::new(sum_pod_input_pods, HashMap::new());

        // Note to Ryan: a better way to do these OperationCmd is to have an enum with different
        // Fields inside it for each operation
        // In fact we could probably do the same for statement where it would be a big enum type
        // We wouldn't have as many Some and None everywhere.

        let sum_pod_ops = vec![
            // If we have this operation, we would copy X and reveal it. Here we don't copy X (we just prove that 25 is the sum of x and z)
            // OpCmd(
            //     Op::CopyStatement(StatementRef("pod-1", "VALUEOF:x")), // a pointer to simple_pod_1, using the sum_pod_input_pods HashMap
            //     // this name comes from applying the predicate name (from predicate_name) followed by the
            //     // statement name
            //     "pod-1-value-of-x",
            // ),
            OpCmd(
                Op::NewEntry(Entry::new_from_scalar("result", GoldilocksField(10 + 15))), // We store simple-pod-1.x + simple-pod-2.z in a new entry
                "result", // statement name are only used to have operations point at statement (poor man's pointer)
                          // they are not cryptographic, hence why we need another name beyond the optional entry
            ),
            OpCmd(
                Op::SumOf(
                    StatementRef("_SELF", "VALUEOF:result"),
                    StatementRef("pod-2", "VALUEOF:z"),
                    StatementRef("pod-1", "VALUEOF:x"),
                ),
                "sum-of-pod-1-x-and-pod-2-z",
            ),
        ];

        let sum_pod = POD::execute_oracle_gadget(&sum_pod_input, &sum_pod_ops).unwrap();
        assert!(sum_pod.verify()? == true);

        // [defpod sum-pod
        //   result 25
        //   :meta [[user @alice]
        //          [result [+ [pod? [x]] [pod? [z]]]]]]

        // Now let's create the product-pod using the Oracle gadget

        // [createpod product-pod  ; Bob's product pod
        //   result [* [pod? [a]]    ; Get a from Bob's simple-pod-3
        //             [pod? [b]]]]  ; Get b from Bob's simple-pod-3

        let mut product_pod_input_pods = HashMap::new();
        product_pod_input_pods.insert("pod-3".to_string(), simple_pod_3.clone());

        // No need to do origin remapping because it's all SELF
        let product_pod_input = GPGInput::new(product_pod_input_pods, HashMap::new());

        let product_pod_ops = vec![
            OpCmd(
                Op::NewEntry(Entry::new_from_scalar("result", GoldilocksField(30 * 40))),
                "result",
            ),
            OpCmd(
                Op::ProductOf(
                    StatementRef("_SELF", "VALUEOF:result"),
                    StatementRef("pod-3", "VALUEOF:a"),
                    StatementRef("pod-3", "VALUEOF:b"),
                ),
                "product-of-pod-3-a-and-pod-3-b",
            ),
        ];

        let product_pod = POD::execute_oracle_gadget(&product_pod_input, &product_pod_ops).unwrap();
        assert!(product_pod.verify()? == true);

        // [defpod product-pod
        //   result 1200
        //   :meta [[user @bob]
        //          [result [* [pod? [a]] [pod? [b]]]]]]

        // And finally, now let's put together the final POD
        // Because the Oracle Gadget is meant to receive all the PODs involved in the computation
        // Details on where the POD comes from (like from @alice or from @bob) will not be visible in the operations below
        // You can think of the Oracle gadget as a magic box into which we put all the input PODs and we compute the output

        // [createpod final-pod  ; Charlie's pod (multiplayer execution from Alice and Bob)
        //   remote-max [max [from @alice [pod? [result [+ [pod? [x]] [pod? [z]]]]]]
        //                   [from @bob [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
        //
        //   local-sum [+ [pod? [local-value]] 42]
        //
        //   overall-max [max remote-max
        //                    local-sum]]

        let mut final_pod_input_pods = HashMap::new();
        final_pod_input_pods.insert("sum-pod".to_string(), sum_pod.clone());
        final_pod_input_pods.insert("product-pod".to_string(), product_pod.clone());
        final_pod_input_pods.insert("simple-pod-4".to_string(), simple_pod_4.clone());

        // We need to remap the origins that are in product-pod and sum-pod. They can't just
        // become product-pod and sum-pod, they need their own name
        // We'll simply collapse them to pod-1, pod-2, pod-3 given there is no name clash here
        // (ie: an origin in sum-pod doesn't clash with an origin in product-pod)
        let mut final_pod_origin_renaming_map = HashMap::new();
        final_pod_origin_renaming_map.insert(
            ("sum-pod".to_string(), "pod-1".to_string()),
            "pod-1".to_string(),
        );
        final_pod_origin_renaming_map.insert(
            ("sum-pod".to_string(), "pod-2".to_string()),
            "pod-2".to_string(),
        );
        final_pod_origin_renaming_map.insert(
            ("product-pod".to_string(), "pod-3".to_string()),
            "pod-3".to_string(),
        );
        // Note to Ryan: remapping is unnecessary if we don't have strings as poor man's pointer
        // It would never be ambiguous what we are referring to
        // However the serialization story is unknown. Maybe we use content ID as origin.
        // The issue with content ID is they can leak data because you can brute force a hidden
        // value if you happen to know all of them but that one (keep hashing different value till you get to the same ID)
        let final_pod_input = GPGInput::new(final_pod_input_pods, final_pod_origin_renaming_map);

        let final_pod_ops = vec![
            // We copy the ProductOf and SumOf statement from product-pod and sum-pod
            // To carry over that part of the computational graph
            // We want final-pod's remote-max to be clearly the max of two entries called
            // "result" that came from the sum and the product of other pods
            // We could have remote-max be the max of two pod (and stop there)
            // But this is not what is being expressed in the createpod of final-pod
            OpCmd(
                Op::CopyStatement(StatementRef("sum-pod", "SUMOF:sum-of-pod-1-x-and-pod-2-z")),
                "sum-of-pod-1-x-and-pod-2-z",
            ),
            OpCmd(
                Op::CopyStatement(StatementRef(
                    "product-pod",
                    "PRODUCTOF:product-of-pod-3-a-and-pod-3-b",
                )),
                "product-of-pod-3-a-and-pod-3-b",
            ),
            OpCmd(
                Op::NewEntry(Entry::new_from_scalar("remote-max", GoldilocksField(1200))),
                "remote-max",
            ),
            OpCmd(
                Op::MaxOf(
                    StatementRef("_SELF", "VALUEOF:remote-max"),
                    StatementRef("sum-pod", "VALUEOF:result"),
                    StatementRef("product-pod", "VALUEOF:result"),
                ),
                "max-sum-pod-and-product-pod",
            ),
            OpCmd(
                Op::NewEntry(Entry::new_from_scalar("42", GoldilocksField(42))),
                "42",
            ),
            OpCmd(
                Op::NewEntry(Entry::new_from_scalar("local-sum", GoldilocksField(142))),
                "local-sum",
            ),
            OpCmd(
                Op::SumOf(
                    StatementRef("_SELF", "VALUEOF:local-sum"),
                    StatementRef("simple-pod-4", "VALUEOF:local-value"),
                    StatementRef("_SELF", "VALUEOF:42"),
                ),
                "sum-of-simple-pod-4-local-value-and-42",
            ),
            OpCmd(
                Op::NewEntry(Entry::new_from_scalar("overall-max", GoldilocksField(1200))),
                "overall-max",
            ),
            OpCmd(
                Op::MaxOf(
                    StatementRef("_SELF", "VALUEOF:overall-max"),
                    StatementRef("_SELF", "VALUEOF:remote-max"),
                    StatementRef("_SELF", "VALUEOF:local-sum"),
                ),
                "max-of-remote-max-and-local-max",
            ),
        ];

        let final_pod = POD::execute_oracle_gadget(&final_pod_input, &final_pod_ops).unwrap();
        assert!(final_pod.verify()? == true);

        // If you are curious what the statements in this POD are
        // for statement in final_pod.payload.statements_list {
        //     println!("{:?}", statement);
        // }

        // [defpod final-pod
        //   remote-max 1200
        //   local-sum 142
        //   overall-max 1200
        //   :meta [[user @charlie]
        //          [remote-max [max [pod? [result [+ [pod? [x]] [pod? [z]]]]]
        //                           [pod? [result [* [pod? [a]] [pod? [b]]]]]]]
        //          [local-sum [+ [pod? [local-value]] 42]]
        //          [overall-max [max local-sum
        //                            custom-sum]]]]

        Ok(())
    }
}
