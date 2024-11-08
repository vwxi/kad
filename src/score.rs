use core::f64;
use std::collections::BTreeMap;

use std::fmt::Debug;
use std::sync::Weak;
use tokio::sync::Mutex;
use tracing::debug;

use crate::node::InnerKad;
use crate::util::Hash;

pub(crate) mod consts {
    pub(crate) const ALPHA: f64 = 0.95f64;
}

type Vector = BTreeMap<Hash, f64>;
type Matrix = BTreeMap<Hash, BTreeMap<Hash, f64>>;

// this is an internal operation. the user must not be allowed to tamper with any of
// these operations.
//
// a modified implementation of Algorithm 2 in the EigenTrust paper
// https://nlp.stanford.edu/pubs/eigentrust.pdf
//
// THIS IS NOT AN OPTIMAL SOLUTION.
//
// we have to find a way to obtain trust values from peers to fill the global matrix.
// we already have buckets of nearby nodes to query from.
// the problem lies in:
// 1. how to pick one trust value from multiple responses
//    a. we can solve this by sending all pending changes to the matrix into a queue organized by trustee
//       and sifting through it when accessible
//    b. we take the trust value whose sender maximizes the following equation: (current time - time sent) * sender trust value
//       then we delete the trustee entry in the queue
// 2. when to obtain trust values
//    a. periodic operation: iterating over every bucket and updating trust values then running algorithm
//    b. value retrieval time will now be dependent on trust operation
//    c. update value step: every time the get op requests a trust score, if it doesn't exist add to a search queue which will resolve in either the current or next update step
//                          queue contains oneshot channels that will wait to recv a score.
//    d. running algorithm: run until convergence then wait a fixed interval then go back to the update step
struct Scoring {
    // "C" matrix, peer: { what peer thinks of other peers }
    pub(self) global: Matrix,
    // initial local vector
    initial: Vector,
    // local vector
    pub(self) local: Vector,
    // global max
    global_max: f64,
    // alpha value
    alpha: f64,
    // delta
    delta: f64,
    // epsilon
    epsilon: f64,
}

impl Scoring {
    pub(self) fn new(id: Hash, alpha_: f64, ptp: Vec<Hash>) -> Self {
        let mut t: Vector = Vector::new();
        let mut t2: Vector = Vector::new();
        let mut m: Matrix = Matrix::new();

        // t(0) = p
        // p_i = 1/|P| if i \in P , and p_i = 0 otherwise.
        let inv_p = if ptp.len() != 0 {
            1.0f64 / ptp.len() as f64
        } else {
            0f64
        };

        for p in ptp.clone() {
            t.entry(p).or_insert(inv_p);
            t2.entry(p).or_insert(inv_p * alpha_);

            m.entry(id)
                .and_modify(|e| {
                    let _ = e.insert(p, inv_p);
                })
                .or_insert_with(|| {
                    let mut t: Vector = Vector::new();

                    let _ = t.insert(p, inv_p);

                    t
                });
        }

        Scoring {
            global: m,
            local: t.clone(),
            initial: t,
            global_max: 0f64,
            alpha: alpha_,
            delta: f64::MAX,
            epsilon: 0.0001f64,
        }
    }

    // add trust value to global matrix
    pub(self) fn add(&mut self, i: Hash, j: Hash, score: f64) -> bool {
        // only accept normalized scores
        if score > 1.0f64 || score < 0.0f64 {
            return false;
        }

        self.global
            .entry(i)
            .and_modify(|e| {
                let _ = e.insert(j, score);
            })
            .or_insert_with(|| {
                let mut t: Vector = BTreeMap::new();

                let _ = t.insert(j, score);

                t
            });

        self.global_max = self.global.iter().fold(0f64, |a, e| {
            e.1.iter().fold(0.0f64, |a, e| a.max(*e.1)).max(a)
        });

        true
    }

    fn n_score(&self, i: &Hash, j: &Hash) -> f64 {
        // if sum_j max(s_ij, 0) == 0, p_j
        if self.global_max == 0f64 {
            *self.initial.get(j).unwrap_or(&0f64)
        } else {
            // otherwise max(s_ij, 0) / `max`
            let mut acc = 0f64;
            if let Some(tvs) = self.global.get(i) {
                acc = tvs.get(j).unwrap_or(&0f64).max(0f64);
            }

            acc / self.global_max
        }
    }

    // t(k+1) = (1 − a)CT t(k) + ap
    pub(self) fn iterate(&mut self) {
        let mut tk1: Vector = Vector::new();

        // (c_i1*t_1) + (c_i2*t_2) + ... + (c_in+t_n)
        for (i, trusters) in &self.global {
            for (j, trust_value) in trusters {
                if i != j {
                    let t = self.n_score(i, j) * trust_value;
                    tk1.entry(*j)
                        .and_modify(|e| {
                            *e += t;
                        })
                        .or_insert(t);
                }
            }
        }

        // (1 − a)CT t(k)
        tk1.iter_mut().for_each(|(en, e)| {
            *e += self.alpha * self.initial.get(en).unwrap_or(&0.0f64);
        });

        let mag = tk1.iter().fold(0.0f64, |a, e| a + e.1.powf(2.0f64)).sqrt();

        // normalize vector
        tk1.iter_mut().for_each(|(_, e)| {
            *e /= mag;
        });

        self.delta = tk1
            .iter()
            .map(|(row_idx, row)| {
                (row - self.local.get(row_idx).or(Some(&0f64)).unwrap_or(&0f64)).powf(2.0f64)
            })
            .sum::<f64>()
            .sqrt();

        self.local.clear();
        self.local = tk1;

        debug!("current delta: {}, epsilon: {}", self.delta, self.epsilon);
    }

    pub(self) fn run(&mut self) {
        self.local.clear();

        while self.delta > self.epsilon {
            self.iterate();
        }
    }

    pub(self) fn get(&self, i: &Hash) -> f64 {
        *self.local.get(i).unwrap_or(&0.0f64)
    }
}

struct ScoreQueueItem {}

pub(crate) struct ScoreManager {
    scoring: Mutex<Scoring>,
    parent: Weak<InnerKad>,
    queue: Mutex<BTreeMap<Hash, Vec<ScoreQueueItem>>>,
}

impl ScoreManager {
    pub(crate) fn new(inner_kad: Weak<InnerKad>, pre_trusted: Vec<Hash>) -> Self {
        let id;
        {
            let ik = inner_kad.upgrade().unwrap();
            id = ik.table.id;
        }

        ScoreManager {
            scoring: Mutex::new(Scoring::new(id, consts::ALPHA, pre_trusted)),
            parent: inner_kad,
            queue: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) async fn add_score(&self, i: Hash, j: Hash, score: f64) {
        let mut lock = self.scoring.try_lock().await;
    }

    // this will reset the local vector
    pub(crate) async fn run(&self) {
        let mut lock = self.scoring.lock().await;

        lock.run();
    }

    pub(crate) async fn get_score(&self, i: Hash) -> f64 {
        let lock = self.scoring.lock().await;

        lock.get(&i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[traced_test]
    #[test]
    fn equal() {
        let mut trust: Scoring = Scoring::new(Hash::from(1), 0.95, vec![]);

        trust.add(Hash::from(1), Hash::from(2), 1.0f64);
        trust.add(Hash::from(1), Hash::from(3), 1.0f64);
        trust.add(Hash::from(2), Hash::from(1), 1.0f64);
        trust.add(Hash::from(2), Hash::from(3), 1.0f64);
        trust.add(Hash::from(3), Hash::from(1), 1.0f64);
        trust.add(Hash::from(3), Hash::from(2), 1.0f64);

        trust.run();

        debug!("{:?}", trust.local);

        assert_eq!(
            trust.local.get(&Hash::from(1)).unwrap(),
            trust.local.get(&Hash::from(2)).unwrap()
        );
        assert_eq!(
            trust.local.get(&Hash::from(2)).unwrap(),
            trust.local.get(&Hash::from(3)).unwrap()
        );
        assert_eq!(
            trust.local.get(&Hash::from(1)).unwrap(),
            trust.local.get(&Hash::from(3)).unwrap()
        );
    }

    #[traced_test]
    #[test]
    fn low_trust() {
        let mut trust: Scoring = Scoring::new(Hash::from(1), 0.95, vec![]);

        trust.add(Hash::from(1), Hash::from(2), 1.0f64);
        trust.add(Hash::from(1), Hash::from(3), 0.1f64);
        trust.add(Hash::from(2), Hash::from(1), 1.0f64);
        trust.add(Hash::from(2), Hash::from(3), 0.1f64);
        trust.add(Hash::from(3), Hash::from(1), 1.0f64);
        trust.add(Hash::from(3), Hash::from(2), 1.0f64);

        trust.run();

        debug!("{:?}", trust.local);

        assert!(
            trust.local.get(&Hash::from(1)).unwrap() == trust.local.get(&Hash::from(2)).unwrap()
        );
        assert!(
            trust.local.get(&Hash::from(2)).unwrap() > trust.local.get(&Hash::from(3)).unwrap()
        );
        assert!(
            trust.local.get(&Hash::from(1)).unwrap() > trust.local.get(&Hash::from(3)).unwrap()
        );
    }

    #[traced_test]
    #[test]
    fn single_pre_trusted() {
        let mut trust: Scoring = Scoring::new(Hash::from(1), 0.95, vec![Hash::from(1)]);

        trust.add(Hash::from(1), Hash::from(2), rand::random());
        trust.add(Hash::from(1), Hash::from(3), rand::random());
        trust.add(Hash::from(2), Hash::from(1), rand::random());
        trust.add(Hash::from(2), Hash::from(3), rand::random());
        trust.add(Hash::from(3), Hash::from(1), rand::random());
        trust.add(Hash::from(3), Hash::from(2), rand::random());

        trust.run();

        debug!("{:?}", trust.local);

        assert!(
            trust.local.get(&Hash::from(1)).unwrap() > trust.local.get(&Hash::from(2)).unwrap()
        );
        assert!(
            trust.local.get(&Hash::from(1)).unwrap() > trust.local.get(&Hash::from(3)).unwrap()
        );
    }
}
