use ark_ff::Field;
use std::collections::HashMap;

pub struct PlonkCircuit<F: Field> {
    pub n_vars: u32,
    pub pub_vars: HashMap<Var, String>,
    pub prods: Vec<(Var, Var, Var)>,
    pub sums: Vec<(Var, Var, Var)>,
    pub values: Option<Vec<F>>,
}

type Var = u32;

impl<F: Field> PlonkCircuit<F> {
    pub fn new(values: bool) -> Self {
        Self {
            n_vars: 0,
            pub_vars: HashMap::new(),
            prods: Vec::new(),
            sums: Vec::new(),
            values: if values { Some(Vec::new()) } else { None },
        }
    }
    pub fn new_var(&mut self, value: impl FnOnce() -> F) -> Var {
        self.n_vars += 1;
        self.values.as_mut().map(|v| v.push(value()));
        self.n_vars - 1
    }
    pub fn publicize_var(&mut self, v: Var, name: String) {
        if let Some(old_name) = self.pub_vars.insert(v, name) {
            panic!(
                "Variable {} was already public as {:?}, but is now being bound to {:?}",
                v, old_name, self.pub_vars[&v]
            );
        }
    }
    pub fn new_sum(&mut self, a: Var, b: Var) -> Var {
        self.values.as_mut().map(|v| {
            let o = v[a as usize] + v[b as usize];
            v.push(o);
        });
        self.sums.push((a, b, self.n_vars));
        self.n_vars += 1;
        self.n_vars - 1
    }
    pub fn new_prod(&mut self, a: Var, b: Var) -> Var {
        self.values.as_mut().map(|v| {
            let o = v[a as usize] * v[b as usize];
            v.push(o);
        });
        self.prods.push((a, b, self.n_vars));
        self.n_vars += 1;
        self.n_vars - 1
    }
    pub fn new_pub_var(&mut self, value: impl FnOnce() -> F, name: String) -> Var {
        let v = self.new_var(value);
        self.publicize_var(v, name);
        v
    }
    pub fn n_gates(&self) -> usize {
        self.prods.len() + self.sums.len()
    }
    pub fn pad_to_power_of_2(&mut self) {
        let n = self.n_gates().next_power_of_two();
        assert!(self.n_vars > 0, "Cannot pad an empty circuit!");
        for _ in self.n_gates()..n {
            let v = self.n_vars - 1;
            self.new_sum(v, v);
        }
        assert!(self.n_gates().is_power_of_two());
    }
    pub fn new_squaring_circuit(steps: usize, start: Option<F>) -> Self {
        let mut self_ = PlonkCircuit::new(start.is_some());
        let mut v = self_.new_var(|| start.unwrap());
        for _ in 0..steps {
            v = self_.new_prod(v, v);
        }
        self_.pad_to_power_of_2();
        self_.publicize_var(v, "out".to_owned());
        self_
    }
}
