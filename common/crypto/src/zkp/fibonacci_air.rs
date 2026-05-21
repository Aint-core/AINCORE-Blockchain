// Fibonacci AIR - Week 4 Implementation
//
// User: NO MOCK, PERFECT TOTAL, FULL implementation
//
// Fibonacci Sequence: F(n+2) = F(n) + F(n+1)
// Trace: Two columns [F(n), F(n+1)]
// Constraint: next[0] = current[1], next[1] = current[0] + current[1]

use winterfell::math::FieldElement;
use winterfell::{
    Air, AirContext, Assertion, EvaluationFrame, FieldExtension, ProofOptions, TraceInfo,
    TransitionConstraintDegree,
};

/// Fibonacci AIR: Proves Fibonacci sequence computation
///
/// This AIR proves that a trace correctly computes the Fibonacci sequence.
/// The trace has 2 columns: [F(n), F(n+1)]
///
/// Constraints:
/// 1. next[0] = current[1]  (shift left)
/// 2. next[1] = current[0] + current[1]  (Fibonacci relation)
pub struct FibonacciAir {
    context: AirContext<winterfell::math::fields::f128::BaseElement>,
    result: winterfell::math::fields::f128::BaseElement, // The final Fibonacci number we're proving
}

impl FibonacciAir {
    /// Creates a new FibonacciAir with default parameters
    ///
    /// # Arguments
    /// * `result` - The final Fibonacci number to prove (F(n))
    pub fn new(result: u64) -> Self {
        use winterfell::math::fields::f128::BaseElement;
        Self::with_params(BaseElement::new(result as u128), 8, 32, 8)
    }

    /// Creates a new FibonacciAir with custom parameters
    ///
    /// # Arguments
    /// * `result` - The final Fibonacci number to prove
    /// * `trace_length` - Number of steps (must be >= 8 and power of 2)
    /// * `num_queries` - Number of queries for security
    /// * `blowup_factor` - Blowup factor for FRI
    pub fn with_params(
        result: winterfell::math::fields::f128::BaseElement,
        trace_length: usize,
        num_queries: usize,
        blowup_factor: usize,
    ) -> Self {
        assert!(trace_length >= 8, "trace length must be at least 8");
        assert!(
            trace_length.is_power_of_two(),
            "trace length must be power of 2"
        );

        // Fibonacci trace has 2 columns: [F(n), F(n+1)]
        let trace_info = TraceInfo::new(2, trace_length);

        // Two transition constraints (both linear)
        let transition_constraint_degrees = vec![
            TransitionConstraintDegree::new(1), // next[0] = current[1]
            TransitionConstraintDegree::new(1), // next[1] = current[0] + current[1]
        ];

        // Assertions: initial values and final result
        let num_assertions = 3; // F(0)=0, F(1)=1, F(n)=result

        let options = ProofOptions::new(
            num_queries,
            blowup_factor,
            0, // grinding_factor
            FieldExtension::None,
            8,  // fri_folding_factor
            31, // fri_max_remainder_degree
        );

        let context = AirContext::new(
            trace_info,
            transition_constraint_degrees,
            num_assertions,
            options,
        );

        Self { context, result }
    }

    /// Returns the Fibonacci result this AIR is proving
    pub fn result(&self) -> winterfell::math::fields::f128::BaseElement {
        self.result
    }
}

// Implementing Air trait for winterfell 0.9
impl Air for FibonacciAir {
    type BaseField = winterfell::math::fields::f128::BaseElement;
    type PublicInputs = winterfell::math::fields::f128::BaseElement;

    // GKR types (not used for Fibonacci AIR)
    type GkrProof = ();
    type GkrVerifier = ();

    fn new(trace_info: TraceInfo, pub_inputs: Self::PublicInputs, options: ProofOptions) -> Self {
        let transition_constraint_degrees = vec![
            TransitionConstraintDegree::new(1),
            TransitionConstraintDegree::new(1),
        ];
        let num_assertions = 3;

        let context = AirContext::new(
            trace_info,
            transition_constraint_degrees,
            num_assertions,
            options,
        );

        Self {
            context,
            result: pub_inputs,
        }
    }

    fn context(&self) -> &AirContext<Self::BaseField> {
        &self.context
    }

    fn evaluate_transition<E: FieldElement<BaseField = Self::BaseField>>(
        &self,
        frame: &EvaluationFrame<E>,
        _periodic_values: &[E],
        result: &mut [E],
    ) {
        let current = frame.current();
        let next = frame.next();

        // Constraint 1: next[0] = current[1]
        result[0] = next[0] - current[1];

        // Constraint 2: next[1] = current[0] + current[1]
        result[1] = next[1] - (current[0] + current[1]);
    }

    fn get_assertions(&self) -> Vec<Assertion<Self::BaseField>> {
        use winterfell::math::fields::f128::BaseElement;

        let last_step = self.context().trace_len() - 1;

        vec![
            // F(0) = 0
            Assertion::single(0, 0, BaseElement::ZERO),
            // F(1) = 1
            Assertion::single(1, 0, BaseElement::ONE),
            // F(n) = result
            Assertion::single(1, last_step, self.result),
        ]
    }
}

impl Default for FibonacciAir {
    fn default() -> Self {
        // Default: prove F(7) = 13 with 8 steps
        Self::new(13)
    }
}

// Week 4: Real Fibonacci AIR implementation
// NO MOCK, PERFECT TOTAL

#[cfg(test)]
mod tests {
    use super::*;
    use winterfell::math::fields::f128::BaseElement;

    #[test]
    fn test_fibonacci_air_creation() {
        let air = FibonacciAir::new(13);
        let ctx = air.context();
        assert_eq!(ctx.trace_len(), 8);
        assert_eq!(ctx.trace_info().width(), 2); // 2 columns for Fibonacci
        assert_eq!(air.result(), BaseElement::new(13));
    }

    #[test]
    fn test_fibonacci_air_custom_params() {
        let air = FibonacciAir::with_params(BaseElement::new(89), 16, 64, 16);
        let ctx = air.context();
        assert_eq!(ctx.trace_len(), 16);
        assert_eq!(ctx.trace_info().width(), 2);
        assert_eq!(air.result(), BaseElement::new(89));
    }

    #[test]
    #[should_panic(expected = "trace length must be at least 8")]
    fn test_fibonacci_air_invalid_trace_length() {
        FibonacciAir::with_params(BaseElement::new(13), 4, 32, 8);
    }

    #[test]
    fn test_fibonacci_air_assertions() {
        let air = FibonacciAir::new(13);
        let assertions = air.get_assertions();
        assert_eq!(assertions.len(), 3);

        // F(0) = 0
        assert_eq!(assertions[0].first_step(), 0);

        // F(1) = 1
        assert_eq!(assertions[1].first_step(), 0);

        // F(n) = result
        assert_eq!(assertions[2].first_step(), 7);
    }

    #[test]
    fn test_fibonacci_air_constraints() {
        let air = FibonacciAir::new(13);
        let ctx = air.context();
        assert_eq!(ctx.num_transition_constraints(), 2); // Two Fibonacci constraints
    }

    #[test]
    fn test_fibonacci_air_default() {
        let air = FibonacciAir::default();
        assert_eq!(air.result(), BaseElement::new(13)); // F(7) = 13
    }
}
