// Fibonacci Trace Generation - Week 5 Phase 1
//
// User: PERFECT TOTAL, approved Week 5-6 plan
//
// This implements trace generation for Fibonacci AIR
// Trace format: 2 columns [F(n), F(n+1)]
// Example for 8 steps:
// Step 0: [0, 1]
// Step 1: [1, 1]
// Step 2: [1, 2]
// Step 3: [2, 3]
// Step 4: [3, 5]
// Step 5: [5, 8]
// Step 6: [8, 13]
// Step 7: [13, 21]

use winterfell::math::fields::f128::BaseElement;
use winterfell::{Trace, TraceTable};

/// Fibonacci execution trace
///
/// Generates a 2-column trace that proves Fibonacci sequence computation.
/// Column 0: F(n)
/// Column 1: F(n+1)
pub struct FibonacciTrace {
    trace: TraceTable<BaseElement>,
}

impl FibonacciTrace {
    /// Creates a new Fibonacci trace for the given number of steps
    ///
    /// # Arguments
    /// * `steps` - Number of steps in the trace (must be >= 8 and power of 2)
    ///
    /// # Returns
    /// A FibonacciTrace containing the Fibonacci sequence
    pub fn new(steps: usize) -> Self {
        assert!(steps >= 8, "trace must have at least 8 steps");
        assert!(steps.is_power_of_two(), "trace length must be power of 2");

        // Generate Fibonacci sequence
        // Column 0: F(n)
        // Column 1: F(n+1)
        let mut col0 = Vec::with_capacity(steps);
        let mut col1 = Vec::with_capacity(steps);

        // Initialize: F(0) = 0, F(1) = 1
        let mut a = 0u64;
        let mut b = 1u64;

        for _ in 0..steps {
            // Add to columns
            col0.push(BaseElement::new(a as u128));
            col1.push(BaseElement::new(b as u128));

            // Compute next Fibonacci number
            let next = a + b;
            a = b;
            b = next;
        }

        // Create trace table: vec of column vectors
        let trace = TraceTable::init(vec![col0, col1]);

        Self { trace }
    }

    /// Returns the final Fibonacci number (F(n))
    pub fn get_result(&self) -> BaseElement {
        let last_step = self.trace.length() - 1;
        self.trace.get(1, last_step)
    }

    /// Returns the trace length
    pub fn length(&self) -> usize {
        self.trace.length()
    }

    /// Returns the trace width (always 2 for Fibonacci)
    pub fn width(&self) -> usize {
        self.trace.width()
    }

    /// Gets a value from the trace at the specified column and step
    pub fn get(&self, col: usize, step: usize) -> BaseElement {
        self.trace.get(col, step)
    }
}

impl Trace for FibonacciTrace {
    type BaseField = BaseElement;

    fn length(&self) -> usize {
        self.trace.length()
    }

    fn info(&self) -> &winterfell::TraceInfo {
        self.trace.info()
    }

    fn read_main_frame(
        &self,
        row_idx: usize,
        frame: &mut winterfell::EvaluationFrame<Self::BaseField>,
    ) {
        let next_idx = (row_idx + 1) % self.length();

        frame.current_mut()[0] = self.trace.get(0, row_idx);
        frame.current_mut()[1] = self.trace.get(1, row_idx);
        frame.next_mut()[0] = self.trace.get(0, next_idx);
        frame.next_mut()[1] = self.trace.get(1, next_idx);
    }

    fn main_segment(&self) -> &winterfell::matrix::ColMatrix<Self::BaseField> {
        self.trace.main_segment()
    }
}

// Week 5 Phase 1: Trace Generation
// NO MOCK, PERFECT TOTAL

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fibonacci_trace_creation() {
        let trace = FibonacciTrace::new(8);
        assert_eq!(trace.length(), 8);
        assert_eq!(trace.width(), 2);
    }

    #[test]
    fn test_fibonacci_trace_values() {
        let trace = FibonacciTrace::new(8);

        // Step 0: [0, 1]
        assert_eq!(trace.get(0, 0), BaseElement::new(0));
        assert_eq!(trace.get(1, 0), BaseElement::new(1));

        // Step 1: [1, 1]
        assert_eq!(trace.get(0, 1), BaseElement::new(1));
        assert_eq!(trace.get(1, 1), BaseElement::new(1));

        // Step 2: [1, 2]
        assert_eq!(trace.get(0, 2), BaseElement::new(1));
        assert_eq!(trace.get(1, 2), BaseElement::new(2));

        // Step 3: [2, 3]
        assert_eq!(trace.get(0, 3), BaseElement::new(2));
        assert_eq!(trace.get(1, 3), BaseElement::new(3));

        // Step 7: [13, 21]
        assert_eq!(trace.get(0, 7), BaseElement::new(13));
        assert_eq!(trace.get(1, 7), BaseElement::new(21));
    }

    #[test]
    fn test_fibonacci_trace_result() {
        let trace = FibonacciTrace::new(8);
        // F(7) = 13 (in column 1, step 7)
        assert_eq!(trace.get_result(), BaseElement::new(21));
    }

    #[test]
    #[should_panic(expected = "trace must have at least 8 steps")]
    fn test_fibonacci_trace_too_short() {
        FibonacciTrace::new(4);
    }

    #[test]
    #[should_panic(expected = "trace length must be power of 2")]
    fn test_fibonacci_trace_not_power_of_2() {
        FibonacciTrace::new(10);
    }

    #[test]
    fn test_fibonacci_trace_larger() {
        let trace = FibonacciTrace::new(16);
        assert_eq!(trace.length(), 16);
        assert_eq!(trace.width(), 2);

        // F(16) should be in column 1, step 15
        // Fibonacci: 0,1,1,2,3,5,8,13,21,34,55,89,144,233,377,610,987
        // At step 15: col0=610, col1=987
        assert_eq!(trace.get(1, 15), BaseElement::new(987));
    }
}
