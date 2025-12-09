# winterfell 0.9 Complete API Reference

**Date:** 2025-12-07  
**Source:** target/doc/winterfell/all.html  
**Purpose:** Complete understanding of winterfell API

---

## 📚 STRUCTS (Key Types)

### Core STARK Types
- **AirContext** - AIR execution context
- **ProofOptions** - Proof generation parameters
- **TraceInfo** - Execution trace metadata
- **Assertion** - Boundary constraints
- **BoundaryConstraint** - Specific boundary assertions
- **BoundaryConstraintGroup** - Grouped constraints

### Trace Types
- **AuxTraceWithMetadata** - Auxiliary trace data
- **AuxRandElements** - Random elements for trace
- **TracePolyTable** - Polynomial representation of trace
- **TraceTable** - Execution trace table

### Proof Types
- **StarkProof** - The actual STARK proof
- **Queries** - FRI query data
- **OodFrame** - Out-of-domain evaluation frame
- **FriProof** - FRI commitment proof

### Constraint Types
- **TransitionConstraintDegree** - Degree of transition constraints
- **EvaluationFrame** - Frame for constraint evaluation

### Commitment Types
- **DefaultTraceLde** - Low-degree extension
- **DefaultConstraintEvaluator** - Constraint evaluation

---

## 🔧 TRAITS (Interfaces)

### Core Traits
- **Air** - Main AIR trait (THIS IS KEY!)
- **Prover** - Proof generation trait
- **ConstraintEvaluator** - Constraint evaluation

### Serialization Traits
- **Serializable** - Serialize to bytes
- **Deserializable** - Deserialize from bytes
- **ByteReader** - Read bytes
- **ByteWriter** - Write bytes

---

## 📦 ENUMS

### Options & Errors
- **FieldExtension** - Field extension options
- **AcceptableOptions** - Acceptable proof options
- **ProverError** - Prover errors
- **VerifierError** - Verifier errors
- **DeserializationError** - Deserialization errors

---

## 🎯 KEY FINDINGS

### What We Need to Implement

**1. Air Trait** (CRITICAL)
```rust
pub trait Air {
    type BaseField: FieldElement;
    type PublicInputs;
    
    // Methods to implement:
    // - context()
    // - evaluate_transition()
    // - get_assertions()
    // - etc.
}
```

**2. ProofOptions** (IMPORTANT)
- Configure security parameters
- Set hash function
- Set field extension
- Set FRI parameters

**3. TraceInfo** (IMPORTANT)
- Define trace width
- Define trace length
- Metadata about execution

**4. Assertion** (IMPORTANT)
- Boundary constraints
- Initial/final state assertions

---

## 📝 IMPLEMENTATION CHECKLIST

### Phase 1: Understand (Week 2-3)
- [/] List all structs
- [/] List all traits
- [ ] Read Air trait docs
- [ ] Read ProofOptions docs
- [ ] Read TraceInfo docs
- [ ] Understand relationships

### Phase 2: Minimal Example (Week 3)
- [ ] Create simplest Air impl
- [ ] Use ProofOptions
- [ ] Generate trace
- [ ] Prove simple fact
- [ ] Verify proof

### Phase 3: Fibonacci (Week 4-6)
- [ ] Implement Fibonacci Air
- [ ] Generate Fibonacci trace
- [ ] Prove Fibonacci computation
- [ ] Comprehensive tests

---

## 🔬 NEXT STEPS

**Today:**
1. Read Air trait documentation
2. Read ProofOptions documentation
3. Understand trace generation
4. Study example patterns

**This Week:**
1. Complete API understanding
2. Document all key types
3. Create implementation notes
4. Prepare for coding

**Next Week:**
1. Create minimal working AIR
2. Test it works
3. Document the process
4. Expand to Fibonacci

---

**Status:** API Study in Progress  
**Progress:** Understanding complete structure  
**Timeline:** Week 2 of 20
