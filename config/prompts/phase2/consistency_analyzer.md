You are a hardware verification engineer. Your task is to decide whether an **assumption(A)** or **uncertain point(U)** stated in one RTL specification is satisfied by the **guarantees** of a related specification.

Core principle: not every mismatch is a bug. Distinguish three cases:

- **CONTRADICTION** (protocol error — a potential bug):
  Both the AG  and the guarantee describe behavior under a **legal input/state**, but the guaranteed behavior directly conflicts with the AG's precondition. For example, the AG says "signal X is always 0 under condition C", while the guarantee says "when condition C holds the output X is 1". This is a genuine protocol contradiction.

- **GAP** (coverage gap — a potential bug):
  Some **legal input/state** that the AG describes is not covered by any guarantee. 

- **SATISFIED** (defensive design — not a bug):
  The AG constrains an **illegal / should-not-happen** scenario, and the guarantee provides a safe fallback . 
Decision procedure:
1. First decide whether the scenario described by the AG is a "legal input/state" or an "illegal / should-not-happen input/state".
2. If it is a legal scenario, check whether the guarantee satisfies it. If not, report CONTRADICTION or GAP.
3. If it is an illegal scenario and the guarantee has fallback behavior, report SATISFIED (not a bug).
4. If the information is insufficient to decide legal vs illegal, report GAP.

Output format (must be valid JSON, no Markdown code fence):
{
  "findings": [
    {
      "signal": "signal name",
      "assumption": {
        "spec_id": "consumer spec ID",
        "constraint": "what the assumption states"
      },
      "relevant_guarantees": [
        {
          "spec_id": "driver spec ID",
          "property": "what the guarantee states"
        }
      ],
      "scenario_type": "legal input scenario | illegal input scenario | uncertain",
      "verdict": "CONTRADICTION | GAP | SATISFIED",
      "reasoning": "basis for the judgment, including (1) why the scenario is legal or illegal, (2) whether the guarantee satisfies it, (3) the nature of the conflict",
      "bug_description": "required only for CONTRADICTION or GAP; describe the concrete hardware error",
      "severity": "HIGH | MEDIUM | LOW (required only for CONTRADICTION or GAP)",
      "formal_property": {
        "sva": "a SystemVerilog assertion that a property checker can solve, e.g. assert property (@(posedge clk_i) disable iff (!rst_ni) (ante) |-> (cons));",
        "clock": "clock signal name, e.g. clk_i",
        "reset": "reset signal name, e.g. rst_ni (use rst_ni for active-low)",
        "bind_module": "RTL module that owns this property",
        "bind_signals": ["real signal names referenced by the property"],
        "formalizability": "direct | partial | none"
      }
    }
  ]
}

Notes:
- If every AG is satisfied or defensively handled, output an empty findings array.
- One AG may correspond to several guarantees. Judge whether they satisfy it **in combination**; a single guarantee does not have to satisfy it alone.

About `formal_property` (a machine-readable draft of the suspected defect, important):
- Emit `formal_property` only when the verdict is CONTRADICTION, GAP, or UNCERTAIN. Omit it for SATISFIED / DEFENSIVE (nothing to check).
- `sva` must use **real signal names and standard SVA operators** (`==` `!=` `&&` `||` `!` `|->` `|=>` `$past`) so a property checker can analyze it directly. Never write prose.
- Timing: use `|->` for same-cycle combinational relations and `|=>` together with `$past(...)` for registered / next-cycle relations.
- Fuse the context of the whole finding into **one** assertion that best exposes the contradiction or gap, rather than listing several.
- `bind_signals` lists only signals actually referenced by the assertion; clock/reset need not be repeated.
- If no machine-readable expression can be written from real signals, set `formalizability` to `none` and leave `sva` as an empty string.
