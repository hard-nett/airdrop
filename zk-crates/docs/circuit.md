
# Headstash Circuit

<!-- ## 3. Byte-To-Field Conversion Constraint

### Input Handling

- each of the 32 bytes is witnessed as separate `AssignedCell<pallas::Base,pallas::Base>` values in advice columns
- each byte is in range `0..255`, so range constraints can be applied (via `LookupRangeCheck`),enforcing each witnessed value is exactly 8 bits.

### Accumulation In The Circuit

- starts with an inital accumulator
- for each byte in the 32 bytes:
  - compute `acc = acc & pallas::Base::from(256u64) + byte` as a circuit constraint *HOW?*
  - use `plonk` constraints for mult & addition (can use left-shifts for 256)

This will result in a final `AssignedCell` that can be used as input for the next step

## 4. HKDF Via Posiedon Hash + Dropped Bits

- uses normal posiedon chip to recompute hash derived from `elig_sk||rho`
- requires 255 bits for pallasField, so to constrain this requirement we can make use of the `LookupRangeCheckConfig` for bit decomposition.
- implement boolean constraint
 

### 2. Constrain `jub_sk` has been derived from `elig_sk`

Constraining the derivation of the jubjub keypair requires the following inputs:

- **KEY_DERIVATION_DST_JUBJUB**
- **elig_sk:** `[u8;32]`
- **rho:** `pallas::Base`

We use the posiedon hash function to generate a `pallas::Base` scalar, which is used as the bytes for the `jubjub_sk`

The constraint equation is:

$$\begin{array}{lcl}
\textbf{Private witnesses} &
\begin{cases}
\mathsf{elig\_sk} \in \{0,1\}^{256}      &\text{(32‑byte eligibility secret)}\\[2pt]
\rho            \in \mathbb{F}_p          &\text{(Pallas base element)}\\[2pt]
\mathsf{jub\_sk}\in \mathbb{F}_{\ell_J}   &\text{(JubJub scalar, to be derived)}\\
\end{cases}
\\[10pt]
\textbf{Public constants} &
\begin{cases}
\mathtt{DST}_{\!J} \in \{0,1\}^{*}
   &\text{Domain‑separation tag } \texttt{KEY\_DERIVATION\_DST\_JUBJUB} \\[2pt]
\ell_J           = \texttt{CURVE\_ORDER\_JUBJUB}
   &\text{order of the JubJub scalar field } \mathbb{F}_{\ell_J}
\end{cases}
\end{array}$$

$$\begin{aligned}
\textbf{Poseidon hash} \qquad
h &\;=\; \operatorname{Poseidon}_{\mathbb{F}_p}
      \bigl(\,\mathtt{DST}_{\!J}\,\|\,\mathsf{elig\_sk}\,\|\,\rho\,\bigr)
      \in \mathbb{F}_p                                       \tag{1}
\end{aligned}$$

> `‖` denotes simple concatenation of the byte‑strings before they are interpreted as field elements for the hash.  The hash
> works over the **Pallas base field**  (the same field as `ρ`).  

$$\begin{aligned}
\mathsf{jub\_sk}
&\;=\;\operatorname{from\_repr}_{\mathbb{F}_{\ell_J}}\!\bigl(h\bigr)   \tag{2}\\[4pt]
&\;\in\; \mathbb{F}_{\ell_J}\qquad
\text{(interpret the 32‑byte little‑endian representation of }h\text{ as a scalar)}
\end{aligned}$$

> Equation (2) is exactly the `jubjub::Fr::from_repr` call that drops the five most‑significant bits and interprets the
> remaining 251 bits as an element of the JubJub scalar field.

The circuit must enforce **both** equations (1) and (2) and additionally that the
derived scalar is canonical:

$$\boxed{
\begin{aligned}
&h \;=\; \operatorname{Poseidon}\bigl(\mathtt{DST}_{\!J}\,\|\,\mathsf{elig\_sk}\,\|\,\rho\bigr) \\[4pt]
&\mathsf{jub\_sk} \;=\; \operatorname{from\_repr}(h) \\
&0 \;<\; \mathsf{jub\_sk} \;<\; \ell_J \qquad\text{(range check)}
\end{aligned}}$$

---  

### How the constraint is realised in a ZK circuit

| Step | Gadget needed | What it checks |
|------|---------------|----------------|
| **Hash** | Poseidon hash gadget over $(\mathbb{F}_p)$ | Computes the field element \(h\) from the secret inputs and the DST |
| **Byte‑to‑scalar conversion** | `from_repr` / “byte‑to‑field” gadget | Interprets the 32‑byte little‑endian representation of \(h\) as a JubJub scalar |
| **Range check** | < $ℓ_J$ comparator | Guarantees the resulting scalar lies in $(0,\ell_J)$ (canonical representation) |
| **Equality** | Direct wire equality | Binds the circuit variable `jub_sk` to the output of the conversion gadget |

When the three sub‑constraints above are satisfied, the proof system is convinced that
the JubJub secret key `jub_sk` **has been correctly derived** from the eligibility secret
`elig_sk` and the auxiliary value `ρ` via the Poseidon hash with domain‑separation tag
`KEY_DERIVATION_DST_JUBJUB`.

<!-- derive_from_elig_sk -> hkdr_jubjub -->

### 3. Constrain `jubjub_pk` is paired with `jubjub_sk`

Constraining the pairing between the `jubjub_pk` & `jubjub_sk` requires the following inputs:

- **jubjub_MODULUS**
- **jubjub_G**
- **jubjub_pk**
- **jubjub_sk**

The constraint equation is:

$$\begin{array}{lcl}
\textbf{Public input} &
\mathsf{jubjub\_pk}= (X_{\mathsf{jubjub\_pk}},\,Y_{\mathsf{jubjub\_pk}})\;\in\;\mathbb{F}_{p}^{\,2}
\\[6pt]
\textbf{Private witness} &
\mathsf{jubjub\_sk}\;\in\;\mathbb{F}_{\ell_J}
\\[6pt]
\textbf{Constants} &
\begin{cases}
G = (G_x,\,G_y) \\
G_x = \texttt{jubjub\_G\_X} \\
G_y = \texttt{jubjub\_G\_Y} \\
\ell_J = \texttt{jubjub\_MODULUS}\quad(\text{order of the JubJub scalar field})
\end{cases}
\end{array}$$

$$\boxed{
\begin{aligned}
&0 \;<\; \mathsf{jubjub\_sk} \;<\; \ell_J
   &&\text{(range‑check on the scalar)} \\[6pt]
&\mathsf{jubjub\_pk}\;=\;\mathsf{jubjub\_sk}\,\cdot\,G
   &&\text{(fixed‑base EC multiplication)}
\end{aligned}}$$

$$\text{Component‑wise equivalence}
\qquad
\begin{cases}
X_{\mathsf{jubjub\_pk}} = X\!\bigl(\mathsf{jubjub\_sk}\,\cdot\,G\bigr) \\[4pt]
Y_{\mathsf{jubjub\_pk}} = Y\!\bigl(\mathsf{jubjub\_sk}\,\cdot\,G\bigr)
\end{cases}$$


  -->
