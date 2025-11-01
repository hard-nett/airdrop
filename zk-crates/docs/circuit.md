
# Headstash Circuit

There are 5 primitive circuits we need to implement:

1. sinsemilla hashDomain hash (airdrop eligibility)
2. sinsemilla commitDomain hash (note commitment integrity)
3. pub/priv key curve constraint (should work for both secp256k1 & jubjub)
4. field conversion accuracy of elig_sk into pallas::Base
5. posiedon hash + dropped bits (used in HKDF to make hash compatible as scalar input for jubjub)

## 1. Ensure Genesis Hash Is Valid & Derived From Note Components

This prooves genesis distribution inclusion by recreating the sinsemilla hashdomain tree leaf with the note components, and then constraining that to the tree root. 

## 2. Ensure PubKey Is Derived From PrivateKey For Both Secp256k1 & JubJub

### 2.a Secp256k1

- both public & private keys must be private inputs
- requires foreign-field arithmetic.
- constraints `pk == sk * G`

### 2.b JubJub

- private key is private input, public key is public input
- orchard implementation uses the pallas::Affine, while jubjub uses twisted Edwards curve. We need to keep concious of this when implementing our chip
- we constrain `pk == sk * G` using fixed-based scalar mul
- <https://github.com/axiom-crypto/halo2-lib/blob/community-edition/halo2-ecc/src/secp256k1/tests/ecdsa.rs>

## 3. Byte-To-Field Conversion Constraint

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

## Notes

### Constraining Values To Expected Curve

we need to be concious about how we are constraining raw values to the pallas/vestas curves required to implement our circuit constraints with minimal modifications from the original specs. For example, `elig_sk` is needed to be hashed by posiedon hashing function, and this requires us to represent these bytes on the pallas curve.  We can do this by clearing the top bytes of the hash ensureing its always `< q`.*We can reduce possible collisions due to this reduction by performing two hashes and concatenating them to each other.*

## Proof Inputs

### Constant Values

<!-- Generators -->
- secp256k1 generator point (G)
- secp256k1 curve order (C)
- jubjub generator (jubju_G)
- jubjub curve modulus (jubjub_MODULUS)

<!-- Domain Separation Tags -->
- jubjub key derivation: `KEY_DERIVATION_DST_JUBJUB`
- note-nullifier-elig-sk-to-base: `NOTE_NULLIFIER_PERSONALIZATION`

### Private Inputs

- **elig_pk**
- **elig_sk**
- **jubjub_sk**
- **rho**
- **ndi**

### Public Inputs

- **jubjub_pk**
- **recp**
- **v**
- **nd**

## Proof Of Ownership

### 1. Constrain `elig_pk` is paired with `elig_sk`

Constraning the pairing between the `elig_pk` & `elig_sk` requires the following inputs:

- **GENERATOR_X & GENERATOR_Y**
- **CURVE_ORDER**
- **elig_pk**
- **elig_sk**

The constraint equation is:

$$\begin{aligned}
\textbf{Private witnesses} &\qquad
\begin{cases}
\mathsf{sk}\in\mathbb{F}_{\ell}      &\text{(secret scalar)}\\[2pt]
\mathsf{pk}= (X_{\mathsf{pk}},Y_{\mathsf{pk}})\in\mathbb{F}_{p}^{\,2}
                                       &\text{(corresponding public point)}
\end{cases}
\\[8pt]
\textbf{Constants} &\qquad
\begin{cases}
G   = (G_{x},G_{y})                     &\text{(generator point)}\\
G_{x}= \texttt{GENERATOR\_X}            &\\
G_{y}= \texttt{GENERATOR\_Y}            &\\
\ell = \texttt{CURVE\_ORDER}            &\text{(sub‑group order)}
\end{cases}
\end{aligned}$$

$$\boxed{
\begin{aligned}
&0 \;<\; \mathsf{sk} \;<\; \ell
   &&\text{(range‑check that the secret is a canonical scalar)}\\[6pt]
&\mathsf{pk}\;=\;\mathsf{sk}\,\cdot\,G
   &&\text{(fixed‑base elliptic‑curve multiplication)}
\end{aligned}}$$

$$\text{Component‑wise this is equivalent to}
\qquad
\begin{cases}
X_{\mathsf{pk}} = X\!\bigl(\mathsf{sk}\,\cdot\,G\bigr) \\[4pt]
Y_{\mathsf{pk}} = Y\!\bigl(\mathsf{sk}\,\cdot\,G\bigr)
\end{cases}$$

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
| **Hash** | Poseidon hash gadget over \(\mathbb{F}_p\) | Computes the field element \(h\) from the secret inputs and the DST |
| **Byte‑to‑scalar conversion** | `from_repr` / “byte‑to‑field” gadget | Interprets the 32‑byte little‑endian representation of \(h\) as a JubJub scalar |
| **Range check** | `< ℓ_J` comparator | Guarantees the resulting scalar lies in \([0,\ell_J)\) (canonical representation) |
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

## Note Commitment

### 1. Constrain `cm` is derived from public + private inputs

Constraining the derivation of the note commitment `cm` requires the following inputs:

- **recp** pub
- **jub_pk** pub
- **v** pub
- **rho**
- **psi***
- **rcm***

> note: in order to derive `psi` & `rcm`, we have a `rseed` that is a randomness source in a PRF, that expends into each.
    <!-- pub fn psi(&self, rho: &Rho) -> pallas::Base {
        to_base(PrfExpand::PSI.with(&self.0, &rho.to_bytes()))
    } -->
    <!-- pub fn rcm(&self, rho: &Rho) -> commitment::NoteCommitTrapdoor {
        commitment::NoteCommitTrapdoor(to_scalar(
            PrfExpand::ORCHARD_RCM.with(&self.0, &rho.to_bytes()),
        ))
    } -->

The constraint equation is:

```math
\begin{array}{lcl}
\textbf{Public inputs} &
\begin{cases}
\mathsf{recp}   \in \mathbb{F}_p & \text{recipient address} \\[4pt]
\mathsf{jub\_pk}= (X_{\mathsf{jub}},\,Y_{\mathsf{jub}}) \in \mathbb{F}_p^{\,2}
    & \text{JubJub public key} \\[4pt]
v               \in \mathbb{F}_p & \text{value} \\[4pt]
\rho            \in \mathbb{F}_p & \text{note randomness}
\end{cases}
\\[10pt]
\textbf{Private witnesses} &
\begin{cases}
\mathsf{rseed} \in \{0,1\}^{256} & \text{PRF seed} \\[4pt]
\psi^{\ast}    \in \mathbb{F}_p   & \text{derived via } \operatorname{PRF}_{\text{PSI}} \\[4pt]
\mathsf{rcm}^{\ast} \in \mathbb{F}_p & \text{derived via } \operatorname{PRF}_{\text{RCM}}
\end{cases}
\end{array}
```

```math
\begin{aligned}
\psi      &:= \operatorname{PRF}_{\text{PSI}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[4pt]
\mathsf{rcm} &:= \operatorname{PRF}_{\text{RCM}}\!\bigl(\mathsf{rseed},\,\rho\bigr) \in \mathbb{F}_p,\\[6pt]
\boxed{%
\mathsf{cm}\;:=\;
\operatorname{Poseidon}_{\mathbb{F}_p}\!\bigl(
\mathsf{recp},\,
X_{\mathsf{jub}},\,Y_{\mathsf{jub}},\,
v,\,\rho,\,\psi,\,\mathsf{rcm}
\bigr)
}
\end{aligned}
```
## Nullifier

### 1. Constrain `nul` is derived from public + private inputs

Constraining the derivation of the nullifier `nul` requires the following inputs:

- **fdi** private
- **v** public
- **nd*** public
- **elig_sk*** private
- **NOTE_NULLIFIER_PERSONALIZATION**constant

> NOTE: each value input is derived into a `pallas::Base`. `nd` & `elig_sk` are hashed using posiedon in order to derive them into the `pallas::Base` point. when hashing the elig_sk to point, the NOTE_NULLIFIER_PERSONALIZATION is used as a DST value for collision resistance.

The constraint equation is:

```math
\begin{array}{lcl}
\textbf{Private witnesses} &
\begin{cases}
\mathsf{fdi}      \in \mathbb{F}_p      &\text{(field element from private input }fdi\text{)}\\[2pt]
\mathsf{elig\_sk}  \in \{0,1\}^{256}   &\text{(32‑byte eligibility secret)}\\[2pt]
\mathsf{nd}        \in \{0,1\}^{256}   &\text{(32‑byte auxiliary data)}\\
\end{cases}
\\[10pt]
\textbf{Public inputs} &
\begin{cases}
\mathsf{v}        \in \mathbb{F}_p      &\text{(public value)}\\[2pt]
\mathsf{nd}^{\ast}\in \mathbb{F}_p      &\text{(public‑derived field element for }nd\text{)}\\[2pt]
\mathsf{elig\_sk}^{\ast}\in \mathbb{F}_p &\text{(public‑derived field element for }elig\_sk\text{)}\\
\end{cases}
\\[10pt]
\textbf{Constants} &
\begin{cases}
\mathtt{DST}_{\!N}= \texttt{NOTE\_NULLIFIER\_PERSONALIZATION}
    &\text{(domain‑separation tag)}\\[2pt]
\mathbb{F}_p &\text{base field of the Pallas curve}
\end{cases}
\end{array}
```

```math
\begin{aligned}
%--- intermediate hashes -------------------------------------------------
h_{\mathsf{nd}}   &:= \operatorname{Poseidon}_{\mathbb{F}_p}
                     \bigl(\,\mathtt{DST}_{\!N}\;\|\;\mathsf{nd}\,\bigr)
                     \;\in\; \mathbb{F}_p \\[4pt]
h_{\mathsf{elig}} &:= \operatorname{Poseidon}_{\mathbb{F}_p}
                     \bigl(\,\mathtt{DST}_{\!N}\;\|\;\mathsf{elig\_sk}\,\bigr)
                     \;\in\; \mathbb{F}_p \\[6pt]
%--- final nullifier ----------------------------------------------------
\boxed{
\mathsf{nul}
   = \operatorname{Poseidon}_{\mathbb{F}_p}
     \bigl(\,\mathsf{fdi},\;\mathsf{v},\;h_{\mathsf{nd}},\;h_{\mathsf{elig}}\,\bigr)
   \in \mathbb{F}_p
}
\end{aligned}
```

## Research
- <https://grok.com/c/3931f7e5-10e6-47e5-86f9-1c25d9963e8a>
