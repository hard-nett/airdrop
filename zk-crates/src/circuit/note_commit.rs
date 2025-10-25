

#[allow(non_snake_case)]
#[derive(Clone, Debug)]
pub struct NoteCommitConfig {
    b: DecomposeB,
    d: DecomposeD,
    e: DecomposeE,
    g: DecomposeG,
    h: DecomposeH,
    g_d: GdCanonicity,
    pk_d: PkdCanonicity,
    value: ValueCanonicity,
    rho: RhoCanonicity,
    psi: PsiCanonicity,
    y_canon: YCanonicity,
    advices: [Column<Advice>; 10],
    sinsemilla_config:
        SinsemillaConfig<OrchardHashDomains, OrchardCommitDomains, OrchardFixedBases>,
}

#[derive(Clone, Debug)]
pub struct NoteCommitChip {
    config: NoteCommitConfig,
}