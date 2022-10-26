use crate::engine::arkworks::{
    ext_field::ToBasePrimeFieldIterator, hashing::hash_to_field::HashToField,
};
use ark_bls12_381::{g1::Parameters as G1Parameters, Fq, Fr};
use ark_ec::{
    short_weierstrass_jacobian::{GroupAffine, GroupProjective},
    AffineCurve, ModelParameters, ProjectiveCurve, SWModelParameters,
};
use ark_ff::{
    batch_inversion, field_new, BigInteger, BitIteratorBE, Field, One, PrimeField, SquareRootField,
    Zero,
};
use ark_poly::{univariate::DensePolynomial, Polynomial, UVPolynomial};
use std::marker::PhantomData;

pub trait ClearCofactor {
    fn clear_cofactor(&self) -> Self;
}

impl ClearCofactor for GroupAffine<G1Parameters> {
    fn clear_cofactor(&self) -> Self {
        let base = self.into_projective();
        let h_eff: &[u64] = &[0xd201000000010001];
        let mut res = GroupProjective::<G1Parameters>::zero();
        for b in BitIteratorBE::without_leading_zeros(h_eff) {
            res.double_in_place();
            if b {
                res += &base;
            }
        }
        res.into_affine()
    }
}

/// Trait for hashing arbitrary data to a group element on an elliptic curve
pub trait HashToCurve<T: SWModelParameters>: Sized {
    /// Create a new hash to curve instance, with a given domain.
    fn new(domain: &[u8]) -> Result<Self, HashToCurveError>;

    /// Produce a hash of the message, which also depends on the domain.
    /// The output of the hash is a curve point in the prime order subgroup
    /// of the given elliptic curve.
    fn hash(&self, message: &[u8]) -> Result<GroupAffine<T>, HashToCurveError>;
}

/// Trait for mapping a random field element to a random curve point.
pub trait MapToCurve<T: SWModelParameters>: Sized {
    /// Constructs a new mapping.
    fn new() -> Result<Self, HashToCurveError>;

    /// Map an arbitary field element to a corresponding curve point.
    fn map_to_curve(&self, point: T::BaseField) -> Result<GroupAffine<T>, HashToCurveError>;
}

/// This is an error that could occur during the hash to curve process
#[derive(Clone, Debug)]
pub enum HashToCurveError {
    /// Curve choice is unsupported by the given HashToCurve method.
    UnsupportedCurveError(String),

    /// Error with map to curve
    MapToCurveError(String),
}

/// Helper struct that can be used to construct elements on the elliptic curve
/// from arbitrary messages, by first hashing the message onto a field element
/// and then mapping it to the elliptic curve defined over that field.
pub struct MapToCurveBasedHasher<T, H2F, M2C>
where
    T: SWModelParameters,
    H2F: HashToField<T::BaseField>,
    M2C: MapToCurve<T>,
{
    field_hasher: H2F,
    curve_mapper: M2C,
    _params_t:    PhantomData<T>,
}

impl<T, H2F, M2C> HashToCurve<T> for MapToCurveBasedHasher<T, H2F, M2C>
where
    T: SWModelParameters,
    GroupAffine<T>: ClearCofactor,
    H2F: HashToField<T::BaseField>,
    M2C: MapToCurve<T>,
{
    fn new(domain: &[u8]) -> Result<Self, HashToCurveError> {
        let field_hasher = H2F::new(domain);
        let curve_mapper = M2C::new()?;
        let _params_t = PhantomData;
        Ok(MapToCurveBasedHasher {
            field_hasher,
            curve_mapper,
            _params_t,
        })
    }

    // Produce a hash of the message, using the hash to field and map to curve
    // traits. This uses the IETF hash to curve's specification for Random
    // oracle encoding (hash_to_curve) defined by combining these components.
    // See https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-09#section-3
    fn hash(&self, msg: &[u8]) -> Result<GroupAffine<T>, HashToCurveError> {
        // IETF spec of hash_to_curve, from hash_to_field and map_to_curve
        // sub-components
        // 1. u = hash_to_field(msg, 2)
        // 2. Q0 = map_to_curve(u[0])
        // 3. Q1 = map_to_curve(u[1])
        // 4. R = Q0 + Q1              # Point addition
        // 5. P = clear_cofactor(R)
        // 6. return P

        let rand_field_elems = self.field_hasher.hash_to_field(msg, 2);
        let rand_curve_elem_0 = self.curve_mapper.map_to_curve(rand_field_elems[0])?;
        let rand_curve_elem_1 = self.curve_mapper.map_to_curve(rand_field_elems[1])?;
        let rand_curve_elem = rand_curve_elem_0 + rand_curve_elem_1;
        let rand_subgroup_elem = rand_curve_elem.clear_cofactor();
        Ok(rand_subgroup_elem)
    }
}

/// Trait defining the necessary parameters for the SWU hash-to-curve method
/// for the curves of Weierstrass form of:
/// y^2 = x^3 + a*x + b where ab != 0. From [\[WB2019\]]
///
/// - [\[WB2019\]] <https://eprint.iacr.org/2019/403>
pub trait SWUParams: SWModelParameters + Sized {
    /// An element of the base field that is not a square root see \[WB2019,
    /// Section 4\]. It is also convenient to have $g(b/ZETA * a)$ to be
    /// square. In general we use a `ZETA` with low absolute value
    /// coefficients when they are represented as integers.
    const ZETA: Self::BaseField;
}

// https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/
// Hashing to Elliptic Curves
// 8.8.1.  BLS12-381 G1
// BLS12381G1_XMD:SHA-256_SSWU_RO_ is defined as follows:
// * E': y'^2 = x'^3 + A' * x' + B', where
//      -  A' = 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
//      -  B' = 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0
//      -  A' = 12190336318893619529228877361869031420615612348429846051986726275283378313155663745811710833465465981901188123677
//      -  B' = 2906670324641927570491258158026293881577086121416628140204402091718288198173574630967936031029026176254968826637280
//  * Z: 11
pub struct G1SWUParameters;

impl ModelParameters for G1SWUParameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl G1SWUParameters {
    const GENERATOR_X: Fq = field_new!(Fq, "1677416608493238977774703213729589714082762656433187746258164626835771660734158898989765932111853529350617333597651");
    const GENERATOR_Y: Fq = field_new!(Fq, "1405098061573104639413728190240719229571583960971553962991897960445246185035342568402755187331334546673157015627211");
}

impl SWModelParameters for G1SWUParameters {
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) =
        (Self::GENERATOR_X, Self::GENERATOR_Y);
    const COEFF_A: Fq = field_new!(Fq, "12190336318893619529228877361869031420615612348429846051986726275283378313155663745811710833465465981901188123677");
    const COEFF_B: Fq = field_new!(Fq, "2906670324641927570491258158026293881577086121416628140204402091718288198173574630967936031029026176254968826637280");
    const COFACTOR: &'static [u64] = &[0x8c00aaab0000aaab, 0x396c8c005555e156];
    const COFACTOR_INV: Fr = field_new!(
        Fr,
        "52435875175126190458656871551744051925719901746859129887267498875565241663483"
    );
}

impl SWUParams for G1SWUParameters {
    const ZETA: Fq = field_new!(Fq, "11");
}

/// Represents the SWU hash-to-curve map defined by `P`.
pub struct SWUMap<P: SWUParams> {
    curve_params: PhantomData<fn() -> P>,
}

/// Trait defining a parity method on the Field elements based on [\[1\]]
/// Section 4.1
///
/// - [\[1\]] <https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/>
pub fn parity<F: Field + ToBasePrimeFieldIterator>(element: &F) -> bool {
    element
        .base_field_iterator()
        .find(|&x| !x.is_zero())
        .map_or(false, |x| x.into_repr().is_odd())
}

impl<P: SWUParams> MapToCurve<P> for SWUMap<P>
where
    P::BaseField: ToBasePrimeFieldIterator,
{
    /// Constructs a new map if `P` represents a valid map.
    fn new() -> Result<Self, HashToCurveError> {
        // Verifying that ZETA is a non-square
        if P::ZETA.legendre().is_qr() {
            return Err(HashToCurveError::MapToCurveError(
                "ZETA should be a quadratic non-residue for the SWU map".to_string(),
            ));
        }

        // Verifying the prerequisite for applicability  of SWU map
        if P::COEFF_A.is_zero() || P::COEFF_B.is_zero() {
            return Err(HashToCurveError::MapToCurveError(
                "Simplified SWU requires a * b != 0 in the short Weierstrass form of y^2 = x^3 + \
                 a*x + b "
                    .to_string(),
            ));
        }

        Ok(SWUMap {
            curve_params: PhantomData,
        })
    }

    /// Map an arbitrary base field element to a curve point.
    /// Based on
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>.
    fn map_to_curve(&self, point: P::BaseField) -> Result<GroupAffine<P>, HashToCurveError> {
        // 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        // 2. x1 = (-B / A) * (1 + tv1)
        // 3. If tv1 == 0, set x1 = B / (Z * A)
        // 4. gx1 = x1^3 + A * x1 + B
        //
        // We use the "Avoiding inversions" optimization in [WB2019, section 4.2]
        // (not to be confused with section 4.3):
        //
        //   here       [WB2019]
        //   -------    ---------------------------------
        //   Z          ξ
        //   u          t
        //   Z * u^2    ξ * t^2 (called u, confusingly)
        //   x1         X_0(t)
        //   x2         X_1(t)
        //   gx1        g(X_0(t))
        //   gx2        g(X_1(t))
        //
        // Using the "here" names:
        //    x1 = num_x1/div      = [B*(Z^2 * u^4 + Z * u^2 + 1)] / [-A*(Z^2 * u^4 + Z
        // * u^2]   gx1 = num_gx1/div_gx1 = [num_x1^3 + A * num_x1 * div^2 + B *
        // div^3] / div^3
        let a = P::COEFF_A;
        let b = P::COEFF_B;

        let zeta_u2 = P::ZETA * point.square();
        let ta = zeta_u2.square() + zeta_u2;
        let num_x1 = b * (ta + <P::BaseField as One>::one());
        let div = a * if ta.is_zero() { P::ZETA } else { -ta };

        let num2_x1 = num_x1.square();
        let div2 = div.square();
        let div3 = div2 * div;
        let num_gx1 = (num2_x1 + a * div2) * num_x1 + b * div3;

        // 5. x2 = Z * u^2 * x1
        let num_x2 = zeta_u2 * num_x1; // same div

        // 6. gx2 = x2^3 + A * x2 + B  [optimized out; see below]
        // 7. If is_square(gx1), set x = x1 and y = sqrt(gx1)
        // 8. Else set x = x2 and y = sqrt(gx2)
        let gx1_square;
        let gx1;

        assert!(
            !div3.is_zero(),
            "we have checked that neither a or ZETA are zero. Q.E.D."
        );
        let y1: P::BaseField = {
            gx1 = num_gx1 / div3;
            if gx1.legendre().is_qr() {
                gx1_square = true;
                gx1.sqrt()
                    .expect("We have checked that gx1 is a quadratic residue. Q.E.D")
            } else {
                let zeta_gx1 = P::ZETA * gx1;
                gx1_square = false;
                zeta_gx1.sqrt().expect(
                    "ZETA * gx1 is a quadratic residue because legard is multiplicative. Q.E.D",
                )
            }
        };

        // This magic also comes from a generalization of [WB2019, section 4.2].
        //
        // The Sarkar square root algorithm with input s gives us a square root of
        // h * s for free when s is not square, where h is a fixed nonsquare.
        // In our implementation, h = ROOT_OF_UNITY.
        // We know that Z / h is a square since both Z and h are
        // nonsquares. Precompute theta as a square root of Z / ROOT_OF_UNITY.
        //
        // We have gx2 = g(Z * u^2 * x1) = Z^3 * u^6 * gx1
        //                               = (Z * u^3)^2 * (Z/h * h * gx1)
        //                               = (Z * theta * u^3)^2 * (h * gx1)
        //
        // When gx1 is not square, y1 is a square root of h * gx1, and so Z * theta *
        // u^3 * y1 is a square root of gx2. Note that we don't actually need to
        // compute gx2.

        let y2 = zeta_u2 * point * y1;
        let num_x = if gx1_square { num_x1 } else { num_x2 };
        let y = if gx1_square { y1 } else { y2 };

        let x_affine = num_x / div;
        let y_affine = if parity(&y) != parity(&point) { -y } else { y };
        let point_on_curve = GroupAffine::<P>::new(x_affine, y_affine, false);
        assert!(
            point_on_curve.is_on_curve(),
            "swu mapped to a point off the curve"
        );
        Ok(point_on_curve)
    }
}

type BaseField<MP> = <MP as ModelParameters>::BaseField;

/// Trait defining the necessary parameters for the WB hash-to-curve method
/// for the curves of Weierstrass form of:
/// of y^2 = x^3 + a*x + b where b != 0 but `a` can be zero like BLS-381 curve.
/// From [\[WB2019\]]
///
/// - [\[WB2019\]] <http://dx.doi.org/10.46586/tches.v2019.i4.154-179>
pub trait WBParams: SWModelParameters + Sized {
    // The isogenous curve should be defined over the same base field but it can
    // have different scalar field type IsogenousCurveScalarField :
    type IsogenousCurve: SWUParams<BaseField = BaseField<Self>>;

    const PHI_X_NOM: &'static [BaseField<Self>];
    const PHI_X_DEN: &'static [BaseField<Self>];

    const PHI_Y_NOM: &'static [BaseField<Self>];
    const PHI_Y_DEN: &'static [BaseField<Self>];

    fn isogeny_map(
        domain_point: GroupAffine<Self::IsogenousCurve>,
    ) -> Result<GroupAffine<Self>, HashToCurveError> {
        let xy = (!domain_point.infinity).then(|| (&domain_point.x, &domain_point.y));
        match xy {
            Some((x, y)) => {
                let x_num = DensePolynomial::from_coefficients_slice(Self::PHI_X_NOM);
                let x_den = DensePolynomial::from_coefficients_slice(Self::PHI_X_DEN);

                let y_num = DensePolynomial::from_coefficients_slice(Self::PHI_Y_NOM);
                let y_den = DensePolynomial::from_coefficients_slice(Self::PHI_Y_DEN);

                let mut v: [BaseField<Self>; 2] = [x_den.evaluate(x), y_den.evaluate(x)];
                batch_inversion(&mut v);
                let img_x = x_num.evaluate(x) * v[0];
                let img_y = (y_num.evaluate(x) * y) * v[1];
                Ok(GroupAffine::new(img_x, img_y, false))
            }
            None => Ok(GroupAffine::zero()),
        }
    }
}

impl WBParams for G1Parameters {
    type IsogenousCurve = G1SWUParameters;

    const PHI_X_DEN: &'static [Fq] = &[
        field_new!(Fq, "1353092447850172218905095041059784486169131709710991428415161466575141675351394082965234118340787683181925558786844"),
        field_new!(Fq, "2822220997908397120956501031591772354860004534930174057793539372552395729721474912921980407622851861692773516917759"),
        field_new!(Fq, "1717937747208385987946072944131378949849282930538642983149296304709633281382731764122371874602115081850953846504985"),
        field_new!(Fq, "501624051089734157816582944025690868317536915684467868346388760435016044027032505306995281054569109955275640941784"),
        field_new!(Fq, "3025903087998593826923738290305187197829899948335370692927241015584233559365859980023579293766193297662657497834014"),
        field_new!(Fq, "2224140216975189437834161136818943039444741035168992629437640302964164227138031844090123490881551522278632040105125"),
        field_new!(Fq, "1146414465848284837484508420047674663876992808692209238763293935905506532411661921697047880549716175045414621825594"),
        field_new!(Fq, "3179090966864399634396993677377903383656908036827452986467581478509513058347781039562481806409014718357094150199902"),
        field_new!(Fq, "1549317016540628014674302140786462938410429359529923207442151939696344988707002602944342203885692366490121021806145"),
        field_new!(Fq, "1442797143427491432630626390066422021593505165588630398337491100088557278058060064930663878153124164818522816175370"),
        field_new!(Fq, "1"),
    ];
    const PHI_X_NOM: &'static [Fq] = &[
        field_new!(Fq, "2712959285290305970661081772124144179193819192423276218370281158706191519995889425075952244140278856085036081760695"),
        field_new!(Fq, "3564859427549639835253027846704205725951033235539816243131874237388832081954622352624080767121604606753339903542203"),
        field_new!(Fq, "2051387046688339481714726479723076305756384619135044672831882917686431912682625619320120082313093891743187631791280"),
        field_new!(Fq, "3612713941521031012780325893181011392520079402153354595775735142359240110423346445050803899623018402874731133626465"),
        field_new!(Fq, "2247053637822768981792833880270996398470828564809439728372634811976089874056583714987807553397615562273407692740057"),
        field_new!(Fq, "3415427104483187489859740871640064348492611444552862448295571438270821994900526625562705192993481400731539293415811"),
        field_new!(Fq, "2067521456483432583860405634125513059912765526223015704616050604591207046392807563217109432457129564962571408764292"),
        field_new!(Fq, "3650721292069012982822225637849018828271936405382082649291891245623305084633066170122780668657208923883092359301262"),
        field_new!(Fq, "1239271775787030039269460763652455868148971086016832054354147730155061349388626624328773377658494412538595239256855"),
        field_new!(Fq, "3479374185711034293956731583912244564891370843071137483962415222733470401948838363051960066766720884717833231600798"),
        field_new!(Fq, "2492756312273161536685660027440158956721981129429869601638362407515627529461742974364729223659746272460004902959995"),
        field_new!(Fq, "1058488477413994682556770863004536636444795456512795473806825292198091015005841418695586811009326456605062948114985"),
    ];
    const PHI_Y_DEN: &'static [Fq] = &[
        field_new!(Fq, "3396434800020507717552209507749485772788165484415495716688989613875369612529138640646200921379825018840894888371137"),
        field_new!(Fq, "3907278185868397906991868466757978732688957419873771881240086730384895060595583602347317992689443299391009456758845"),
        field_new!(Fq, "854914566454823955479427412036002165304466268547334760894270240966182605542146252771872707010378658178126128834546"),
        field_new!(Fq, "3496628876382137961119423566187258795236027183112131017519536056628828830323846696121917502443333849318934945158166"),
        field_new!(Fq, "1828256966233331991927609917644344011503610008134915752990581590799656305331275863706710232159635159092657073225757"),
        field_new!(Fq, "1362317127649143894542621413133849052553333099883364300946623208643344298804722863920546222860227051989127113848748"),
        field_new!(Fq, "3443845896188810583748698342858554856823966611538932245284665132724280883115455093457486044009395063504744802318172"),
        field_new!(Fq, "3484671274283470572728732863557945897902920439975203610275006103818288159899345245633896492713412187296754791689945"),
        field_new!(Fq, "3755735109429418587065437067067640634211015783636675372165599470771975919172394156249639331555277748466603540045130"),
        field_new!(Fq, "3459661102222301807083870307127272890283709299202626530836335779816726101522661683404130556379097384249447658110805"),
        field_new!(Fq, "742483168411032072323733249644347333168432665415341249073150659015707795549260947228694495111018381111866512337576"),
        field_new!(Fq, "1662231279858095762833829698537304807741442669992646287950513237989158777254081548205552083108208170765474149568658"),
        field_new!(Fq, "1668238650112823419388205992952852912407572045257706138925379268508860023191233729074751042562151098884528280913356"),
        field_new!(Fq, "369162719928976119195087327055926326601627748362769544198813069133429557026740823593067700396825489145575282378487"),
        field_new!(Fq, "2164195715141237148945939585099633032390257748382945597506236650132835917087090097395995817229686247227784224263055"),
        field_new!(Fq, "1"),
    ];
    const PHI_Y_NOM: &'static [Fq] = &[
        field_new!(Fq, "1393399195776646641963150658816615410692049723305861307490980409834842911816308830479576739332720113414154429643571"),
        field_new!(Fq, "2968610969752762946134106091152102846225411740689724909058016729455736597929366401532929068084731548131227395540630"),
        field_new!(Fq, "122933100683284845219599644396874530871261396084070222155796123161881094323788483360414289333111221370374027338230"),
        field_new!(Fq, "303251954782077855462083823228569901064301365507057490567314302006681283228886645653148231378803311079384246777035"),
        field_new!(Fq, "1353972356724735644398279028378555627591260676383150667237975415318226973994509601413730187583692624416197017403099"),
        field_new!(Fq, "3443977503653895028417260979421240655844034880950251104724609885224259484262346958661845148165419691583810082940400"),
        field_new!(Fq, "718493410301850496156792713845282235942975872282052335612908458061560958159410402177452633054233549648465863759602"),
        field_new!(Fq, "1466864076415884313141727877156167508644960317046160398342634861648153052436926062434809922037623519108138661903145"),
        field_new!(Fq, "1536886493137106337339531461344158973554574987550750910027365237255347020572858445054025958480906372033954157667719"),
        field_new!(Fq, "2171468288973248519912068884667133903101171670397991979582205855298465414047741472281361964966463442016062407908400"),
        field_new!(Fq, "3915937073730221072189646057898966011292434045388986394373682715266664498392389619761133407846638689998746172899634"),
        field_new!(Fq, "3802409194827407598156407709510350851173404795262202653149767739163117554648574333789388883640862266596657730112910"),
        field_new!(Fq, "1707589313757812493102695021134258021969283151093981498394095062397393499601961942449581422761005023512037430861560"),
        field_new!(Fq, "349697005987545415860583335313370109325490073856352967581197273584891698473628451945217286148025358795756956811571"),
        field_new!(Fq, "885704436476567581377743161796735879083481447641210566405057346859953524538988296201011389016649354976986251207243"),
        field_new!(Fq, "3370924952219000111210625390420697640496067348723987858345031683392215988129398381698161406651860675722373763741188"),
    ];
}

pub struct WBMap<P: WBParams> {
    swu_field_curve_hasher: SWUMap<P::IsogenousCurve>,
    curve_params:           PhantomData<fn() -> P>,
}

impl<P: WBParams> MapToCurve<P> for WBMap<P>
where
    P::BaseField: ToBasePrimeFieldIterator,
{
    /// Constructs a new map if `P` represents a valid map.
    fn new() -> Result<Self, HashToCurveError> {
        match P::isogeny_map(GroupAffine::<P::IsogenousCurve>::prime_subgroup_generator()) {
            Ok(point_on_curve) => {
                if !point_on_curve.is_on_curve() {
                    return Err(HashToCurveError::MapToCurveError(format!(
                        "the isogeny maps the generator of its domain: {} into {} which does not \
                         belong to its codomain.",
                        GroupAffine::<P::IsogenousCurve>::prime_subgroup_generator(),
                        point_on_curve
                    )));
                }
            }
            Err(e) => return Err(e),
        }

        Ok(WBMap {
            swu_field_curve_hasher: SWUMap::<P::IsogenousCurve>::new().unwrap(),
            curve_params:           PhantomData,
        })
    }

    /// Map random field point to a random curve point
    /// inspired from
    /// <https://github.com/zcash/pasta_curves/blob/main/src/hashtocurve.rs>
    fn map_to_curve(&self, element: P::BaseField) -> Result<GroupAffine<P>, HashToCurveError> {
        // first we need to map the field point to the isogenous curve
        let point_on_isogenious_curve = self.swu_field_curve_hasher.map_to_curve(element).unwrap();
        P::isogeny_map(point_on_isogenious_curve)
    }
}
