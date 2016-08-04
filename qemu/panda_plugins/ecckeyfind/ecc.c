
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>

#define NDEBUG
#include <assert.h>

#include "ecc.h"

/* EC arithmetic formulas initially taken from
   http://www.infosecwriters.com/text_resources/pdf/Elliptic_Curve_AnnopMS.pdf. Then
   I discovered that they are slightly wrong (there are a few typos
   and some assume a = -3), so I moved to
   https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Jacobian_Coordinates,
   but did not rewrite everything in the new notation. So now the code
   has login from the latter page and notation from the former.

   I use the multiplicative notation ("multiply" and "square") instead
   of the additive one, because they seems much more logical. */

void point_init(Point *p) {
  mpz_init(p->x);
  mpz_init(p->y);
  mpz_init(p->z);
}

void point_clear(Point *p) {
  mpz_clear(p->x);
  mpz_clear(p->y);
  mpz_clear(p->z);
}

void point_set(Point *p, const mpz_t x, const mpz_t y) {
  mpz_set(p->x, x);
  mpz_set(p->y, y);
  mpz_set_ui(p->z, 1);
}

void point_set_str(Point *p, const char *x, const char *y) {
  mpz_set_str(p->x, x, 0);
  mpz_set_str(p->y, y, 0);
  mpz_set_ui(p->z, 1);
}

void point_set_identity(Point *p) {
  mpz_set_ui(p->x, 1);
  mpz_set_ui(p->y, 1);
  mpz_set_ui(p->z, 0);
}

void point_copy(Point *pr, const Point *p) {
  mpz_set(pr->x, p->x);
  mpz_set(pr->y, p->y);
  mpz_set(pr->z, p->z);
}

void point_print(const Point *p, FILE* fout, const char *name) {
  gmp_fprintf(fout, "%s: (%#Zd, %#Zd, %#Zd)\n", name, p->x, p->y, p->z);
}

bool point_check(Curve *c, const Point *p) {
  if (mpz_sgn(p->x) == 0 &&
      mpz_sgn(p->y) == 0 &&
      mpz_sgn(p->z) == 0) {
    return false;
  }

  // y^2
  mpz_mul(c->tmp1, p->y, p->y);
  mpz_mod(c->tmp1, c->tmp1, c->p);

  // -x^3
  mpz_mul(c->tmp2, p->x, p->x);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_mul(c->tmp2, c->tmp2, p->x);
  mpz_mod(c->tmp2, c->tmp2, c->p);

  // -a*x*z^4
  mpz_sub(c->tmp1, c->tmp1, c->tmp2);
  mpz_mod(c->tmp1, c->tmp1, c->p);
  mpz_mul(c->tmp2, p->x, c->a);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_mul(c->tmp4, p->z, p->z);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_mul(c->tmp3, c->tmp4, c->tmp4);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp2, c->tmp2, c->tmp3);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_sub(c->tmp1, c->tmp1, c->tmp2);
  mpz_mod(c->tmp1, c->tmp1, c->p);

  // -b*z^6
  mpz_mul(c->tmp3, c->tmp3, c->tmp4);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp2, c->b, c->tmp3);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_sub(c->tmp1, c->tmp1, c->tmp2);
  mpz_mod(c->tmp1, c->tmp1, c->p);

  // final check
  return mpz_sgn(c->tmp1) == 0;
}

void point_normalize(Curve *c, Point *p) {
  assert(point_check(c, p));

  //point_print(p, stdout, "p");

  // tmp1 := (p->z) ^ (-1)
  // tmp2 := tmp1 ^ 2 = (p->z) ^ (-2)
  mpz_invert(c->tmp1, p->z, c->p);
  mpz_mul(c->tmp2, c->tmp1, c->tmp1);
  mpz_mod(c->tmp2, c->tmp2, c->p);

  // p->x := p->x * tmp2 = p->x * (p->z) ^ (-2)
  mpz_mul(p->x, p->x, c->tmp2);
  mpz_mod(p->x, p->x, c->p);

  // p->y := p->y * tmp2 * tmp1 = p->y * (p->z) ^ (-3)
  mpz_mul(p->y, p->y, c->tmp2);
  mpz_mod(p->y, p->y, c->p);
  mpz_mul(p->y, p->y, c->tmp1);
  mpz_mod(p->y, p->y, c->p);

  // p->z := 1
  mpz_set_ui(p->z, 1);

  assert(point_check(c, p));
}

bool point_eq(Curve *c, const Point *p1, const Point *p2) {
  assert(point_check(c, p1));
  assert(point_check(c, p2));

  // Normalizing and comparing is expensive; it is better to cross
  // multiply (this also should handle the case z=0)
  // tmp1 := (p1->z) ^ 2
  // tmp2 := (p2->z) ^ 2
  mpz_mul(c->tmp1, p1->z, p1->z);
  mpz_mod(c->tmp1, c->tmp1, c->p);
  mpz_mul(c->tmp2, p2->z, p2->z);
  mpz_mod(c->tmp2, c->tmp2, c->p);

  // tmp3 := tmp1 * p2->x
  // tmp4 := tmp2 * p1->x
  // If tmp3 != tmp4, comparison has failed
  mpz_mul(c->tmp3, c->tmp1, p2->x);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp4, c->tmp2, p1->x);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  if (mpz_cmp(c->tmp3, c->tmp4) != 0) {
    return false;
  }

  // tmp1 := tmp1 * p1->z = (p1->z) ^ 3
  // tmp2 := tmp2 * p2->z = (p2->z) ^ 3
  mpz_mul(c->tmp1, c->tmp1, p1->z);
  mpz_mod(c->tmp1, c->tmp1, c->p);
  mpz_mul(c->tmp2, c->tmp2, p2->z);
  mpz_mod(c->tmp2, c->tmp2, c->p);

  // tmp3 := tmp1 * p2->y
  // tmp4 := tmp2 * p1->y
  // If tmp3 != tmp4, comparison has failed
  mpz_mul(c->tmp3, c->tmp1, p2->y);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp4, c->tmp2, p1->y);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  if (mpz_cmp(c->tmp3, c->tmp4) != 0) {
    return false;
  }

  // If not, comparison is true!
  return true;
}

void point_square(Curve *c, Point *pr, const Point *p) {
  assert(point_check(c, p));

  // If the point is the identity, return the identity
  if (mpz_sgn(p->z) == 0) {
    point_set_identity(pr);
    return;
  }

  // Operations are done in a funny order beucase of a combination of
  // my efforts to use as few temporaries as possible and some
  // mistakes I made choosing slightly wrong formulas

  // tmp4 := (p->z) ^ 2
  // tmp4 := tmp4 * tmp4 = (p->z) ^ 4
  // tmp4 := a * tmp4 = a * (p->z) ^ 4
  // tmp3 := 3 * p->x * p->x = 3 * (p->x) ^ 2
  // tmp3 = C := tmp3 + tmp4 = 3 * (p->x) ^ 2 + a * (p->z) ^ 4
  mpz_mul(c->tmp4, p->z, p->z);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_mul(c->tmp4, c->tmp4, c->tmp4);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_mul(c->tmp4, c->tmp4, c->a);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_set_ui(c->tmp3, 3);
  mpz_mul(c->tmp3, c->tmp3, p->x);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp3, c->tmp3, p->x);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_add(c->tmp3, c->tmp3, c->tmp4);
  mpz_mod(c->tmp3, c->tmp3, c->p);

  // tmp1 := (p->y) ^ 2
  // tmp4 := 8
  // tmp2 = B := tmp1 * tmp1 * tmp4 = 8 * (p->y) ^ 4
  // tmp4 := 4 * p->x
  // tmp1 = A := tmp1 * tmp4 = 4 * p->x * (p->y) ^ 2
  mpz_mul(c->tmp1, p->y, p->y);
  mpz_mod(c->tmp1, c->tmp1, c->p);
  mpz_set_ui(c->tmp4, 8);
  mpz_mul(c->tmp2, c->tmp1, c->tmp1);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_mul(c->tmp2, c->tmp2, c->tmp4);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_set_ui(c->tmp4, 4);
  mpz_mul(c->tmp4, c->tmp4, p->x);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_mul(c->tmp1, c->tmp1, c->tmp4);
  mpz_mod(c->tmp1, c->tmp1, c->p);

  // tmp4 = D := tmp3 * tmp3 - tmp1 - tmp1 = C ^ 2 - 2 * A
  mpz_mul(c->tmp4, c->tmp3, c->tmp3);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_sub(c->tmp4, c->tmp4, c->tmp1);
  mpz_mod(c->tmp4, c->tmp4, c->p);
  mpz_sub(c->tmp4, c->tmp4, c->tmp1);
  mpz_mod(c->tmp4, c->tmp4, c->p);

  // pr->x := tmp4 = D
  // pr->y := (tmp1 - tmp4) * tmp3 - tmp2 = (A - D) * C - B
  // pr->z := 2 * p->y * p->z
  mpz_set(pr->x, c->tmp4);
  mpz_mod(pr->x, pr->x, c->p);
  mpz_sub(pr->y, c->tmp1, c->tmp4);
  mpz_mod(pr->y, pr->y, c->p);
  mpz_mul(pr->y, pr->y, c->tmp3);
  mpz_mod(pr->y, pr->y, c->p);
  mpz_sub(pr->y, pr->y, c->tmp2);
  mpz_mod(pr->y, pr->y, c->p);
  mpz_set_ui(pr->z, 2);
  mpz_mul(pr->z, pr->z, p->y);
  mpz_mod(pr->z, pr->z, c->p);
  mpz_mul(pr->z, pr->z, p->z);
  mpz_mod(pr->z, pr->z, c->p);

  assert(point_check(c, pr));
}

void point_mult(Curve *c, Point *pr, const Point *p1, const Point *p2) {
  assert(point_check(c, p1));
  assert(point_check(c, p2));

  // Our formulas are only valid if the second point is in affine
  // coordinates
  assert(mpz_cmp_ui(p2->z, 1) == 0);

  // If one of the points is the identity, return the other
  if (mpz_sgn(p1->z) == 0) {
    point_copy(pr, p2);
    return;
  }
  if (mpz_sgn(p2->z) == 0) {
    point_copy(pr, p1);
    return;
  }

  // tmp3 := (p1->z) ^ 2
  // tmp1 = A := p2->x * tmp3 = p2->x * (p1->z) ^ 2
  // tmp3 := tmp3 * p1->z = (p1->z) ^ 3
  // tmp2 = B := p2->y * tmp3 = p2->y * (p1->z) ^ 3
  mpz_mul(c->tmp3, p1->z, p1->z);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp1, p2->x, c->tmp3);
  mpz_mod(c->tmp1, c->tmp1, c->p);
  mpz_mul(c->tmp3, c->tmp3, p1->z);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_mul(c->tmp2, p2->y, c->tmp3);
  mpz_mod(c->tmp2, c->tmp2, c->p);

  // tmp3 = C := tmp1 - p1->x
  // tmp4 = D := tmp2 - p1->y
  mpz_sub(c->tmp3, c->tmp1, p1->x);
  mpz_mod(c->tmp3, c->tmp3, c->p);
  mpz_sub(c->tmp4, c->tmp2, p1->y);
  mpz_mod(c->tmp4, c->tmp4, c->p);

  if (mpz_sgn(c->tmp3) == 0) {
    if (mpz_sgn(c->tmp4) != 0) {
      point_set_identity(pr);
      return;
    } else {
      point_square(c, pr, p1);
      return;
    }
  }

  // tmp1 := C ^ 2
  // tmp2 := tmp1 * C = C ^ 3
  mpz_mul(c->tmp1, c->tmp3, c->tmp3);
  mpz_mod(c->tmp1, c->tmp1, c->p);
  mpz_mul(c->tmp2, c->tmp1, c->tmp3);
  mpz_mod(c->tmp2, c->tmp2, c->p);

  // pr->x := tmp4 ^ 2 - tmp2 = D ^ 2 - C ^ 3 [partial]
  // pr->z := p1->z * tmp3 = p1->z * C
  mpz_mul(pr->x, c->tmp4, c->tmp4);
  mpz_mod(pr->x, pr->x, c->p);
  mpz_sub(pr->x, pr->x, c->tmp2);
  mpz_mod(pr->x, pr->x, c->p);
  mpz_mul(pr->z, p1->z, c->tmp3);
  mpz_mod(pr->z, pr->z, c->p);

  // pr->y := p1->x * tmp1 = p1->x * C ^ 2 [partial]
  // pr->x := pr->x - pr->y - pr->y = D ^ 2 - C ^ 3 - 2 * p1->x * C ^ 2
  mpz_mul(pr->y, p1->x, c->tmp1);
  mpz_mod(pr->y, pr->y, c->p);
  mpz_sub(pr->x, pr->x, pr->y);
  mpz_mod(pr->x, pr->x, c->p);
  mpz_sub(pr->x, pr->x, pr->y);
  mpz_mod(pr->x, pr->x, c->p);

  // tmp2 := tmp2 * p1->y = C ^ 3 * p1->y
  // pr->y := (pr->y - pr->x) * tmp4 - tmp2 = (p1->x * C ^ 2 - pr->x) * D - C ^ 3 * p1->y
  mpz_mul(c->tmp2, c->tmp2, p1->y);
  mpz_mod(c->tmp2, c->tmp2, c->p);
  mpz_sub(pr->y, pr->y, pr->x);
  mpz_mod(pr->y, pr->y, c->p);
  mpz_mul(pr->y, pr->y, c->tmp4);
  mpz_mod(pr->y, pr->y, c->p);
  mpz_sub(pr->y, pr->y, c->tmp2);
  mpz_mod(pr->y, pr->y, c->p);

  assert(point_check(c, pr));
}

void curve_init(Curve *c) {
  mpz_init(c->p);
  mpz_init(c->a);
  mpz_init(c->b);
  mpz_init(c->tmp1);
  mpz_init(c->tmp2);
  mpz_init(c->tmp3);
  mpz_init(c->tmp4);
}

void curve_clear(Curve *c) {
  mpz_clear(c->p);
  mpz_clear(c->a);
  mpz_clear(c->b);
  mpz_clear(c->tmp1);
  mpz_clear(c->tmp2);
  mpz_clear(c->tmp3);
  mpz_clear(c->tmp4);
}

void curve_set(Curve *c, const mpz_t p, const mpz_t a, const mpz_t b) {
  mpz_set(c->p, p);
  mpz_set(c->a, a);
  mpz_set(c->b, b);
}

void curve_set_str(Curve *c, const char *p, const char *a, const char *b) {
  mpz_set_str(c->p, p, 0);
  mpz_set_str(c->a, a, 0);
  mpz_set_str(c->b, b, 0);
}

void cryptocurve_init(CryptoCurve *cc) {
  cc->mults = NULL;
  point_init(&cc->tmpp1);
  point_init(&cc->tmpp2);
}

void cryptocurve_clear(CryptoCurve *cc) {
  point_clear(&cc->tmpp1);
  point_clear(&cc->tmpp2);
  free(cc->mults);
}

void cryptocurve_set(CryptoCurve *cc, Curve *c, const Point *g) {
  cc->c = c;
  cc->g = g;
  cc->size = mpz_sizeinbase(c->p, 2);
  // We round up the number of bytes and limbs, although I think that
  // all used EC have an integer number of bytes
  cc->size_bytes = (cc->size + 7) / 8;

  // Precompute multipliers for faster exponentiation of g
  cc->mults = malloc(cc->size * sizeof(Point));
  point_init(&cc->mults[0]);
  point_copy(&cc->mults[0], cc->g);
  point_normalize(cc->c, &cc->mults[0]);
  for (int i = 1; i < cc->size; i++) {
    point_init(&cc->mults[i]);
    point_square(cc->c, &cc->mults[i], &cc->mults[i-1]);
    point_normalize(cc->c, &cc->mults[i]);
  }
}

void cryptocurve_exp(CryptoCurve *cc, Point *pr, const mpz_t exp) {
  point_set_identity(pr);
  for (int i = 0; i < cc->size; i++) {
    if (mpz_tstbit(exp, i)) {
      point_mult(cc->c, &cc->tmpp1, pr, &cc->mults[i]);
      point_copy(pr, &cc->tmpp1);
    }
  }
}

bool cryptocurve_check_private_key(CryptoCurve *cc, const mpz_t priv, const Point *pub) {
  cryptocurve_exp(cc, &cc->tmpp2, priv);
  return point_eq(cc->c, &cc->tmpp2, pub);
}

bool cryptocurve_check_private_key_str(CryptoCurve *cc, const char *priv, const Point *pub) {
  mpz_t priv_mpz;
  mpz_init(priv_mpz);
  mpz_set_str(priv_mpz, priv, 0);
  return cryptocurve_check_private_key(cc, priv_mpz, pub);
  mpz_clear(priv_mpz);
}

bool cryptocurve_check_private_key_raw(CryptoCurve *cc, const char *priv, const Point *pub) {
  mpz_t priv_mpz;
  mpz_init(priv_mpz);
  mpz_import(priv_mpz, cc->size_bytes, 1, 1, 1, 0, priv);
  return cryptocurve_check_private_key(cc, priv_mpz, pub);
  mpz_clear(priv_mpz);
}

// Just for test
int main_(void) {

  const char *p = "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
  const char *a = "0";
  const char *b = "7";
  const char *g1 = "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
  const char *g2 = "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
  const char *priv = "0x83847e2207c73ec40381dc389adf4d69b0e5d8ed28278857648cebc6bfe7ba93";
  const char *pub1 = "0xc215aa61a2ee4cf174068f33fa58de9a5af6b95bc318e5369bebeefd00766cfe";
  const char *pub2 = "0xbd76f2b9200f7b530a79ae58098463931c349f2dbafd5b222d744a099c13b73a";

  Curve c;
  Point g;
  Point pub;
  CryptoCurve cc;

  curve_init(&c);
  curve_set_str(&c, p, a, b);
  point_init(&g);
  point_set_str(&g, g1, g2);
  point_init(&pub);
  point_set_str(&pub, pub1, pub2);
  cryptocurve_init(&cc);
  cryptocurve_set(&cc, &c, &g);

  if (cryptocurve_check_private_key_str(&cc, priv, &pub)) {
    printf("good\n");
  } else {
    printf("bad\n");
  }

  cryptocurve_clear(&cc);
  point_clear(&pub);
  point_clear(&g);
  curve_clear(&c);

  return 0;

}
