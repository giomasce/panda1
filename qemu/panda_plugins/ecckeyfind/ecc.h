
#pragma once

#include <gmp.h>

#ifdef __cplusplus
extern "C" {
#endif

  typedef struct {
    mpz_t x, y, z;
  } Point;

  typedef struct {
    mpz_t p, a, b;
    // tmp{1-4} are used as temporary values for computations, so that
    // we do not have to allocate and deallocate continuously
    mpz_t tmp1, tmp2, tmp3, tmp4;
  } Curve;

  typedef struct {
    Curve *c;
    const Point *g;
    size_t size, size_bytes;
    Point *mults;
    // tmpp{1-2} are just like tmp* in Curve
    Point tmpp1, tmpp2;
  } CryptoCurve;

  void point_init(Point *p);
  void point_clear(Point *p);
  void point_set(Point *p, const mpz_t x, const mpz_t y);
  void point_set_str(Point *p, const char *x, const char *y);
  void point_set_identity(Point *p);
  void point_copy(Point *pr, const Point *p);
  void point_print(const Point *p, FILE* fout, const char *name);
  bool point_check(Curve *c, const Point *p);
  void point_normalize(Curve *c, Point *p);
  bool point_eq(Curve *c, const Point *p1, const Point *p2);
  void point_square(Curve *c, Point *pr, const Point *p);
  void point_mult(Curve *c, Point *pr, const Point *p1, const Point *p2);
  void curve_init(Curve *c);
  void curve_clear(Curve *c);
  void curve_set(Curve *c, const mpz_t p, const mpz_t a, const mpz_t b);
  void curve_set_str(Curve *c, const char *p, const char *a, const char *b);
  void cryptocurve_init(CryptoCurve *cc);
  void cryptocurve_clear(CryptoCurve *cc);
  void cryptocurve_set(CryptoCurve *cc, Curve *c, const Point *g);
  void cryptocurve_exp(CryptoCurve *cc, Point *pr, const mpz_t exp);
  bool cryptocurve_check_private_key(CryptoCurve *cc, const mpz_t priv, const Point *pub);
  bool cryptocurve_check_private_key_str(CryptoCurve *cc, const char *priv, const Point *pub);
  bool cryptocurve_check_private_key_raw(CryptoCurve *cc, const char *priv, const Point *pub);
  int main_(void);

#ifdef __cplusplus
}
#endif
