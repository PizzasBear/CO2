(library (libcrypt ecc)
  (export
    ;; General
    gen-ec-keys
    ;; ECDH
    create-ecdh-csk
    ;; EC-Schnorr
    sign-ec-schnorr
    verify-ec-schnorr
    ;; ECDSA
    sign-ecdsa
    verify-ecdsa)
  (import (chezscheme))

  (define A 486662)
  (define B 1)
  (define C 0)
  (define P (- (ash 1 255) 19))
  (define G '(9 . 43114425171068552920764898935933967039370386198203806730763910166200978582548))
  (define N (+ (ash 1 252) 27742317777372353535851937790883648493))

  (define (mod-inv x n)
    (let loop ([r (mod x n)] [r-old n] [y 1] [y-old 0])
      (if (zero? r)
          (mod y-old n)
          (let ([q (div r-old r)])
            (loop
              (- r-old (* q r)) r
              (- y-old (* y q)) y)))))

  (define (mod-div x y n)
    (mod (* (mod x n) (mod-inv y n)) n))

  (define (double-point p)
    (cond
      [(null? p) '()]
      [(zero? (cdr p)) '()]
      [else
        (let*
          ([x (car p)]
           [y (cdr p)]
           [s (mod-div (+ (* 3 x x) (* 2 A x) B) (* 2 y) P)]
           [x-new (mod (- (* s s) A x x) P)]
           [y-new (mod (- (* s (- x x-new)) y) P)])
          (cons x-new y-new))]))

  (define (add-points p q)
    (cond
      [(null? p) q]
      [(null? q) p]
      [(equal? p q) (double-point p)]
      [(= (car p) (car q)) '()]
      [else
        (let*
          ([x1 (car p)]
           [x2 (car q)]
           [y1 (cdr p)]
           [y2 (cdr q)]
           [s (mod-div (- y1 y2) (- x1 x2) P)]
           [x-new (mod (- (* s s) A x1 x2) P)]
           [y-new (mod (- (* s (- x1 x-new)) y1) P)])
          (cons x-new y-new))]))

  (define (scalar-mul k p)
    (let loop ([k k] [p p] [out '()])
      (cond
        [(= k 0) '()]
        [(= k 1) (add-points out p)]
        [(null? p) out]
        [else
          (loop
            (ash k -1)
            (double-point p)
            (if
              (odd? k)
              (add-points p out)
              out))])))

  (define (is-point-on-curve p)
    (let ([x (car p)] [y (cdr p)])
      (or (null? p) (= (* y y) (+ (* x x x) (* A x x) (B x) C)))))

  (define (gen-ec-keys)
    (let ([sk (+ 1 (random (- N 1)))])
      (values sk (scalar-mul sk G))))

  (define (create-ecdh-csk hash sk pk)
    (hash (car (scalar-mul sk pk))))

  (define (sign-ecdsa hash m sk)
    (let*
      ([z (hash m)]
       [k (+ 1 (random (- N 1)))]
       [r (mod (car (scalar-mul k G)) N)]
       [s (mod-div (+ z (* r sk)) k N)])
      (if
        (or (zero? r) (zero? s))
        (sign-ecdsa hash m sk)
        (cons r s))))

  (define (verify-ecdsa hash m ds pk)
    (and
      (not (null? pk))
      (is-point-on-curve pk)
      (null? (scalar-mul N pk))
      (< 0 (car ds) N)
      (< 0 (cdr ds) N))
      (let*
        ([z (hash m)]
         [r (car ds)]
         [s (cdr ds)]
         [inv-s (mod-inv s N)]
         [u1 (mod (* z inv-s) N)]
         [u2 (mod (* r inv-s) N)]
         [x2 (car (add-points (scalar-mul u1 G) (scalar-mul u2 pk)))])
        (= r (mod x2 N))))

  (define (sign-ec-schnorr hash m sk)
    (let*
      ([k (+ 1 (random (- N 1)))]
       [r (mod (car (scalar-mul k G)) N)]
       [e (mod (hash r m) N)]
       [s (mod (- k (* sk e)) N)])
      (if
        (or (zero? r) (zero? e) (zero? s))
        (sign-ec-schnorr hash m sk)
        (cons s e))))

  (define (verify-ec-schnorr hash m ds pk)
    (and
      (not (null? pk))
      (is-point-on-curve pk)
      (< 0 (car ds) N)
      (< 0 (cdr ds) N)
      (let*
        ([s (car ds)]
         [e (cdr ds)]
         [rv (mod (car (add-points (scalar-mul s G) (scalar-mul e pk))) N)]
         [ev (mod (hash rv m) N)])
        (= e ev)))))

