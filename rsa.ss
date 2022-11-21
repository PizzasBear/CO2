(library (libcrypt rsa)
  (export is-prime sign-rsa verify-rsa rsa gen-rsa-key)
  (import (chezscheme))

  (define BITS 3072)
  (define PRIME-BITS (ash BITS -1))

  (define (mod-inv x n)
    (let loop ([r x] [r-old n] [y 1] [y-old 0])
      (if (zero? r)
          (mod y-old n)
          (let ([q (div r-old r)])
            (loop
              (- r-old (* q r)) r
              (- y-old (* y q)) y)))))

  (define first-primes
    (reverse
      (let loop ([a '()] [n 2])
        (cond
          ((= (length a) 50) a)
          ((let loop ([a a])
             (cond
               ((null? a) #t)
               ((zero? (mod n (car a))) #f)
               (else (loop (cdr a)))))
           (loop (cons n a) (+ 1 n)))
          (else (loop a (+ 1 n)))))))

  (define (miller-rabin n k)
    (cond
      ((= n 2) #t)
      ((= n 3) #t)
      ((even? n) #f)
      (else
        (let loop ([r 1] [d (ash n -1)])
          (if
            (even? d)
            (loop (ash r 1) (ash d -1))
            (let kloop ([k k])
              (if
                (zero? k)
                #t
                (let*
                  ([a (+ 2 (random (- n 3)))]
                   [x (expt-mod a d n)])
                  (let loop ([i r] [x x])
                    (cond
                      ((zero? i) #f)
                      ((or (= x 1) (= x (+ -1 n))) (kloop (+ -1 k)))
                      (else (loop (+ -1 i) (mod (* x x) n)))))))))))))

  (define (small-prime-check n)
    (let loop ([a first-primes])
      (cond
        ((null? a) #t)
        ((= n (car a)) #t)
        ((zero? (mod n (car a))) #f)
        (else (loop (cdr a))))))

  (define (is-prime n)
    (and (small-prime-check n) (miller-rabin n 40)))

  (define (gen-prime)
    (let loop ([n (logor (ash 1 (- PRIME-BITS 1)) (random (ash 1 (- PRIME-BITS 1))))])
      (if (is-prime n)
          n
          (loop (+ 1 n)))))

  (define (create-rsa-key p q)
    (let*
      ([lam (lcm (+ -1 p) (+ -1 q))]
       [n (* p q)]
       [e (let loop ([e (random lam)])
            (if
              (= (gcd e lam) 1)
              e
              (loop (+ 1 e))))]
       [d (mod-inv e lam)])
      (values (cons e n) (cons d n))))

  (define (gen-rsa-key)
    (create-rsa-key (gen-prime) (gen-prime)))

  (define (rsa m k)
    (expt-mod m (car k) (cdr k)))

  (define (sign-rsa hash m sk)
    (rsa (hash m) sk))

  (define (verify-rsa hash m ds pk)
    (= (rsa ds pk) (hash m))))
