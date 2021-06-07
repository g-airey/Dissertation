import scipy.special
import sys

def calculate(N, prob):
    total = 0
    for n in range(int((N + 1) / 2), N+1):
        total += scipy.special.binom(N,n) * prob**n * (1-prob)**(N-n)
    return total

def find(target, prob):
    for n in range(1,1000):
        if n % 2 == 0:
            continue
        if(calculate(n,prob)) >= target:
            return n

if len(sys.argv) < 3:
    print(calculate(3,0.6))
else:
    print(find(target = float(sys.argv[1]), prob = float(sys.argv[2])))

