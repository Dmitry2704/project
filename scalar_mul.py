def scalar_mul(p,n):
  P = p
  Q = p
  R=(0,0) 
  while n>0:
    if n&1:
      R=add_points(R,Q)
    Q=add_points(Q,Q)
    n=n//2
  return R
