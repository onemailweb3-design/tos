#include "pq-consensus.h"
#include <cassert>
#include <cstdio>
using namespace tos::pq;
int main(){
  std::string pk(mldsa44_public_key_bytes,'\x01'), sig(mldsa44_signature_bytes,'\x02');
  // size controls: 1311/1312/1313 and 2419/2420/2421
  assert(!valid_public_key(PQAlgorithmId::mldsa44, std::string(1311,'x')));
  assert( valid_public_key(PQAlgorithmId::mldsa44, pk));
  assert(!valid_public_key(PQAlgorithmId::mldsa44, std::string(1313,'x')));
  assert(!valid_signature(PQAlgorithmId::mldsa44, std::string(2419,'x')));
  assert( valid_signature(PQAlgorithmId::mldsa44, sig));
  assert(!valid_signature(PQAlgorithmId::mldsa44, std::string(2421,'x')));
  // unknown algorithm fails closed
  assert(!valid_public_key(PQAlgorithmId::unknown, pk));
  assert(!valid_signature(PQAlgorithmId::unknown, sig));
  assert(!is_admitted(PQAlgorithmId::unknown) && is_admitted(PQAlgorithmId::mldsa44));
  // key_id: deterministic, key-dependent, algorithm-dependent, domain-separated
  auto a = derive_key_id(PQAlgorithmId::mldsa44, pk);
  auto b = derive_key_id(PQAlgorithmId::mldsa44, pk);
  assert(a==b);
  std::string pk2=pk; pk2[0]^=1;
  assert(derive_key_id(PQAlgorithmId::mldsa44, pk2)!=a);          // different key -> different id
  assert(derive_key_id(PQAlgorithmId::unknown, pk)!=a);          // algorithm bound into id
  // limits: 100 main and 400 max certificate bounds are sane and monotone
  PQConsensusLimits L;
  assert(L.public_key_bytes==1312 && L.signature_bytes==2420);
  assert(L.certificate_bytes(100) < L.certificate_bytes(400));
  assert(L.max_certificate_bytes()==L.certificate_bytes(400));
  printf("PQ_CONSENSUS_N1_FOUNDATION_OK cert100=%zu cert400=%zu key_id0=%02x\n",
         L.certificate_bytes(100), L.certificate_bytes(400), a[0]);
  return 0;
}
