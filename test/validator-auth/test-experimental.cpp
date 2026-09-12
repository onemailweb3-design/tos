/* Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later */
// Real signatures over isolated candidate transcripts. No network scheme IDs
// are allocated and none of these test keys authorizes a running validator.
#include "validator/auth/experimental.h"
#include "crypto/Ed25519.h"
#include "crypto/pq/mldsa44.h"
#include "mldsa_native.h"

#include <algorithm>
#include <array>
#include <functional>
#include <iostream>
#include <limits>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace a = tos::validator::auth::experimental;
namespace {
// Opaque test-local choices, not reservations in a consensus suite registry.
constexpr a::Profile ed{17, 1}, pq{29, 44}, unknown{999, 1};
constexpr char pq_context[] = "TOS-VAL-AUTH-EXPERIMENT/v1";
unsigned checks = 0;
void expect(bool condition, const std::string& label) {
  if (!condition) throw std::runtime_error(label);
  ++checks;
  std::cout << "PASS\t" << label << '\n';
}
a::Digest digest(unsigned char value) { a::Digest out{}; out.fill(value); return out; }
std::vector<std::uint8_t> bytes(td::Slice value) {
  return {reinterpret_cast<const std::uint8_t*>(value.data()),
          reinterpret_cast<const std::uint8_t*>(value.data()) + value.size()};
}
std::string_view view(a::Bytes value) {
  return {reinterpret_cast<const char*>(value.data()), value.size()};
}
std::string hex(a::Bytes value) {
  constexpr char digits[] = "0123456789abcdef";
  std::string out;
  for (auto ch : value) { out += digits[ch >> 4]; out += digits[ch & 15]; }
  return out;
}
struct Keys {
  td::Ed25519::PrivateKey classic;
  std::array<std::uint8_t, MLDSA44_PUBLICKEYBYTES> public_pq{};
  std::array<std::uint8_t, MLDSA44_SECRETKEYBYTES> private_pq{};
  explicit Keys(unsigned char seed_byte) : classic(td::SecureString(std::string(32, static_cast<char>(seed_byte)))) {
    std::array<std::uint8_t, MLDSA_SEEDBYTES> seed{}; seed.fill(seed_byte);
    if (tos_validator_auth_test_keypair_internal(public_pq.data(), private_pq.data(), seed.data()) != 0)
      throw std::runtime_error("test-key-generation");
  }
  Keys(const Keys&) = delete;
  ~Keys() { volatile std::uint8_t* p = private_pq.data(); for (std::size_t i=0;i<private_pq.size();++i) p[i]=0; }
  std::vector<std::uint8_t> public_key(a::Profile profile) const {
    if (profile == ed) return bytes(classic.get_public_key().move_as_ok().as_octet_string());
    if (profile == pq) return {public_pq.begin(), public_pq.end()};
    throw std::runtime_error("test-unsupported-key");
  }
  std::vector<std::uint8_t> sign(a::Profile profile, a::Bytes message) const {
    if (profile == ed) return bytes(classic.sign(a::slice(message)).move_as_ok());
    if (profile != pq) throw std::runtime_error("test-unsupported-signature");
    std::array<std::uint8_t, MLDSA_RNDBYTES> rnd{};
    std::vector<std::uint8_t> sig(MLDSA44_BYTES);
    std::vector<std::uint8_t> prefix{0, sizeof(pq_context)-1};
    prefix.insert(prefix.end(), pq_context, pq_context + sizeof(pq_context)-1);
    if (tos_validator_auth_test_signature_internal(sig.data(), message.data(), message.size(),
        prefix.data(), prefix.size(), rnd.data(), private_pq.data(), 0) != 0)
      throw std::runtime_error("test-signing");
    return sig;
  }
};
struct Provider {
  unsigned ed_calls=0, pq_calls=0;
  bool pq_enabled=true, force_backend_error=false;
  bool supports(a::Profile p) const { return p == ed || (p == pq && pq_enabled); }
  bool canonical(a::Profile p, a::Bytes key, a::Bytes signature) const {
    return (p == ed && key.size()==32 && signature.size()==64) ||
           (p == pq && key.size()==1312 && signature.size()==2420);
  }
  a::CryptoResult verify(a::Profile profile, a::Bytes key, a::Bytes message, a::Bytes signature) {
    if (!supports(profile)) return a::CryptoResult::unsupported;
    if (profile == ed) ++ed_calls; else ++pq_calls;
    if (force_backend_error) return a::CryptoResult::backend_error; // explicit fault injection, not a crypto verdict
    if (!canonical(profile,key,signature)) return a::CryptoResult::invalid;
    if (profile == ed) {
      td::Ed25519::PublicKey public_key(td::SecureString(a::slice(key)));
      return public_key.verify_signature(a::slice(message), a::slice(signature)).is_ok()
          ? a::CryptoResult::valid : a::CryptoResult::invalid;
    }
    switch (tos::pq::verify_mldsa44(view(message), pq_context, view(signature), view(key))) {
      case tos::pq::VerifyResult::valid: return a::CryptoResult::valid;
      case tos::pq::VerifyResult::invalid:
      case tos::pq::VerifyResult::malformed_input: return a::CryptoResult::invalid;
      case tos::pq::VerifyResult::backend_error: return a::CryptoResult::backend_error;
    }
    return a::CryptoResult::backend_error;
  }
};
struct Certificate {
  std::vector<std::vector<std::vector<std::uint8_t>>> signatures;
  std::vector<std::vector<a::Component>> components;
  std::vector<a::SignedRecord> records;
};
struct Fixture {
  std::array<std::unique_ptr<Keys>,3> keys;
  std::vector<a::ValidatorRecord> roster;
  a::Context context{42,digest(2),digest(3),0,0x8000000000000000ULL,100,a::Role::proposal,digest(4)};
  Fixture() {
    for (unsigned i=0;i<3;++i) {
      keys[i]=std::make_unique<Keys>(static_cast<unsigned char>(11+i));
      a::ValidatorRecord record{digest(static_cast<unsigned char>(i+1)),1,{}};
      for (unsigned role=1;role<=5;++role) for (auto profile : {ed,pq})
        record.keys.push_back({profile,static_cast<a::Role>(role),9,10,1000,true,keys[i]->public_key(profile)});
      roster.push_back(std::move(record));
    }
  }
  a::Policy policy(a::Phase phase) const { return {phase,ed,pq,digest(5)}; }
  Certificate certificate(const a::Registry& registry, const a::Policy& policy, const a::Context& ctx,
                          std::vector<unsigned> signers = {0,1}) const {
    Certificate result;
    const auto profiles=a::required_profiles(policy);
    for (auto i : signers) {
      const auto* record=registry.find(roster.at(i).identity);
      if (!record) throw std::runtime_error("missing-test-signer");
      auto message=a::statement(registry,policy,ctx,*record);
      if (message.empty()) throw std::runtime_error("missing-test-key");
      std::vector<std::vector<std::uint8_t>> signatures;
      for (auto profile : profiles) signatures.push_back(keys[i]->sign(profile,message));
      result.signatures.push_back(std::move(signatures));
    }
    for (std::size_t i=0;i<signers.size();++i) {
      std::vector<a::Component> components;
      const auto* record=registry.find(roster.at(signers[i]).identity);
      for (std::size_t j=0;j<profiles.size();++j)
        components.push_back({profiles[j],a::key_for(*record,profiles[j],ctx)->epoch,result.signatures[i][j]});
      result.components.push_back(std::move(components));
    }
    for (std::size_t i=0;i<signers.size();++i) result.records.push_back({roster.at(signers[i]).identity,result.components[i]});
    return result;
  }
};
void check_result(const a::Registry& registry, const a::Policy& policy, const a::Context& context,
                  const Certificate& cert, a::Error error, const std::string& label,
                  bool pre_crypto=false) {
  Provider provider;
  auto result=a::verify(registry,policy,context,cert.records,provider);
  expect(result.error==error,label);
  if (error!=a::Error::none) expect(result.weight==0,label+"-no-authorized-weight");
  if (pre_crypto) expect(provider.ed_calls+provider.pq_calls==0,label+"-before-crypto");
}
void phases(Fixture& f) {
  a::Registry registry(f.roster);
  for (auto phase : {a::Phase::classical,a::Phase::shadow,a::Phase::hybrid_required,a::Phase::pq_required}) {
    auto policy=f.policy(phase);
    for (unsigned role=1;role<=5;++role) {
      auto ctx=f.context;ctx.role=static_cast<a::Role>(role);
      auto cert=f.certificate(registry,policy,ctx);
      Provider p;auto result=a::verify(registry,policy,ctx,cert.records,p);
      const auto label="phase-"+std::to_string(static_cast<int>(phase))+"-role-"+std::to_string(role);
      expect(result.accepted()&&result.weight==2,label);
      expect(p.ed_calls==(phase==a::Phase::pq_required?0U:2U),label+"-classical-call-count");
      expect(p.pq_calls==((phase==a::Phase::hybrid_required||phase==a::Phase::pq_required)?2U:0U),label+"-pq-call-count");
      if (role==1) {
        const auto* signer=registry.find(cert.records[0].identity);
        auto message=a::statement(registry,policy,ctx,*signer);
        for (const auto& component : cert.components[0])
          std::cout<<"VECTOR\t"<<label<<'\t'<<(component.profile==ed?"ed25519":"mldsa44")<<'\t'
                   <<hex(a::key_for(*signer,component.profile,ctx)->bytes)<<'\t'<<hex(message)<<'\t'<<hex(component.bytes)<<'\n';
      }
      cert.signatures[0][0][0]^=1;
      check_result(registry,policy,ctx,cert,a::Error::signature,label+"-invalid-real-proof");
    }
  }
  auto policy=f.policy(a::Phase::classical);
  auto cert=f.certificate(registry,policy,f.context);
  auto extra=f.certificate(registry,f.policy(a::Phase::hybrid_required),f.context);
  check_result(registry,policy,f.context,extra,a::Error::components,"classical-forbids-extra-authoritative-pq",true);
  check_result(registry,f.policy(a::Phase::shadow),f.context,extra,a::Error::components,"shadow-forbids-authoritative-sidecar",true);
  check_result(registry,f.policy(a::Phase::pq_required),f.context,cert,a::Error::components,"pq-required-forbids-classical-fallback",true);
  Provider p;p.pq_enabled=false;
  expect(a::verify(registry,policy,f.context,cert.records,p).accepted(),"classical-needs-no-pq-provider");
  // Shadow diagnostics are explicit and have no route into authoritative weight.
  auto shadow=f.policy(a::Phase::shadow);auto sc=f.certificate(registry,shadow,f.context);
  expect(a::statement(registry,policy,f.context,*registry.find(f.roster[0].identity)) ==
         a::statement(registry,shadow,f.context,*registry.find(f.roster[0].identity)),
         "shadow-does-not-rewrite-classical-transcript");
  expect(a::verify(registry,shadow,f.context,cert.records,p).accepted(),"shadow-accepts-existing-classical-proof");
  Provider sp;sp.pq_enabled=false;
  expect(a::verify(registry,shadow,f.context,sc.records,sp).accepted()&&sp.pq_calls==0,"shadow-unavailable-backend-no-authority");
  auto msg=a::statement(registry,shadow,f.context,*registry.find(f.roster[0].identity));
  auto signature=f.keys[0]->sign(pq,msg);signature[0]^=1;
  Provider observer;
  auto observation=a::observe_shadow(pq,f.keys[0]->public_key(pq),msg,signature,observer);
  expect(observation.result==a::CryptoResult::invalid,"shadow-bad-real-pq-observed");
  expect(a::verify(registry,shadow,f.context,sc.records,sp).accepted(),"shadow-failure-does-not-reject-classical");
  sc.signatures[0][0][0]^=1;
  expect(!a::verify(registry,shadow,f.context,sc.records,sp).accepted(),"shadow-cannot-rescue-classical");
}
void hybrid(Fixture& f) {
  a::Registry registry(f.roster);auto policy=f.policy(a::Phase::hybrid_required);
  auto good=f.certificate(registry,policy,f.context);
  for (unsigned component=0;component<2;++component) {
    auto cert=f.certificate(registry,policy,f.context);cert.signatures[0][component][0]^=1;
    check_result(registry,policy,f.context,cert,a::Error::signature,"hybrid-component-"+std::to_string(component)+"-required");
    cert=f.certificate(registry,policy,f.context);cert.records[0].components=std::span(cert.components[0]).first(1);
    check_result(registry,policy,f.context,cert,a::Error::components,"hybrid-omitted-component-"+std::to_string(component),true);
  }
  auto independent=f.certificate(registry,policy,f.context,{0,1,2});
  independent.signatures[0][1][0]^=1;independent.signatures[2][0][0]^=1;
  check_result(registry,policy,f.context,independent,a::Error::signature,"independent-component-quorums-not-intersection");
  auto surplus=f.certificate(registry,policy,f.context,{0,1,2});surplus.signatures[2][1][0]^=1;
  check_result(registry,policy,f.context,surplus,a::Error::signature,"invalid-surplus-signer-not-ignored");
  auto changed=policy;changed.pq=unknown;
  check_result(registry,changed,f.context,good,a::Error::policy,"unknown-mandatory-suite",true);
  changed=policy;changed.pq=ed;
  check_result(registry,changed,f.context,good,a::Error::policy,"aliased-hybrid-components",true);
  changed=policy;changed.phase=static_cast<a::Phase>(255);
  check_result(registry,changed,f.context,good,a::Error::policy,"unknown-phase",true);
  Provider failed;failed.force_backend_error=true;
  expect(a::verify(registry,policy,f.context,good.records,failed).error==a::Error::backend,"backend-error-no-fallback");
}
void context_binding(Fixture& f) {
  a::Registry registry(f.roster);auto policy=f.policy(a::Phase::hybrid_required);
  auto cert=f.certificate(registry,policy,f.context);
  const std::vector<std::pair<std::string,std::function<void(a::Context&)>>> mutations={
    {"network",[](auto& c){++c.network;}},{"genesis",[](auto& c){c.genesis[0]^=1;}},
    {"session",[](auto& c){c.session[0]^=1;}},{"workchain",[](auto& c){c.workchain=-1;}},
    {"shard",[](auto& c){c.shard^=1;}},{"slot",[](auto& c){++c.slot;}},
    {"role",[](auto& c){c.role=a::Role::finalize;}},{"payload",[](auto& c){c.payload[0]^=1;}}
  };
  for (const auto& [name,mutate] : mutations) {
    auto context=f.context;mutate(context);
    check_result(registry,policy,context,cert,a::Error::signature,"bound-"+name);
  }
  auto changed=policy;changed.governance_commitment[0]^=1;
  check_result(registry,changed,f.context,cert,a::Error::signature,"bound-policy-commitment");
  auto unknown_role=f.context;unknown_role.role=static_cast<a::Role>(0);
  check_result(registry,policy,unknown_role,cert,a::Error::policy,"unknown-role",true);
  auto changed_roster=f.roster;changed_roster[2].weight=2;
  a::Registry weight_registry(changed_roster);
  auto all=f.certificate(registry,policy,f.context,{0,1,2});
  check_result(weight_registry,policy,f.context,all,a::Error::signature,"full-roster-weight-commitment");
  changed_roster=f.roster;changed_roster[2].keys[1].bytes=f.keys[1]->public_key(pq);
  a::Registry key_registry(changed_roster);
  check_result(key_registry,policy,f.context,cert,a::Error::signature,"absent-signer-key-commitment");
  changed_roster=f.roster;for(auto& key:changed_roster[0].keys)key.bytes=f.keys[1]->public_key(key.profile);
  a::Registry replaced(changed_roster);
  check_result(replaced,policy,f.context,cert,a::Error::signature,"registered-key-replacement");
}
void rejection_and_limits(Fixture& f) {
  a::Registry registry(f.roster);auto policy=f.policy(a::Phase::hybrid_required);
  auto run=[&](const Certificate& c,a::Error e,const std::string& label){check_result(registry,policy,f.context,c,e,label,true);};
  auto cert=f.certificate(registry,policy,f.context);cert.records[1].identity=cert.records[0].identity;
  run(cert,a::Error::duplicate_signer,"duplicate-signer");
  cert=f.certificate(registry,policy,f.context);cert.records[1].identity=digest(99);
  run(cert,a::Error::unknown_signer,"unknown-signer");
  cert=f.certificate(registry,policy,f.context,{0});run(cert,a::Error::quorum,"insufficient-weight");
  cert=f.certificate(registry,policy,f.context);cert.records.clear();run(cert,a::Error::count,"empty-certificate");
  cert=f.certificate(registry,policy,f.context);std::swap(cert.components[0][0],cert.components[0][1]);
  run(cert,a::Error::components,"noncanonical-component-order");
  cert=f.certificate(registry,policy,f.context);cert.components[0][1]=cert.components[0][0];
  run(cert,a::Error::components,"duplicate-component");
  cert=f.certificate(registry,policy,f.context);cert.components[0][0].profile.parameters=2;
  run(cert,a::Error::components,"wrong-parameter-profile");
  cert=f.certificate(registry,policy,f.context);++cert.components[0][1].key_epoch;
  run(cert,a::Error::key_binding,"wrong-key-epoch");
  for(unsigned component=0;component<2;++component)for(std::size_t n:{std::size_t(0),std::size_t(1),std::size_t(63),std::size_t(65),std::size_t(1312),std::size_t(2419),std::size_t(2421),a::max_signature_bytes+1}) {
    cert=f.certificate(registry,policy,f.context);std::vector<std::uint8_t> raw(n);
    cert.components[0][component].bytes=raw;
    run(cert,n==0||n>a::max_signature_bytes?a::Error::resource:a::Error::components,
        "length-"+std::to_string(component)+"-"+std::to_string(n));
  }
  auto epoch_roster=f.roster;++epoch_roster[0].keys[1].epoch;
  a::Registry new_epoch(epoch_roster);cert=f.certificate(registry,policy,f.context);
  ++cert.components[0][1].key_epoch;
  check_result(new_epoch,policy,f.context,cert,a::Error::signature,"epoch-relabel-does-not-reuse-old-proof");
  for(const std::string name:{"disabled","retired","not-yet-valid","epoch"}) {
    auto roster=f.roster;auto& key=roster[0].keys[1];
    if(name=="disabled")key.enabled=false;
    if(name=="retired")key.last_slot=99;
    if(name=="not-yet-valid")key.first_slot=101;
    if(name=="epoch")++key.epoch;
    a::Registry altered(roster);cert=f.certificate(registry,policy,f.context);
    check_result(altered,policy,f.context,cert,a::Error::key_binding,"key-"+name,true);
  }
  for(std::uint32_t slot:{10U,1000U}) {
    auto ctx=f.context;ctx.slot=slot;auto boundary=f.certificate(registry,policy,ctx);
    check_result(registry,policy,ctx,boundary,a::Error::none,"key-window-inclusive-"+std::to_string(slot));
  }
  cert=f.certificate(registry,policy,f.context);
  auto bad_registry=[&](std::vector<a::ValidatorRecord> rows,const std::string& label){
    a::Registry bad(std::move(rows));expect(!bad.valid(),label+"-admission");
    check_result(bad,policy,f.context,cert,a::Error::registry,label,true);
  };
  bad_registry({},"empty-registry");
  std::vector<a::ValidatorRecord> oversized(a::max_validators+1,f.roster[0]);
  for(std::size_t i=0;i<oversized.size();++i) {
    oversized[i].identity={};oversized[i].identity[30]=static_cast<std::uint8_t>(i>>8);
    oversized[i].identity[31]=static_cast<std::uint8_t>(i);
  }
  bad_registry(std::move(oversized),"validator-count-bound");
  auto roster=f.roster;roster[0].weight=0;bad_registry(roster,"zero-weight");
  roster=f.roster;roster[0].weight=tos::kMaxTotalValidatorWeight;bad_registry(roster,"weight-overflow");
  roster=f.roster;roster[1].identity=roster[0].identity;bad_registry(roster,"duplicate-identity");
  roster=f.roster;std::swap(roster[0],roster[1]);bad_registry(roster,"unsorted-registry");
  roster=f.roster;roster[0].keys[1]=roster[0].keys[0];bad_registry(roster,"duplicate-key-role-suite");
  roster=f.roster;roster[0].keys[0].bytes.resize(a::max_key_bytes+1);bad_registry(roster,"key-size-bound");
  roster=f.roster;roster[0].keys[0].first_slot=1001;bad_registry(roster,"inverted-validity");
  roster=f.roster;roster[0].keys[0].role=static_cast<a::Role>(0);bad_registry(roster,"unknown-key-role");
  roster=f.roster;roster[0].keys.clear();bad_registry(roster,"no-key-record");
  roster=f.roster;roster[0].keys[0].bytes.clear();bad_registry(roster,"empty-public-key");
  roster=f.roster;roster[0].keys.push_back(roster[0].keys.back());
  roster[0].keys.back().profile=unknown;bad_registry(roster,"key-count-bound");
  roster=f.roster;roster[0].weight=7;roster[1].weight=2;roster[2].weight=1;
  a::Registry weighted(roster);auto heavy=f.certificate(weighted,policy,f.context,{0});
  check_result(weighted,policy,f.context,heavy,a::Error::none,"weighted-quorum");
  roster={f.roster[0]};roster[0].weight=tos::kMaxTotalValidatorWeight;
  a::Registry capped(roster);auto maximum=f.certificate(capped,policy,f.context,{0});
  Provider cap_provider;auto cap_result=a::verify(capped,policy,f.context,maximum.records,cap_provider);
  expect(cap_result.accepted()&&cap_result.weight==tos::kMaxTotalValidatorWeight,"exact-maximum-weight");
  auto light=f.certificate(weighted,policy,f.context,{1,2});
  check_result(weighted,policy,f.context,light,a::Error::quorum,"absent-heavy-voter-kept-in-denominator",true);
}

void future_resource_budget(Fixture& f) {
  // A deliberately noncryptographic shape probe exercises sizes no enabled
  // algorithm produces today. It NEVER returns valid, and must not be reported
  // as a PQ cryptographic test. It only tells whether admission reached crypto.
  struct ShapeProbe {
    unsigned calls=0;
    bool supports(a::Profile)const{return true;}
    bool canonical(a::Profile,a::Bytes,a::Bytes)const{return true;}
    a::CryptoResult verify(a::Profile,a::Bytes,a::Bytes,a::Bytes){++calls;return a::CryptoResult::backend_error;}
  };
  auto roster=f.roster;
  roster.resize(a::max_certificate_bytes/a::max_signature_bytes+1,roster[0]);
  for(std::size_t i=0;i<roster.size();++i) {
    roster[i].identity={};roster[i].identity[30]=static_cast<std::uint8_t>(i>>8);
    roster[i].identity[31]=static_cast<std::uint8_t>(i);
  }
  a::Registry registry(roster);
  expect(registry.valid(),"aggregate-budget-fixture-admitted");
  const auto policy=f.policy(a::Phase::classical);
  std::vector<std::uint8_t> raw(a::max_signature_bytes);
  const std::array<a::Component,1> components{{{ed,9,raw}}};
  std::vector<a::SignedRecord> records;
  for(const auto& record:roster)records.push_back({record.identity,components});
  ShapeProbe over;
  auto result=a::verify(registry,policy,f.context,records,over);
  expect(result.error==a::Error::resource&&over.calls==0,"aggregate-budget-rejected-before-crypto");
  records.pop_back();
  ShapeProbe exact;
  result=a::verify(registry,policy,f.context,records,exact);
  expect(result.error==a::Error::backend&&exact.calls==1,"aggregate-budget-exact-bound-reaches-provider");
}
}
int main(int argc,char**) {
  try {
    if(argc!=1)throw std::runtime_error("usage: test-validator-auth-experimental (no arguments)");
    Fixture fixture;phases(fixture);hybrid(fixture);context_binding(fixture);rejection_and_limits(fixture);future_resource_budget(fixture);
    std::cout<<"SUMMARY\t"<<checks<<"\tisolated real Ed25519/ML-DSA verification; no network activation\n";
    return 0;
  }catch(const std::exception& error){std::cerr<<"FAIL\t"<<error.what()<<'\n';return 1;}
}
