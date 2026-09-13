// Exercise the repository cell serializer and generated profile TL-B types.
#include "p0-native.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include "td/utils/crypto.h"
#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

void require(bool ok) { if (!ok) throw std::runtime_error("native profile check failed"); }
td::Ref<vm::Cell> tree(td::Slice raw) {
  vm::CellBuilder b;
  if (raw.size() <= 120) {
    require(raw.size() > 0); b.store_long(0,1).store_long(raw.size(),7).store_bytes(raw);
  } else {
    std::size_t cap=120; while(raw.size()>4*cap) cap*=4;
    b.store_long(1,1).store_long((raw.size()+cap-1)/cap,3).store_long(raw.size(),32);
    for(std::size_t i=0;i<raw.size();i+=cap) b.store_ref(tree(raw.substr(i,std::min(cap,raw.size()-i))));
  }
  return b.finalize();
}
std::string read(td::Ref<vm::Cell> cell, unsigned depth, unsigned& count) {
  require(depth<=10 && ++count<=400000);
  vm::CellSlice s{vm::NoVm{},cell};
  if(s.fetch_ulong(1)==0) {
    auto n=s.fetch_ulong(7); require(n>=1 && n<=120 && s.size()==n*8 && !s.size_refs());
    std::string out(n,'\0'); require(s.fetch_bytes(td::MutableSlice(out))); return out;
  }
  auto n=s.fetch_ulong(3), length=s.fetch_ulong(32); require(n>=2 && n<=4 && !s.size() && s.size_refs()==n);
  std::string out;
  for(unsigned i=0;i<n;++i) out+=read(s.fetch_ref(),depth+1,count);
  require(out.size()==length); return out;
}
int main() {
  try {
    for(std::size_t size: {std::size_t(1),std::size_t(120),std::size_t(121),std::size_t(1048576),std::size_t(33554432)}) {
      std::string raw(size,'\0');
      unsigned x=7; for(auto& c:raw){x^=x<<13;x^=x>>17;x^=x<<5;c=static_cast<char>(x);}
      auto node=tree(raw); vm::CellBuilder outer;
      auto hash=td::sha256(raw);
      outer.store_long(0x76616231,32).store_long(1,16).store_long(size,32).store_bytes(hash).store_ref(node);
      auto cell=outer.finalize(); require(p0wire::t_AuthBytes.validate_ref(500000,cell));
      auto encoded=vm::std_boc_serialize(cell,31); require(encoded.is_ok());
      auto bytes=encoded.move_as_ok(); require(bytes.size()<=67108864);
      auto decoded=vm::std_boc_deserialize(bytes); require(decoded.is_ok());
      auto root=decoded.move_as_ok(); p0wire::AuthBytes::Record record;
      require(p0wire::t_AuthBytes.cell_unpack(root,record)); require(record.version==1 && record.byte_length==size);
      unsigned count=0; auto recovered=read(record.root,0,count); require(recovered==raw);
      require(tree(recovered)->get_hash()==record.root->get_hash());
      std::cout<<size<<' '<<bytes.size()<<' '<<count<<'\n';
    }
    vm::CellBuilder malformed; malformed.store_long(0,1).store_long(0,7);
    require(!p0wire::t_AuthByteNode.validate_ref(malformed.finalize()));
    vm::CellBuilder extra; extra.store_long(0,1).store_long(1,7).store_long(0,8).store_long(0,1);
    require(!p0wire::t_AuthByteNode.validate_ref(extra.finalize()));
    std::cout<<"PASS native TL-B/BOC and malformed leaf controls\n";
  } catch(const std::exception& e) {std::cerr<<e.what()<<'\n';return 1;}
}
