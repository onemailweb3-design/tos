// Independent ordered-schema decoder and encoder for interoperability checks.
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
struct Type {std::string tag;std::vector<std::string> fields;};
std::map<std::string,Type> types;
std::vector<std::string> split(const std::string& s,char c){std::vector<std::string> out;std::stringstream in(s);std::string p;while(std::getline(in,p,c))out.push_back(p);return out;}
struct Codec {
 std::vector<unsigned char> input,output;std::size_t at=0;
 void require(bool b){if(!b)throw std::runtime_error("refused");}
 std::uint64_t read(unsigned n){require(n<=input.size()-at);std::uint64_t v=0;for(unsigned i=0;i<n;++i)v=(v<<8)|input[at++];return v;}
 void write(std::uint64_t v,unsigned n){for(unsigned i=n;i>0;--i)output.push_back(static_cast<unsigned char>(v>>(8*(i-1))));}
 void bytes(std::size_t n){require(n<=input.size()-at);output.insert(output.end(),input.begin()+at,input.begin()+at+n);at+=n;}
 void value(const std::string& t,unsigned depth=0){
  require(depth<64);
  if(t=="u8"||t=="u16"||t=="u32"||t=="u64"||t=="i32"){unsigned n=std::stoul(t.substr(1))/8;write(read(n),n);}
  else if(t=="h")bytes(32);
  else if(t[0]=='b'){auto n=read(4);require(n<=std::stoull(t.substr(1)));write(n,4);bytes(n);}
  else if(t[0]=='l'){auto f=split(t.substr(1),'/');require(f.size()==3);unsigned w=std::stoul(f[0])/8;auto n=read(w);require(n<=std::stoull(f[1]));write(n,w);for(std::uint64_t i=0;i<n;++i)value(f[2],depth+1);}
  else {auto found=types.find(t);require(found!=types.end());const auto& def=found->second;
   if(def.tag!="-"){for(unsigned char c:def.tag){require(read(1)==c);write(c,1);}require(read(2)==1);write(1,2);require(read(2)==0);write(0,2);}
   for(const auto& child:def.fields)value(child,depth+1);
  }
  require(output.size()<=33554432);
 }
};
int main(int argc,char** argv){try{
 if(argc!=5)throw std::runtime_error("arguments");
 std::ifstream schema(argv[1]);if(!schema)throw std::runtime_error("schema");std::string line;
 while(std::getline(schema,line)){auto f=split(line,'|');if(f.size()<2)throw std::runtime_error("schema line");types.emplace(f[0],Type{f[1],f.size()>2?split(f[2],','):std::vector<std::string>{}});}
 std::ifstream in(argv[3],std::ios::binary);if(!in)throw std::runtime_error("input");Codec c;c.input.assign(std::istreambuf_iterator<char>(in),{});c.require(c.input.size()<=33554432);c.value(argv[2]);c.require(c.at==c.input.size());
 std::ofstream out(argv[4],std::ios::binary);out.write(reinterpret_cast<const char*>(c.output.data()),c.output.size());if(!out)throw std::runtime_error("output");
 }catch(const std::exception& e){std::cerr<<e.what()<<'\n';return 1;}}
