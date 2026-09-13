// Independent ordered-schema decoder and encoder for interoperability checks.
use std::{collections::BTreeMap,env,fs};
#[derive(Clone)]
struct Type {tag:String,fields:Vec<String>}
struct Codec {input:Vec<u8>,output:Vec<u8>,at:usize,types:BTreeMap<String,Type>}
impl Codec {
 fn read(&mut self,n:usize)->Result<u64,String>{
  if n>self.input.len()-self.at{return Err("truncated".into());}
  let mut v=0;for _ in 0..n{v=(v<<8)|u64::from(self.input[self.at]);self.at+=1;}Ok(v)
 }
 fn write(&mut self,v:u64,n:usize){for i in (0..n).rev(){self.output.push((v>>(8*i)) as u8);}}
 fn bytes(&mut self,n:usize)->Result<(),String>{
  if n>self.input.len()-self.at{return Err("truncated".into());}
  self.output.extend_from_slice(&self.input[self.at..self.at+n]);self.at+=n;Ok(())
 }
 fn number(t:&str)->Result<usize,String>{t.parse::<usize>().map_err(|e|e.to_string())}
 fn value(&mut self,t:&str,depth:usize)->Result<(),String>{
  if depth>=64{return Err("depth".into());}
  if ["u8","u16","u32","u64","i32"].contains(&t){let n=Self::number(&t[1..])?/8;let v=self.read(n)?;self.write(v,n);}
  else if t=="h"{self.bytes(32)?;}
  else if let Some(b)=t.strip_prefix('b'){let n=self.read(4)? as usize;if n>Self::number(b)?{return Err("blob-bound".into());}self.write(n as u64,4);self.bytes(n)?;}
  else if let Some(l)=t.strip_prefix('l'){
   let f:Vec<_>=l.split('/').collect();if f.len()!=3{return Err("schema".into());}
   let w=Self::number(f[0])?/8;let n=self.read(w)? as usize;if n>Self::number(f[1])?{return Err("list-bound".into());}
   self.write(n as u64,w);for _ in 0..n{self.value(f[2],depth+1)?;}
  }else{
   let def=self.types.get(t).ok_or("unknown type")?.clone();
   if def.tag!="-"{for c in def.tag.bytes(){if self.read(1)?!=u64::from(c){return Err("tag".into());}self.write(u64::from(c),1);}
    if self.read(2)?!=1{return Err("version".into());}self.write(1,2);
    if self.read(2)?!=0{return Err("flags".into());}self.write(0,2);
   }
   for child in def.fields{self.value(&child,depth+1)?;}
  }
  if self.output.len()>33554432{return Err("object-bound".into());}Ok(())
 }
}
fn run()->Result<(),String>{
 let args:Vec<_>=env::args().collect();if args.len()!=5{return Err("arguments".into());}
 let schema=fs::read_to_string(&args[1]).map_err(|e|e.to_string())?;let mut types=BTreeMap::new();
 for line in schema.lines(){let f:Vec<_>=line.split('|').collect();if f.len()!=3{return Err("schema".into());}
  let fields=if f[2].is_empty(){vec![]}else{f[2].split(',').map(String::from).collect()};types.insert(f[0].into(),Type{tag:f[1].into(),fields});
 }
 let input=fs::read(&args[3]).map_err(|e|e.to_string())?;if input.len()>33554432{return Err("object-bound".into());}
 let mut c=Codec{input,output:vec![],at:0,types};c.value(&args[2],0)?;
 if c.at!=c.input.len(){return Err("trailing".into());}fs::write(&args[4],c.output).map_err(|e|e.to_string())
}
fn main(){if let Err(e)=run(){eprintln!("{}",e);std::process::exit(1);}}
