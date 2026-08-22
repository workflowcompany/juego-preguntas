"use strict";
/** Cifrado simétrico para invitaciones — ofuscación en URL, no seguridad fuerte. */
const INVITE=(()=>{
  const SECRET="mistica-invite-k7x-sebas";
  const SALT="juego-preguntas-invite-v1";
  const enc=new TextEncoder(), dec=new TextDecoder();

  function b64urlEncode(bytes){
    let s=btoa(String.fromCharCode(...bytes));
    return s.replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
  }
  function b64urlDecode(str){
    let s=str.replace(/-/g,"+").replace(/_/g,"/");
    while(s.length%4)s+="=";
    const bin=atob(s);
    return Uint8Array.from(bin,c=>c.charCodeAt(0));
  }

  let _key=null;
  async function key(){
    if(_key)return _key;
    const km=await crypto.subtle.importKey("raw",enc.encode(SECRET),"PBKDF2",false,["deriveKey"]);
    _key=await crypto.subtle.deriveKey(
      {name:"PBKDF2",salt:enc.encode(SALT),iterations:120000,hash:"SHA-256"},
      km,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]
    );
    return _key;
  }

  async function encryptName(name){
    const n=String(name).trim();
    if(!n||n.length>24)throw new Error("Nombre inválido");
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const ct=await crypto.subtle.encrypt({name:"AES-GCM",iv},await key(),enc.encode(n));
    const out=new Uint8Array(iv.length+ct.byteLength);
    out.set(iv,0); out.set(new Uint8Array(ct),iv.length);
    return b64urlEncode(out);
  }

  async function decryptName(token){
    if(!token)return null;
    const raw=b64urlDecode(token.trim());
    if(raw.length<13)return null;
    const iv=raw.slice(0,12), data=raw.slice(12);
    const pt=await crypto.subtle.decrypt({name:"AES-GCM",iv},await key(),data);
    const name=dec.decode(pt).trim();
    return name||null;
  }

  function parseInviteId(){
    const q=new URLSearchParams(location.search);
    return q.get("id")||q.get("ID")||"";
  }

  function gameUrl(token){
    let path=location.pathname.replace(/\/generador\.html$/i,"/").replace(/\/g\.html$/i,"/").replace(/\/index\.html$/i,"/");
    if(!path.endsWith("/")) path=path.slice(0,path.lastIndexOf("/")+1);
    return `${location.origin}${path}?id=${encodeURIComponent(token)}`;
  }

  return {encryptName,decryptName,parseInviteId,gameUrl};
})();
