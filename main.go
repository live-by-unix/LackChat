package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s", hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:]))
}

type Pool[T any] struct {
	p sync.Pool
}

func NewPool[T any](fn func() T) *Pool[T] {
	return &Pool[T]{p: sync.Pool{New: func() any { return fn() }}}
}

func (p *Pool[T]) Get() T  { return p.p.Get().(T) }
func (p *Pool[T]) Put(v T) { p.p.Put(v) }

type Message struct {
	ID         string `json:"id"`
	Room       string `json:"room"`
	FromIP     string `json:"fromIP"`
	Ciphertext string `json:"ciphertext"`
	Nonce      string `json:"nonce"`
	Timestamp  int64  `json:"timestamp"`
}

type Room struct {
	Name      string    `json:"name"`
	CreatedBy string    `json:"createdBy"`
	Messages  []Message `json:"messages"`
}

type Client struct {
	ws   *websocket.Conn
	send chan []byte
	ip   string
}

type BroadcastEvent struct {
	Type    string `json:"type"`
	Payload any    `json:"payload"`
}

type Server struct {
	mu         sync.RWMutex
	rooms      map[string]*Room
	clients    map[*Client]bool
	clientsMu  sync.RWMutex
	allowedIPs map[string]bool
	bufPool    *Pool[*strings.Builder]
}

func NewServer() *Server {
	s := &Server{
		rooms:      make(map[string]*Room),
		clients:    make(map[*Client]bool),
		allowedIPs: make(map[string]bool),
		bufPool:    NewPool(func() *strings.Builder { return &strings.Builder{} }),
	}
	s.rooms["general"] = &Room{Name: "general", CreatedBy: "system", Messages: []Message{}}
	return s
}

func extractIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isHost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1" || ip == "localhost"
}

func (s *Server) isAllowed(ip string) bool {
	if isHost(ip) {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowedIPs[ip]
}

func (s *Server) broadcast(eventType string, payload any) {
	data, err := json.Marshal(BroadcastEvent{Type: eventType, Payload: payload})
	if err != nil {
		return
	}
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()
	for c := range s.clients {
		select {
		case c.send <- data:
		default:
		}
	}
}

func (s *Server) wsHandler(ws *websocket.Conn) {
	ip := extractIP(ws.Request())
	c := &Client{ws: ws, send: make(chan []byte, 256), ip: ip}
	s.clientsMu.Lock()
	s.clients[c] = true
	s.clientsMu.Unlock()
	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, c)
		s.clientsMu.Unlock()
		ws.Close()
	}()
	go func() {
		for data := range c.send {
			ws.Write(data)
		}
	}()
	buf := make([]byte, 1)
	for {
		if _, err := ws.Read(buf); err != nil {
			break
		}
	}
	close(c.send)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rooms := make([]*Room, 0, len(s.rooms))
	for _, room := range s.rooms {
		rooms = append(rooms, room)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rooms)
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Room       string `json:"room"`
		Ciphertext string `json:"ciphertext"`
		Nonce      string `json:"nonce"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Room == "" || req.Ciphertext == "" || req.Nonce == "" {
		http.Error(w, "bad request", 400)
		return
	}
	ip := extractIP(r)
	s.mu.Lock()
	room, ok := s.rooms[req.Room]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "room not found", 404)
		return
	}
	msg := Message{
		ID:         generateID(),
		Room:       req.Room,
		FromIP:     ip,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Timestamp:  time.Now().Unix(),
	}
	room.Messages = append(room.Messages, msg)
	s.mu.Unlock()
	s.broadcast("message", msg)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

func (s *Server) handleDeleteMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		ID   string `json:"id"`
		Room string `json:"room"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" || req.Room == "" {
		http.Error(w, "bad request", 400)
		return
	}
	ip := extractIP(r)
	s.mu.Lock()
	room, ok := s.rooms[req.Room]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "room not found", 404)
		return
	}
	found := false
	for i, m := range room.Messages {
		if m.ID == req.ID {
			if m.FromIP != ip && !isHost(ip) {
				s.mu.Unlock()
				http.Error(w, "forbidden", 403)
				return
			}
			room.Messages = append(room.Messages[:i], room.Messages[i+1:]...)
			found = true
			break
		}
	}
	s.mu.Unlock()
	if !found {
		http.Error(w, "not found", 404)
		return
	}
	s.broadcast("deleteMessage", map[string]string{"id": req.ID, "room": req.Room})
	w.WriteHeader(200)
}

func (s *Server) handleCreateRoom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		http.Error(w, "bad request", 400)
		return
	}
	name := strings.TrimSpace(req.Name)
	ip := extractIP(r)
	s.mu.Lock()
	if _, exists := s.rooms[name]; exists {
		s.mu.Unlock()
		http.Error(w, "room exists", 409)
		return
	}
	room := &Room{Name: name, CreatedBy: ip, Messages: []Message{}}
	s.rooms[name] = room
	s.mu.Unlock()
	s.broadcast("room", map[string]string{"name": name, "createdBy": ip})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(room)
}

func (s *Server) handleHostPage(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)
	if !isHost(ip) {
		http.Error(w, "forbidden", 403)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, hostHTML)
}

func (s *Server) hostMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		if !isHost(ip) {
			http.Error(w, "forbidden", 403)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHostAddIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.IP) == "" {
		http.Error(w, "bad request", 400)
		return
	}
	s.mu.Lock()
	s.allowedIPs[strings.TrimSpace(req.IP)] = true
	s.mu.Unlock()
	w.WriteHeader(200)
}

func (s *Server) handleHostRemoveIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		IP string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.IP) == "" {
		http.Error(w, "bad request", 400)
		return
	}
	s.mu.Lock()
	delete(s.allowedIPs, strings.TrimSpace(req.IP))
	s.mu.Unlock()
	w.WriteHeader(200)
}

func (s *Server) handleHostDeleteRoom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		http.Error(w, "bad request", 400)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "general" {
		http.Error(w, "cannot delete general", 400)
		return
	}
	ip := extractIP(r)
	if !s.isAllowed(ip) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.Lock()
	delete(s.rooms, name)
	s.mu.Unlock()
	s.broadcast("deleteRoom", map[string]string{"name": name})
	w.WriteHeader(200)
}

func (s *Server) handleHostClearRoom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Name) == "" {
		http.Error(w, "bad request", 400)
		return
	}
	name := strings.TrimSpace(req.Name)
	ip := extractIP(r)
	if !s.isAllowed(ip) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.Lock()
	if room, ok := s.rooms[name]; ok {
		room.Messages = []Message{}
	}
	s.mu.Unlock()
	s.broadcast("clearRoom", map[string]string{"name": name})
	w.WriteHeader(200)
}

func (s *Server) handleHostClearAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	ip := extractIP(r)
	if !isHost(ip) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.Lock()
	s.rooms = map[string]*Room{
		"general": {Name: "general", CreatedBy: "system", Messages: []Message{}},
	}
	s.mu.Unlock()
	s.broadcast("clearAll", nil)
	w.WriteHeader(200)
}

func (s *Server) handleHostState(w http.ResponseWriter, r *http.Request) {
	ip := extractIP(r)
	if !isHost(ip) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.RLock()
	type RoomInfo struct {
		Name      string `json:"name"`
		CreatedBy string `json:"createdBy"`
		MsgCount  int    `json:"msgCount"`
	}
	rooms := make([]RoomInfo, 0, len(s.rooms))
	for _, room := range s.rooms {
		rooms = append(rooms, RoomInfo{Name: room.Name, CreatedBy: room.CreatedBy, MsgCount: len(room.Messages)})
	}
	ips := make([]string, 0, len(s.allowedIPs))
	for ip := range s.allowedIPs {
		ips = append(ips, ip)
	}
	s.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"rooms": rooms, "allowedIPs": ips})
}

const mainHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LackChat</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;height:100vh;display:flex;flex-direction:column}
body.dark{background:#1a1a2e;color:#e0e0e0}
body.light{background:#f5f5f5;color:#222}
#app{display:flex;flex:1;overflow:hidden}
#sidebar{width:220px;display:flex;flex-direction:column;border-right:1px solid #444;padding:10px;gap:8px}
body.light #sidebar{border-color:#ccc}
#sidebar h2{font-size:1rem;margin-bottom:4px}
#rooms{flex:1;overflow-y:auto;display:flex;flex-direction:column;gap:4px}
.room-item{padding:6px 10px;border-radius:6px;cursor:pointer;font-size:.9rem}
body.dark .room-item{background:#2a2a4a}
body.light .room-item{background:#ddd}
.room-item.active{background:#5555aa;color:#fff}
#new-room-btn{padding:6px;border-radius:6px;border:none;cursor:pointer;font-size:.85rem}
body.dark #new-room-btn{background:#444;color:#fff}
body.light #new-room-btn{background:#bbb;color:#222}
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#room-header{padding:10px 16px;font-size:1.1rem;font-weight:bold;border-bottom:1px solid #444}
body.light #room-header{border-color:#ccc}
#messages{flex:1;overflow-y:auto;padding:12px;display:flex;flex-direction:column;gap:8px}
.msg{padding:8px 12px;border-radius:8px;max-width:80%;word-break:break-word;cursor:pointer;position:relative}
body.dark .msg{background:#2a2a4a}
body.light .msg{background:#e0e0f0}
.msg .meta{font-size:.72rem;opacity:.6;margin-bottom:2px}
.msg .text{font-size:.92rem}
.msg .decryption-error{color:#f66;font-size:.8rem;font-style:italic}
#input-bar{display:flex;padding:10px;gap:8px;border-top:1px solid #444}
body.light #input-bar{border-color:#ccc}
#msg-input{flex:1;padding:8px 12px;border-radius:8px;border:none;font-size:.95rem;outline:none}
body.dark #msg-input{background:#2a2a4a;color:#fff}
body.light #msg-input{background:#ddd;color:#222}
#send-btn{padding:8px 16px;border-radius:8px;border:none;cursor:pointer;font-weight:bold}
body.dark #send-btn{background:#5555aa;color:#fff}
body.light #send-btn{background:#5555aa;color:#fff}
#top-bar{display:flex;justify-content:space-between;align-items:center;padding:8px 16px;border-bottom:1px solid #444}
body.light #top-bar{border-color:#ccc}
#toggle-btn{padding:4px 12px;border-radius:6px;border:none;cursor:pointer;font-size:.85rem}
body.dark #toggle-btn{background:#333;color:#fff}
body.light #toggle-btn{background:#ccc;color:#222}
.key-prompt{background:#553300;color:#ffcc88;padding:8px 12px;border-radius:6px;font-size:.85rem;display:flex;align-items:center;gap:8px}
.key-btn{padding:3px 10px;border-radius:4px;border:none;cursor:pointer;background:#aa7700;color:#fff;font-size:.8rem}
</style>
</head>
<body class="dark">
<div id="top-bar">
  <span style="font-weight:bold;font-size:1.1rem">LackChat</span>
  <button id="toggle-btn" onclick="toggleTheme()">☀️ Light</button>
</div>
<div id="app">
  <div id="sidebar">
    <h2>Rooms</h2>
    <div id="rooms"></div>
    <button id="new-room-btn" onclick="promptNewRoom()">+ New Room</button>
  </div>
  <div id="main">
    <div id="room-header">general</div>
    <div id="messages"></div>
    <div id="input-bar">
      <input id="msg-input" type="text" placeholder="Type a message..." autocomplete="off" onkeydown="if(event.key==='Enter')sendMessage()">
      <button id="send-btn" onclick="sendMessage()">Send</button>
    </div>
  </div>
</div>
<script>
const enc=new TextEncoder(),dec=new TextDecoder();
let currentRoom='general',rooms={},roomKeys={},ws;

function b64e(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)));}
function b64d(s){const b=atob(s);const u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}

async function generateKeyForRoom(room){
  const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const raw=await crypto.subtle.exportKey('raw',key);
  localStorage.setItem('key_'+room,b64e(raw));
  roomKeys[room]=key;
  return key;
}

async function loadKeyForRoom(room){
  if(roomKeys[room])return roomKeys[room];
  const stored=localStorage.getItem('key_'+room);
  if(!stored)return null;
  const raw=b64d(stored);
  const key=await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']);
  roomKeys[room]=key;
  return key;
}

async function encryptMessage(room,plaintext){
  let key=await loadKeyForRoom(room);
  if(!key)key=await generateKeyForRoom(room);
  const nonce=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv:nonce},key,enc.encode(plaintext));
  return{ciphertextBase64:b64e(ct),nonceBase64:b64e(nonce)};
}

async function decryptMessage(room,ctB64,nonceB64){
  const key=await loadKeyForRoom(room);
  if(!key)return null;
  try{
    const pt=await crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(nonceB64)},key,b64d(ctB64));
    return dec.decode(pt);
  }catch(e){return null;}
}

function saveTheme(t){localStorage.setItem('theme',t);}
function toggleTheme(){
  const d=document.body.classList.contains('dark');
  document.body.classList.toggle('dark',!d);
  document.body.classList.toggle('light',d);
  document.getElementById('toggle-btn').textContent=d?'☀️ Light':'🌙 Dark';
  saveTheme(d?'light':'dark');
}

function applyTheme(){
  const t=localStorage.getItem('theme')||'dark';
  document.body.classList.add(t);
  document.body.classList.remove(t==='dark'?'light':'dark');
  document.getElementById('toggle-btn').textContent=t==='dark'?'☀️ Light':'🌙 Dark';
}

function renderRooms(){
  const el=document.getElementById('rooms');
  el.innerHTML='';
  Object.keys(rooms).sort().forEach(name=>{
    const d=document.createElement('div');
    d.className='room-item'+(name===currentRoom?' active':'');
    d.textContent='# '+name;
    d.onclick=()=>switchRoom(name);
    el.appendChild(d);
  });
}

async function renderMessages(){
  const el=document.getElementById('messages');
  el.innerHTML='';
  const room=rooms[currentRoom];
  if(!room)return;
  const keyStored=localStorage.getItem('key_'+currentRoom);
  if(!keyStored){
    const kp=document.createElement('div');
    kp.className='key-prompt';
    kp.innerHTML='No encryption key for this room. <button class="key-btn" onclick="generateKeyForRoom(\''+currentRoom+'\').then(renderMessages)">Generate Key</button>';
    el.appendChild(kp);
  }
  for(const m of room.messages){
    const d=document.createElement('div');
    d.className='msg';
    d.dataset.id=m.id;
    d.dataset.room=m.room;
    const meta=document.createElement('div');
    meta.className='meta';
    meta.textContent=m.fromIP+' · '+new Date(m.timestamp*1000).toLocaleTimeString();
    const txt=document.createElement('div');
    txt.className='text';
    const pt=await decryptMessage(m.room,m.ciphertext,m.nonce);
    if(pt===null){
      txt.className='decryption-error';
      txt.textContent='[encrypted – key mismatch]';
    }else{
      txt.textContent=pt;
    }
    d.appendChild(meta);
    d.appendChild(txt);
    d.onclick=()=>deleteMsg(m.id,m.room);
    el.appendChild(d);
  }
  el.scrollTop=el.scrollHeight;
}

function switchRoom(name){
  currentRoom=name;
  document.getElementById('room-header').textContent=name;
  renderRooms();
  renderMessages();
}

async function sendMessage(){
  const input=document.getElementById('msg-input');
  const text=input.value.trim();
  if(!text)return;
  input.value='';
  const{ciphertextBase64,nonceBase64}=await encryptMessage(currentRoom,text);
  await fetch('/api/message',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({room:currentRoom,ciphertext:ciphertextBase64,nonce:nonceBase64})});
}

async function deleteMsg(id,room){
  if(!confirm('Delete this message?'))return;
  await fetch('/api/message/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,room})});
}

function promptNewRoom(){
  const name=prompt('Room name:');
  if(!name||!name.trim())return;
  fetch('/api/room',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name:name.trim()})});
}

async function loadState(){
  const res=await fetch('/api/state');
  const data=await res.json();
  rooms={};
  for(const r of data){rooms[r.name]={name:r.name,createdBy:r.createdBy,messages:r.messages||[]};}
  if(!rooms[currentRoom])currentRoom='general';
  renderRooms();
  renderMessages();
}

function connectWS(){
  ws=new WebSocket('ws://'+location.host+'/ws');
  ws.onmessage=async e=>{
    const ev=JSON.parse(e.data);
    if(ev.type==='message'){
      const m=ev.payload;
      if(!rooms[m.room])rooms[m.room]={name:m.room,createdBy:'',messages:[]};
      rooms[m.room].messages.push(m);
      if(m.room===currentRoom){
        const el=document.getElementById('messages');
        const d=document.createElement('div');
        d.className='msg';
        d.dataset.id=m.id;
        d.dataset.room=m.room;
        const meta=document.createElement('div');
        meta.className='meta';
        meta.textContent=m.fromIP+' · '+new Date(m.timestamp*1000).toLocaleTimeString();
        const txt=document.createElement('div');
        txt.className='text';
        const pt=await decryptMessage(m.room,m.ciphertext,m.nonce);
        if(pt===null){txt.className='decryption-error';txt.textContent='[encrypted – key mismatch]';}
        else{txt.textContent=pt;}
        d.appendChild(meta);d.appendChild(txt);
        d.onclick=()=>deleteMsg(m.id,m.room);
        el.appendChild(d);
        el.scrollTop=el.scrollHeight;
      }
    }else if(ev.type==='deleteMessage'){
      const{id,room}=ev.payload;
      if(rooms[room])rooms[room].messages=rooms[room].messages.filter(m=>m.id!==id);
      if(room===currentRoom){const d=document.querySelector('[data-id="'+id+'"]');if(d)d.remove();}
    }else if(ev.type==='room'){
      const r=ev.payload;
      if(!rooms[r.name])rooms[r.name]={name:r.name,createdBy:r.createdBy,messages:[]};
      renderRooms();
    }else if(ev.type==='deleteRoom'){
      const{name}=ev.payload;
      delete rooms[name];
      if(currentRoom===name)switchRoom('general');
      renderRooms();
    }else if(ev.type==='clearRoom'){
      const{name}=ev.payload;
      if(rooms[name])rooms[name].messages=[];
      if(currentRoom===name)renderMessages();
    }else if(ev.type==='clearAll'){
      rooms={general:{name:'general',createdBy:'system',messages:[]}};
      if(currentRoom!=='general')switchRoom('general');
      renderRooms();renderMessages();
    }
  };
  ws.onclose=()=>setTimeout(connectWS,2000);
}

applyTheme();
loadState();
connectWS();
</script>
</body>
</html>`

const hostHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LackChat – Host Dashboard</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#1a1a2e;color:#e0e0e0;padding:20px}
h1{margin-bottom:16px;font-size:1.4rem;color:#aac}
h2{font-size:1rem;margin:16px 0 8px;color:#99b}
table{width:100%;border-collapse:collapse;margin-bottom:12px}
th,td{padding:6px 10px;border:1px solid #333;text-align:left;font-size:.85rem}
th{background:#2a2a4a}
button{padding:4px 12px;border-radius:4px;border:none;cursor:pointer;font-size:.82rem;margin:2px}
.btn-del{background:#8b2222;color:#fff}
.btn-clr{background:#3a6a3a;color:#fff}
.btn-add{background:#2a4a8a;color:#fff}
.btn-rem{background:#6a4a00;color:#fff}
input[type=text]{background:#2a2a4a;color:#fff;border:1px solid #555;padding:4px 8px;border-radius:4px;font-size:.85rem}
#status{margin-top:8px;font-size:.8rem;color:#9f9}
</style>
</head>
<body>
<h1>LackChat – Host Dashboard</h1>
<div id="status"></div>
<h2>Rooms</h2>
<table id="rooms-table">
<thead><tr><th>Name</th><th>Created By</th><th>Messages</th><th>Actions</th></tr></thead>
<tbody id="rooms-body"></tbody>
</table>
<button class="btn-del" onclick="clearAll()">Clear All Rooms (keep general)</button>
<h2>Allowed IPs</h2>
<table id="ips-table">
<thead><tr><th>IP</th><th>Actions</th></tr></thead>
<tbody id="ips-body"></tbody>
</table>
<div style="display:flex;gap:8px;align-items:center;margin-top:8px">
  <input type="text" id="new-ip" placeholder="e.g. 192.168.1.5">
  <button class="btn-add" onclick="addIP()">Add IP</button>
</div>
<script>
function setStatus(msg){document.getElementById('status').textContent=msg;}

async function loadState(){
  const res=await fetch('/api/host/state');
  if(!res.ok){document.body.innerHTML='<h1>Access denied</h1>';return;}
  const data=await res.json();
  const rb=document.getElementById('rooms-body');
  rb.innerHTML='';
  for(const r of(data.rooms||[])){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(r.name)+'</td><td>'+esc(r.createdBy)+'</td><td>'+r.msgCount+'</td><td>'+(r.name!=='general'?'<button class="btn-del" onclick="deleteRoom(\''+esc(r.name)+'\')">Delete</button>':'')+'<button class="btn-clr" onclick="clearRoom(\''+esc(r.name)+'\')">Clear</button></td>';
    rb.appendChild(tr);
  }
  const ib=document.getElementById('ips-body');
  ib.innerHTML='';
  for(const ip of(data.allowedIPs||[])){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(ip)+'</td><td><button class="btn-rem" onclick="removeIP(\''+esc(ip)+'\')">Remove</button></td>';
    ib.appendChild(tr);
  }
}

function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

async function post(url,body){
  const res=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!res.ok)setStatus('Error: '+res.status+' '+res.statusText);
  else setStatus('Done.');
  loadState();
}

function deleteRoom(name){if(confirm('Delete room '+name+'?'))post('/api/host/room/delete',{name});}
function clearRoom(name){if(confirm('Clear messages in '+name+'?'))post('/api/host/room/clear',{name});}
function clearAll(){if(confirm('Clear ALL rooms (keep general)?'))post('/api/host/rooms/clearAll',{});}
function addIP(){const ip=document.getElementById('new-ip').value.trim();if(ip)post('/api/host/allow',{ip});}
function removeIP(ip){post('/api/host/allow/remove',{ip});}

loadState();
setInterval(loadState,5000);
</script>
</body>
</html>`

func main() {
	s := NewServer()

	http.Handle("/ws", websocket.Handler(s.wsHandler))
	http.HandleFunc("/api/state", s.handleState)
	http.HandleFunc("/api/message", s.handleMessage)
	http.HandleFunc("/api/message/delete", s.handleDeleteMessage)
	http.HandleFunc("/api/room", s.handleCreateRoom)
	http.HandleFunc("/host", s.handleHostPage)
	http.HandleFunc("/api/host/state", s.hostMiddleware(s.handleHostState))
	http.HandleFunc("/api/host/allow", s.hostMiddleware(s.handleHostAddIP))
	http.HandleFunc("/api/host/allow/remove", s.hostMiddleware(s.handleHostRemoveIP))
	http.HandleFunc("/api/host/room/delete", s.hostMiddleware(s.handleHostDeleteRoom))
	http.HandleFunc("/api/host/room/clear", s.hostMiddleware(s.handleHostClearRoom))
	http.HandleFunc("/api/host/rooms/clearAll", s.hostMiddleware(s.handleHostClearAll))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, mainHTML)
	})

	fmt.Println("LackChat listening on :7878")
	if err := http.ListenAndServe(":7878", nil); err != nil {
		fmt.Println("Error:", err)
	}
}
