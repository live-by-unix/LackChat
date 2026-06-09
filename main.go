package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/websocket"
)

// ─── ID generation ────────────────────────────────────────────────────────────

func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:]))
}

// ─── Generic pool ─────────────────────────────────────────────────────────────

type Pool[T any] struct{ p sync.Pool }

func NewPool[T any](fn func() T) *Pool[T] {
	return &Pool[T]{p: sync.Pool{New: func() any { return fn() }}}
}
func (p *Pool[T]) Get() T  { return p.p.Get().(T) }
func (p *Pool[T]) Put(v T) { p.p.Put(v) }

// ─── Data model ───────────────────────────────────────────────────────────────

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

// roomMeta is the on-disk room header (no messages).
type roomMeta struct {
	Name      string `json:"name"`
	CreatedBy string `json:"createdBy"`
}

// ─── Persistence helpers ──────────────────────────────────────────────────────

// dataDir layout:
//
//	lackchat-data/
//	  rooms/<roomname>/meta.json       – room metadata
//	  rooms/<roomname>/messages.jsonl  – one Message JSON per line
//	  allowed_ips.json                 – []string

const dataDir = "lackchat-data"

func roomDir(name string) string  { return filepath.Join(dataDir, "rooms", name) }
func metaFile(name string) string { return filepath.Join(roomDir(name), "meta.json") }
func msgsFile(name string) string { return filepath.Join(roomDir(name), "messages.jsonl") }
func allowedIPsFile() string      { return filepath.Join(dataDir, "allowed_ips.json") }

func ensureDir(path string) error { return os.MkdirAll(path, 0755) }

func writeJSON(path string, v any) error {
	tmp := path + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(v); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	f.Close()
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewDecoder(f).Decode(v)
}

// appendMessageToDisk appends a single message as a JSONL line.
func appendMessageToDisk(msg Message) error {
	if err := ensureDir(roomDir(msg.Room)); err != nil {
		return err
	}
	f, err := os.OpenFile(msgsFile(msg.Room), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(msg)
}

// rewriteMessages rewrites the full messages.jsonl for a room (used on delete/clear).
func rewriteMessages(roomName string, msgs []Message) error {
	if err := ensureDir(roomDir(roomName)); err != nil {
		return err
	}
	f, err := os.Create(msgsFile(roomName))
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for _, m := range msgs {
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	return nil
}

// loadMessagesFromDisk reads messages.jsonl for a room.
func loadMessagesFromDisk(roomName string) ([]Message, error) {
	path := msgsFile(roomName)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return []Message{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var msgs []Message
	dec := json.NewDecoder(f)
	for {
		var m Message
		if err := dec.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}
			// skip corrupt lines
			continue
		}
		msgs = append(msgs, m)
	}
	if msgs == nil {
		msgs = []Message{}
	}
	return msgs, nil
}

// persistRoom writes room meta to disk.
func persistRoom(r *Room) error {
	if err := ensureDir(roomDir(r.Name)); err != nil {
		return err
	}
	return writeJSON(metaFile(r.Name), roomMeta{Name: r.Name, CreatedBy: r.CreatedBy})
}

// deleteRoomFromDisk removes the room directory entirely.
func deleteRoomFromDisk(name string) error {
	return os.RemoveAll(roomDir(name))
}

// loadAllRooms scans lackchat-data/rooms/ and rebuilds the in-memory map.
func loadAllRooms() (map[string]*Room, error) {
	rooms := make(map[string]*Room)
	roomsDir := filepath.Join(dataDir, "rooms")
	entries, err := os.ReadDir(roomsDir)
	if os.IsNotExist(err) {
		return rooms, nil
	}
	if err != nil {
		return rooms, err
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		var meta roomMeta
		if err := readJSON(metaFile(name), &meta); err != nil {
			log.Printf("warn: skipping room %q – cannot read meta: %v", name, err)
			continue
		}
		msgs, err := loadMessagesFromDisk(name)
		if err != nil {
			log.Printf("warn: room %q messages unreadable: %v", name, err)
			msgs = []Message{}
		}
		rooms[name] = &Room{Name: meta.Name, CreatedBy: meta.CreatedBy, Messages: msgs}
	}
	return rooms, nil
}

// persistAllowedIPs saves the allowed IP set.
func persistAllowedIPs(ips map[string]bool) {
	list := make([]string, 0, len(ips))
	for ip := range ips {
		list = append(list, ip)
	}
	if err := writeJSON(allowedIPsFile(), list); err != nil {
		log.Printf("warn: could not persist allowed IPs: %v", err)
	}
}

// loadAllowedIPs reads the allowed IP set from disk.
func loadAllowedIPs() map[string]bool {
	m := make(map[string]bool)
	var list []string
	if err := readJSON(allowedIPsFile(), &list); err != nil {
		return m
	}
	for _, ip := range list {
		m[ip] = true
	}
	return m
}

// ─── Server ───────────────────────────────────────────────────────────────────

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
	clientsMu  sync.RWMutex
	clients    map[*Client]bool
	allowedIPs map[string]bool
	bufPool    *Pool[*strings.Builder]
}

func NewServer() *Server {
	if err := ensureDir(filepath.Join(dataDir, "rooms")); err != nil {
		log.Fatalf("cannot create data dir: %v", err)
	}

	rooms, err := loadAllRooms()
	if err != nil {
		log.Printf("warn: error loading rooms: %v", err)
		rooms = make(map[string]*Room)
	}

	// Always ensure general exists
	if _, ok := rooms["general"]; !ok {
		r := &Room{Name: "general", CreatedBy: "system", Messages: []Message{}}
		rooms["general"] = r
		if err := persistRoom(r); err != nil {
			log.Printf("warn: could not persist general room: %v", err)
		}
	}

	allowedIPs := loadAllowedIPs()

	s := &Server{
		rooms:      rooms,
		clients:    make(map[*Client]bool),
		allowedIPs: allowedIPs,
		bufPool:    NewPool(func() *strings.Builder { return &strings.Builder{} }),
	}

	log.Printf("Loaded %d room(s) from disk", len(rooms))
	return s
}

// ─── Network helpers ──────────────────────────────────────────────────────────

func extractIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isHost(ip string) bool {
	return ip == "127.0.0.1" || ip == "::1"
}

func (s *Server) isAllowed(ip string) bool {
	if isHost(ip) {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.allowedIPs[ip]
}

// ─── Broadcast ────────────────────────────────────────────────────────────────

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

func (s *Server) broadcastFrom(from *Client, eventType string, payload any) {
	data, err := json.Marshal(BroadcastEvent{Type: eventType, Payload: payload})
	if err != nil {
		return
	}
	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()
	for c := range s.clients {
		if c == from {
			continue
		}
		select {
		case c.send <- data:
		default:
		}
	}
}

// ─── WebSocket handler ────────────────────────────────────────────────────────

func (s *Server) wsHandler(ws *websocket.Conn) {
	ip := extractIP(ws.Request())
	c := &Client{ws: ws, send: make(chan []byte, 512), ip: ip}
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
			if _, err := ws.Write(data); err != nil {
				return
			}
		}
	}()
	buf := make([]byte, 8192)
	for {
		n, err := ws.Read(buf)
		if err != nil {
			break
		}
		if n == 0 {
			continue
		}
		var ev BroadcastEvent
		if err := json.Unmarshal(buf[:n], &ev); err != nil {
			continue
		}
		switch ev.Type {
		case "signal", "call-invite", "call-answer", "call-reject", "call-end", "ice":
			s.broadcastFrom(c, ev.Type, ev.Payload)
		}
	}
	close(c.send)
}

// ─── HTTP handlers ────────────────────────────────────────────────────────────

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	rooms := make([]*Room, 0, len(s.rooms))
	for _, room := range s.rooms {
		rooms = append(rooms, room)
	}
	s.mu.RUnlock()
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), 400)
		return
	}
	req.Room = strings.TrimSpace(req.Room)
	if req.Room == "" || req.Ciphertext == "" || req.Nonce == "" {
		http.Error(w, "bad request: missing fields", 400)
		return
	}
	ip := extractIP(r)
	msg := Message{
		ID:         generateID(),
		Room:       req.Room,
		FromIP:     ip,
		Ciphertext: req.Ciphertext,
		Nonce:      req.Nonce,
		Timestamp:  time.Now().Unix(),
	}
	s.mu.Lock()
	room, ok := s.rooms[req.Room]
	if !ok {
		s.mu.Unlock()
		http.Error(w, "room not found", 404)
		return
	}
	room.Messages = append(room.Messages, msg)
	s.mu.Unlock()

	// Persist asynchronously so the HTTP response isn't blocked.
	go func() {
		if err := appendMessageToDisk(msg); err != nil {
			log.Printf("warn: persist message: %v", err)
		}
	}()

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
	if !found {
		s.mu.Unlock()
		http.Error(w, "not found", 404)
		return
	}
	snapshot := make([]Message, len(room.Messages))
	copy(snapshot, room.Messages)
	roomName := req.Room
	s.mu.Unlock()

	go func() {
		if err := rewriteMessages(roomName, snapshot); err != nil {
			log.Printf("warn: rewrite after delete: %v", err)
		}
	}()

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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request: "+err.Error(), 400)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "bad request: name is empty", 400)
		return
	}
	ip := extractIP(r)

	s.mu.Lock()
	if _, exists := s.rooms[name]; exists {
		s.mu.Unlock()
		// Return 200 with the existing room so the client can still switch to it.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]string{"name": name, "status": "exists"})
		return
	}
	room := &Room{Name: name, CreatedBy: ip, Messages: []Message{}}
	s.rooms[name] = room
	s.mu.Unlock()

	// Persist synchronously before broadcasting so the room is on disk before
	// any client tries to fetch state again.
	if err := persistRoom(room); err != nil {
		log.Printf("warn: persist room %q: %v", name, err)
	}

	s.broadcast("room", map[string]string{"name": name, "createdBy": ip})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(room)
}

// ─── Host page & middleware ───────────────────────────────────────────────────

func (s *Server) handleHostPage(w http.ResponseWriter, r *http.Request) {
	if !isHost(extractIP(r)) {
		http.Error(w, "forbidden", 403)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, hostHTML)
}

func (s *Server) hostMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !isHost(extractIP(r)) {
			http.Error(w, "forbidden", 403)
			return
		}
		next(w, r)
	}
}

func (s *Server) handleHostState(w http.ResponseWriter, r *http.Request) {
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
	ip := strings.TrimSpace(req.IP)
	s.mu.Lock()
	s.allowedIPs[ip] = true
	snap := copyMap(s.allowedIPs)
	s.mu.Unlock()
	go persistAllowedIPs(snap)
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
	ip := strings.TrimSpace(req.IP)
	s.mu.Lock()
	delete(s.allowedIPs, ip)
	snap := copyMap(s.allowedIPs)
	s.mu.Unlock()
	go persistAllowedIPs(snap)
	w.WriteHeader(200)
}

func copyMap(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
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
	if !s.isAllowed(extractIP(r)) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.Lock()
	delete(s.rooms, name)
	s.mu.Unlock()
	go func() {
		if err := deleteRoomFromDisk(name); err != nil {
			log.Printf("warn: delete room %q from disk: %v", name, err)
		}
	}()
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
	if !s.isAllowed(extractIP(r)) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.Lock()
	if room, ok := s.rooms[name]; ok {
		room.Messages = []Message{}
	}
	s.mu.Unlock()
	go func() {
		if err := rewriteMessages(name, []Message{}); err != nil {
			log.Printf("warn: clear room %q on disk: %v", name, err)
		}
	}()
	s.broadcast("clearRoom", map[string]string{"name": name})
	w.WriteHeader(200)
}

func (s *Server) handleHostClearAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	if !isHost(extractIP(r)) {
		http.Error(w, "forbidden", 403)
		return
	}
	s.mu.Lock()
	// Collect room names to delete from disk
	var toDelete []string
	for name := range s.rooms {
		if name != "general" {
			toDelete = append(toDelete, name)
		}
	}
	general := &Room{Name: "general", CreatedBy: "system", Messages: []Message{}}
	s.rooms = map[string]*Room{"general": general}
	s.mu.Unlock()

	go func() {
		for _, name := range toDelete {
			if err := deleteRoomFromDisk(name); err != nil {
				log.Printf("warn: clearAll delete %q: %v", name, err)
			}
		}
		if err := rewriteMessages("general", []Message{}); err != nil {
			log.Printf("warn: clearAll reset general: %v", err)
		}
	}()

	s.broadcast("clearAll", nil)
	w.WriteHeader(200)
}

// ─── Favicon (inline SVG as data URI) ────────────────────────────────────────
// A chat bubble with three dots, served as image/svg+xml from /favicon.svg
// and referenced via <link rel="icon"> in the HTML.

const faviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64">
  <rect width="64" height="64" rx="14" fill="#7c6af7"/>
  <path d="M10 14 Q10 10 14 10 L50 10 Q54 10 54 14 L54 40 Q54 44 50 44 L36 44 L28 54 L28 44 L14 44 Q10 44 10 40 Z" fill="white"/>
  <circle cx="22" cy="27" r="3.5" fill="#7c6af7"/>
  <circle cx="32" cy="27" r="3.5" fill="#7c6af7"/>
  <circle cx="42" cy="27" r="3.5" fill="#7c6af7"/>
</svg>`

// ─── Embedded HTML ────────────────────────────────────────────────────────────

const mainHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LackChat</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f0f17;--bg2:#16161f;--bg3:#1e1e2e;--bg4:#252535;
  --acc:#7c6af7;--acc2:#6355d4;--txt:#e2e2f0;--txt2:#9999bb;
  --brd:#2a2a3e;--grn:#4ade80;--red:#f87171;
  --msg-me:#2d2060;--msg-them:#1e1e2e;
  --rad:14px;--rad-sm:8px;
}
body.light{
  --bg:#f0f0f8;--bg2:#e4e4f4;--bg3:#ffffff;--bg4:#d8d8ee;
  --txt:#111128;--txt2:#555577;--brd:#c8c8e0;
  --msg-me:#dbd8ff;--msg-them:#ffffff;
}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:var(--bg);color:var(--txt);height:100vh;display:flex;flex-direction:column;overflow:hidden}
/* ── top bar ── */
#topbar{display:flex;align-items:center;padding:0 14px;height:52px;background:var(--bg2);border-bottom:1px solid var(--brd);gap:8px;flex-shrink:0;z-index:10}
#topbar .logo{font-weight:700;font-size:1.1rem;color:var(--acc);letter-spacing:.4px;display:flex;align-items:center;gap:7px;margin-right:auto}
#topbar .logo img{width:26px;height:26px;border-radius:6px}
.topbtn{background:var(--bg4);border:none;color:var(--txt);padding:6px 13px;border-radius:var(--rad-sm);cursor:pointer;font-size:.8rem;transition:background .15s;white-space:nowrap;display:flex;align-items:center;gap:5px}
.topbtn:hover{background:var(--acc2);color:#fff}
.topbtn.call-video{background:#162a1e;color:#6ee7a0}
.topbtn.call-audio{background:#16202e;color:#7ec8ff}
.topbtn.call-end{background:#2e1616;color:#fca5a5}
#call-status{font-size:.75rem;color:var(--txt2);display:none;padding:0 4px}
/* ── layout ── */
#app{display:flex;flex:1;overflow:hidden}
/* ── sidebar ── */
#sidebar{width:224px;flex-shrink:0;display:flex;flex-direction:column;background:var(--bg2);border-right:1px solid var(--brd)}
#sidebar-header{padding:12px 12px 6px;font-size:.72rem;font-weight:700;color:var(--txt2);text-transform:uppercase;letter-spacing:.9px;display:flex;justify-content:space-between;align-items:center}
#new-room-btn{background:var(--acc);border:none;color:#fff;width:22px;height:22px;border-radius:50%;cursor:pointer;font-size:1.1rem;line-height:1;display:flex;align-items:center;justify-content:center;flex-shrink:0}
#new-room-wrap{padding:0 8px 4px;display:none}
#new-room-input{width:100%;background:var(--bg4);color:var(--txt);border:1px solid var(--acc);border-radius:var(--rad-sm);padding:7px 10px;font-size:.85rem;outline:none}
#rooms{flex:1;overflow-y:auto;padding:4px 8px 8px}
.room-item{padding:8px 10px;border-radius:var(--rad-sm);cursor:pointer;font-size:.88rem;color:var(--txt2);display:flex;align-items:center;gap:7px;margin:1px 0;transition:background .1s,color .1s;user-select:none}
.room-item:hover{background:var(--bg4);color:var(--txt)}
.room-item.active{background:var(--acc);color:#fff}
.room-item .r-hash{opacity:.45;font-size:.82rem;flex-shrink:0}
#enc-badge{margin:8px 10px 10px;padding:5px 9px;background:#0d221a;border:1px solid #1e4d36;border-radius:var(--rad-sm);font-size:.69rem;color:#5dba8a;display:flex;align-items:center;gap:6px;flex-shrink:0}
body.light #enc-badge{background:#e0f4eb;border-color:#a0d4b8;color:#1a7a4a}
/* ── main panel ── */
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#room-header{padding:11px 16px;background:var(--bg2);border-bottom:1px solid var(--brd);display:flex;align-items:center;gap:9px;flex-shrink:0}
#room-name{font-weight:600;font-size:.98rem}
#room-enc-pill{font-size:.65rem;background:#0d221a;border:1px solid #1e4d36;color:#5dba8a;padding:2px 8px;border-radius:20px;display:flex;align-items:center;gap:3px;flex-shrink:0}
body.light #room-enc-pill{background:#e0f4eb;border-color:#a0d4b8;color:#1a7a4a}
/* ── messages ── */
#messages{flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:3px}
.msg-row{display:flex;flex-direction:column;max-width:74%;margin-bottom:1px}
.msg-row.me{align-self:flex-end;align-items:flex-end}
.msg-row.them{align-self:flex-start;align-items:flex-start}
.msg-bubble{padding:8px 13px;border-radius:18px;font-size:.88rem;line-height:1.45;word-break:break-word;cursor:pointer;transition:filter .15s}
.msg-bubble:hover{filter:brightness(1.15)}
.msg-row.me .msg-bubble{background:var(--msg-me);border-bottom-right-radius:5px}
.msg-row.them .msg-bubble{background:var(--msg-them);border-bottom-left-radius:5px;border:1px solid var(--brd)}
.msg-meta{font-size:.64rem;color:var(--txt2);margin:2px 5px}
.msg-err{color:#f87171;font-style:italic;font-size:.8rem}
.day-sep{text-align:center;font-size:.68rem;color:var(--txt2);margin:10px 0 6px;display:flex;align-items:center;gap:8px}
.day-sep::before,.day-sep::after{content:'';flex:1;height:1px;background:var(--brd)}
/* ── input bar ── */
#input-bar{padding:10px 14px;background:var(--bg2);border-top:1px solid var(--brd);display:flex;gap:9px;align-items:center;flex-shrink:0}
#msg-input{flex:1;background:var(--bg4);color:var(--txt);border:1px solid var(--brd);border-radius:22px;padding:9px 15px;font-size:.9rem;outline:none;transition:border .15s}
#msg-input:focus{border-color:var(--acc)}
#send-btn{background:var(--acc);border:none;color:#fff;width:38px;height:38px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;flex-shrink:0;transition:background .15s}
#send-btn:hover{background:var(--acc2)}
/* ── call overlay ── */
#call-overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.88);z-index:100;flex-direction:column;align-items:center;justify-content:center;gap:14px}
#call-overlay.active{display:flex}
#call-overlay h2{color:#fff;font-size:1.25rem}
#call-overlay p{color:#999;font-size:.87rem}
#videos{display:flex;gap:14px;flex-wrap:wrap;justify-content:center;align-items:flex-start}
#remote-video{border-radius:12px;background:#111;object-fit:cover;width:600px;height:338px;max-width:92vw}
#local-video{border-radius:10px;background:#111;object-fit:cover;width:190px;height:107px;max-width:38vw}
.call-btn-row{display:flex;gap:10px;flex-wrap:wrap;justify-content:center}
.cbtn{padding:9px 22px;border-radius:22px;border:none;cursor:pointer;font-size:.87rem;font-weight:600}
.cbtn.green{background:#22c55e;color:#fff}
.cbtn.red{background:#ef4444;color:#fff}
.cbtn.gray{background:#444;color:#eee}
/* ── incoming call toast ── */
#incoming-call{display:none;position:fixed;top:18px;right:18px;background:var(--bg3);border:1px solid var(--brd);border-radius:var(--rad);padding:16px 18px;z-index:200;box-shadow:0 8px 32px rgba(0,0,0,.55);min-width:230px}
#incoming-call h3{font-size:.95rem;margin-bottom:4px}
#incoming-call p{font-size:.8rem;color:var(--txt2);margin-bottom:12px}
.ic-btns{display:flex;gap:8px}
/* ── scrollbar ── */
::-webkit-scrollbar{width:4px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--brd);border-radius:2px}
</style>
</head>
<body class="dark">

<div id="topbar">
  <span class="logo">
    <img src="/favicon.svg" alt="">
    LackChat
  </span>
  <span id="call-status"></span>
  <button class="topbtn call-video" id="btn-video-call" onclick="startCall(true)">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2"/></svg>
    Video
  </button>
  <button class="topbtn call-audio" id="btn-audio-call" onclick="startCall(false)">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><path d="M22 16.92v3a2 2 0 0 1-2.18 2A19.79 19.79 0 0 1 11.39 19a19.5 19.5 0 0 1-6-6A19.79 19.79 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.127.96.361 1.903.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.907.339 1.85.573 2.81.7A2 2 0 0 1 22 16.92z"/></svg>
    Audio
  </button>
  <button class="topbtn call-end" id="btn-end-call" style="display:none" onclick="endCall()">
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
    End
  </button>
  <button class="topbtn" id="theme-btn" onclick="toggleTheme()">☀️</button>
</div>

<div id="app">
  <div id="sidebar">
    <div id="sidebar-header">
      Rooms
      <button id="new-room-btn" onclick="showRoomInput()" title="New room">+</button>
    </div>
    <div id="new-room-wrap">
      <input id="new-room-input" placeholder="Name, then Enter…"
        onkeydown="handleRoomKey(event)" onblur="hideRoomInput()">
    </div>
    <div id="rooms"></div>
    <div id="enc-badge">
      <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
      End-to-end encrypted
    </div>
  </div>

  <div id="main">
    <div id="room-header">
      <span id="room-name">general</span>
      <span id="room-enc-pill">
        <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        Encrypted
      </span>
    </div>
    <div id="messages"></div>
    <div id="input-bar">
      <input id="msg-input" type="text" placeholder="Message" autocomplete="off"
        onkeydown="if(event.key==='Enter'&&!event.shiftKey){event.preventDefault();sendMessage()}">
      <button id="send-btn" onclick="sendMessage()">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>
      </button>
    </div>
  </div>
</div>

<!-- call overlay -->
<div id="call-overlay">
  <h2 id="call-title">Call</h2>
  <p id="call-sub"></p>
  <div id="videos">
    <video id="remote-video" autoplay playsinline></video>
    <video id="local-video" autoplay playsinline muted></video>
  </div>
  <div class="call-btn-row">
    <button class="cbtn gray" id="btn-tog-mic" onclick="toggleMic()">🎙 Mute</button>
    <button class="cbtn gray" id="btn-tog-cam" onclick="toggleCam()">📹 Hide</button>
    <button class="cbtn red" onclick="endCall()">✕ Hang Up</button>
  </div>
</div>

<!-- incoming call -->
<div id="incoming-call">
  <h3>Incoming Call</h3>
  <p id="inc-type"></p>
  <div class="ic-btns">
    <button class="cbtn green" onclick="answerCall()">Answer</button>
    <button class="cbtn red" onclick="rejectCall()">Decline</button>
  </div>
</div>

<script>
// ── Crypto ────────────────────────────────────────────────────────────────────
const _te=new TextEncoder(),_td=new TextDecoder();
const _keys={};

function b64e(b){return btoa(String.fromCharCode(...new Uint8Array(b)));}
function b64d(s){const b=atob(s),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);return u;}

async function ensureKey(room){
  if(_keys[room])return _keys[room];
  const stored=localStorage.getItem('lc_k2_'+room);
  if(stored){
    try{
      const k=await crypto.subtle.importKey('raw',b64d(stored),{name:'AES-GCM'},false,['encrypt','decrypt']);
      _keys[room]=k;return k;
    }catch(_){}
  }
  const k=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
  const raw=await crypto.subtle.exportKey('raw',k);
  localStorage.setItem('lc_k2_'+room,b64e(raw));
  _keys[room]=k;return k;
}

async function encryptMsg(room,text){
  const key=await ensureKey(room);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,_te.encode(text));
  return{ciphertextBase64:b64e(ct),nonceBase64:b64e(iv)};
}

async function decryptMsg(room,ctB64,ivB64){
  const key=await ensureKey(room);
  try{return _td.decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:b64d(ivB64)},key,b64d(ctB64)));}
  catch(_){return null;}
}

// ── State ─────────────────────────────────────────────────────────────────────
let rooms={},currentRoom='general',ws,myIP='?';

// ── Theme ─────────────────────────────────────────────────────────────────────
function toggleTheme(){
  const isDark=document.body.classList.contains('dark');
  document.body.classList.toggle('dark',!isDark);
  document.body.classList.toggle('light',isDark);
  document.getElementById('theme-btn').textContent=isDark?'🌙':'☀️';
  localStorage.setItem('lc_theme',isDark?'light':'dark');
}
(function(){
  const t=localStorage.getItem('lc_theme')||'dark';
  document.body.className=t;
  document.getElementById('theme-btn').textContent=t==='dark'?'☀️':'🌙';
})();

// ── Room input ────────────────────────────────────────────────────────────────
function showRoomInput(){
  const w=document.getElementById('new-room-wrap');
  w.style.display='block';
  document.getElementById('new-room-input').focus();
}
function hideRoomInput(){
  setTimeout(()=>{
    document.getElementById('new-room-wrap').style.display='none';
    document.getElementById('new-room-input').value='';
  },180);
}
function handleRoomKey(e){
  if(e.key==='Enter'){
    const v=document.getElementById('new-room-input').value.trim();
    if(v)doCreateRoom(v);
    hideRoomInput();
  }else if(e.key==='Escape'){hideRoomInput();}
}

// ── Render rooms ──────────────────────────────────────────────────────────────
function renderRooms(){
  const el=document.getElementById('rooms');
  el.innerHTML='';
  Object.keys(rooms).sort().forEach(name=>{
    const d=document.createElement('div');
    d.className='room-item'+(name===currentRoom?' active':'');
    d.innerHTML='<span class="r-hash">#</span>'+esc(name);
    d.onclick=()=>switchRoom(name);
    el.appendChild(d);
  });
}

async function switchRoom(name){
  currentRoom=name;
  document.getElementById('room-name').textContent=name;
  await ensureKey(name);
  renderRooms();
  await renderMessages();
}

// ── Render messages ───────────────────────────────────────────────────────────
let _lastDay='';

async function renderMessages(){
  const el=document.getElementById('messages');
  el.innerHTML='';
  _lastDay='';
  const room=rooms[currentRoom];
  if(!room)return;
  for(const m of room.messages)await appendMsgEl(el,m,false);
  el.scrollTop=el.scrollHeight;
}

function dayLabel(ts){
  const d=new Date(ts*1000),t=new Date();
  if(d.toDateString()===t.toDateString())return'Today';
  const y=new Date(t);y.setDate(y.getDate()-1);
  if(d.toDateString()===y.toDateString())return'Yesterday';
  return d.toLocaleDateString(undefined,{month:'short',day:'numeric',year:'numeric'});
}

async function appendMsgEl(container,m,scroll){
  const dl=dayLabel(m.timestamp);
  if(dl!==_lastDay){
    _lastDay=dl;
    const sep=document.createElement('div');
    sep.className='day-sep';sep.textContent=dl;
    container.appendChild(sep);
  }
  const isMe=(m.fromIP===myIP);
  const row=document.createElement('div');
  row.className='msg-row '+(isMe?'me':'them');
  row.dataset.id=m.id;row.dataset.room=m.room;

  const bubble=document.createElement('div');
  bubble.className='msg-bubble';
  const pt=await decryptMsg(m.room,m.ciphertext,m.nonce);
  if(pt===null){
    const e=document.createElement('span');
    e.className='msg-err';e.textContent='🔒 Encrypted (key mismatch)';
    bubble.appendChild(e);
  }else{bubble.textContent=pt;}
  bubble.title='Click to delete';
  bubble.onclick=()=>deleteMsg(m.id,m.room);

  const meta=document.createElement('div');
  meta.className='msg-meta';
  const time=new Date(m.timestamp*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  meta.textContent=(isMe?'You':m.fromIP)+' · '+time;

  row.appendChild(bubble);row.appendChild(meta);
  container.appendChild(row);
  if(scroll){container.scrollTop=container.scrollHeight;}
}

// ── Send / delete ─────────────────────────────────────────────────────────────
async function sendMessage(){
  const input=document.getElementById('msg-input');
  const text=input.value.trim();if(!text)return;
  input.value='';
  const{ciphertextBase64,nonceBase64}=await encryptMsg(currentRoom,text);
  try{
    await fetch('/api/message',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({room:currentRoom,ciphertext:ciphertextBase64,nonce:nonceBase64})});
  }catch(err){input.value=text;}// restore on network error
}

async function deleteMsg(id,room){
  if(!confirm('Delete this message?'))return;
  fetch('/api/message/delete',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,room})});
}

// ── Create room (with retry on 409) ──────────────────────────────────────────
async function doCreateRoom(name){
  try{
    const res=await fetch('/api/room',{method:'POST',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({name})});
    if(res.ok){
      // Room created or already exists – ensure local state and switch.
      if(!rooms[name]){rooms[name]={name,createdBy:'',messages:[]};await ensureKey(name);}
      renderRooms();
      switchRoom(name);
    }
  }catch(err){console.error('createRoom',err);}
}

// ── Load initial state ────────────────────────────────────────────────────────
async function loadState(){
  try{
    const res=await fetch('/api/state');
    const data=await res.json();
    // Detect my IP from first message I can find, or leave as '?'
    for(const r of data){
      for(const m of(r.messages||[])){
        // We can't know our own IP without a dedicated endpoint; leave as '?'
        break;
      }
    }
    rooms={};
    for(const r of data){
      rooms[r.name]={name:r.name,createdBy:r.createdBy,messages:r.messages||[]};
      // Pre-generate keys silently for every room.
      ensureKey(r.name);
    }
    if(!rooms[currentRoom])currentRoom='general';
    renderRooms();
    await renderMessages();
  }catch(err){console.error('loadState',err);}
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function wsSend(type,payload){if(ws&&ws.readyState===1)ws.send(JSON.stringify({type,payload}));}

function connectWS(){
  const proto=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(proto+'://'+location.host+'/ws');
  ws.onmessage=async e=>{
    let ev;
    try{ev=JSON.parse(e.data);}catch(_){return;}
    switch(ev.type){
      case'message':{
        const m=ev.payload;
        if(!rooms[m.room]){rooms[m.room]={name:m.room,createdBy:'',messages:[]};await ensureKey(m.room);}
        rooms[m.room].messages.push(m);
        if(m.room===currentRoom){
          const el=document.getElementById('messages');
          await appendMsgEl(el,m,true);
        }
        break;
      }
      case'deleteMessage':{
        const{id,room}=ev.payload;
        if(rooms[room])rooms[room].messages=rooms[room].messages.filter(x=>x.id!==id);
        if(room===currentRoom){const d=document.querySelector('.msg-row[data-id="'+id+'"]');if(d)d.remove();}
        break;
      }
      case'room':{
        const r=ev.payload;
        if(!rooms[r.name]){rooms[r.name]={name:r.name,createdBy:r.createdBy,messages:[]};await ensureKey(r.name);}
        renderRooms();
        break;
      }
      case'deleteRoom':{
        delete rooms[ev.payload.name];
        if(currentRoom===ev.payload.name)await switchRoom('general');
        renderRooms();break;
      }
      case'clearRoom':{
        if(rooms[ev.payload.name])rooms[ev.payload.name].messages=[];
        if(currentRoom===ev.payload.name)await renderMessages();
        break;
      }
      case'clearAll':{
        rooms={general:{name:'general',createdBy:'system',messages:[]}};
        await switchRoom('general');renderRooms();break;
      }
      case'call-invite':handleIncomingCall(ev.payload);break;
      case'call-answer':handleCallAnswer(ev.payload);break;
      case'call-reject':handleCallReject();break;
      case'call-end':handleCallEnd();break;
      case'signal':handleSignal(ev.payload);break;
      case'ice':handleIce(ev.payload);break;
    }
  };
  ws.onclose=()=>setTimeout(connectWS,2000);
}

// ── WebRTC ────────────────────────────────────────────────────────────────────
let pc=null,localStream=null,isVideoCall=false,callState='idle',incomingOffer=null;
const ICE={iceServers:[{urls:'stun:stun.l.google.com:19302'},{urls:'stun:stun1.l.google.com:19302'}]};

async function startCall(withVideo){
  if(callState!=='idle')return;
  isVideoCall=withVideo;callState='outgoing';
  setCallStatus('Calling…');
  document.getElementById('btn-end-call').style.display='';
  document.getElementById('btn-video-call').style.display='none';
  document.getElementById('btn-audio-call').style.display='none';
  try{
    localStream=await navigator.mediaDevices.getUserMedia({video:withVideo,audio:true});
    document.getElementById('local-video').srcObject=localStream;
    showOverlay(withVideo?'Video Call':'Audio Call','Ringing…');
    pc=mkPC();
    localStream.getTracks().forEach(t=>pc.addTrack(t,localStream));
    const offer=await pc.createOffer();
    await pc.setLocalDescription(offer);
    wsSend('call-invite',{type:withVideo?'video':'audio',sdp:offer.sdp});
  }catch(err){showOverlay('Call Failed',err.message);setTimeout(endCall,2500);}
}

function mkPC(){
  const p=new RTCPeerConnection(ICE);
  p.onicecandidate=e=>{if(e.candidate)wsSend('ice',{candidate:e.candidate});};
  p.ontrack=e=>{
    const rv=document.getElementById('remote-video');
    if(!rv.srcObject)rv.srcObject=new MediaStream();
    rv.srcObject.addTrack(e.track);
  };
  p.oniceconnectionstatechange=()=>{
    if(p.iceConnectionState==='disconnected'||p.iceConnectionState==='failed')endCall();
  };
  return p;
}

function handleIncomingCall(payload){
  if(callState!=='idle'){wsSend('call-reject',{});return;}
  incomingOffer=payload;callState='incoming';
  document.getElementById('inc-type').textContent=(payload.type==='video'?'📹 Video':'🎙 Audio')+' call';
  document.getElementById('incoming-call').style.display='block';
}

async function answerCall(){
  document.getElementById('incoming-call').style.display='none';
  if(!incomingOffer)return;
  isVideoCall=incomingOffer.type==='video';callState='active';
  document.getElementById('btn-end-call').style.display='';
  document.getElementById('btn-video-call').style.display='none';
  document.getElementById('btn-audio-call').style.display='none';
  try{
    localStream=await navigator.mediaDevices.getUserMedia({video:isVideoCall,audio:true});
    document.getElementById('local-video').srcObject=localStream;
    showOverlay(isVideoCall?'Video Call':'Audio Call','Connecting…');
    pc=mkPC();
    localStream.getTracks().forEach(t=>pc.addTrack(t,localStream));
    await pc.setRemoteDescription({type:'offer',sdp:incomingOffer.sdp});
    const ans=await pc.createAnswer();
    await pc.setLocalDescription(ans);
    wsSend('call-answer',{sdp:ans.sdp});
    setCallStatus('In call');
  }catch(err){endCall();}
}

function rejectCall(){
  document.getElementById('incoming-call').style.display='none';
  wsSend('call-reject',{});callState='idle';incomingOffer=null;
}

async function handleCallAnswer(p){
  if(!pc||callState!=='outgoing')return;
  callState='active';setCallStatus('In call');
  document.getElementById('call-sub').textContent='Connected';
  await pc.setRemoteDescription({type:'answer',sdp:p.sdp});
}

function handleCallReject(){
  document.getElementById('call-sub').textContent='Call declined';
  setTimeout(endCall,1500);
}

function handleCallEnd(){endCall();}

async function handleSignal(p){
  if(!pc)return;
  if(p.type==='offer'){
    await pc.setRemoteDescription(p);
    const a=await pc.createAnswer();
    await pc.setLocalDescription(a);
    wsSend('signal',a);
  }else if(p.type==='answer'){await pc.setRemoteDescription(p);}
}

async function handleIce(p){
  if(pc&&p.candidate){try{await pc.addIceCandidate(p.candidate);}catch(_){}}
}

function endCall(){
  document.getElementById('call-overlay').classList.remove('active');
  document.getElementById('incoming-call').style.display='none';
  if(localStream){localStream.getTracks().forEach(t=>t.stop());localStream=null;}
  if(pc){pc.close();pc=null;}
  document.getElementById('remote-video').srcObject=null;
  document.getElementById('local-video').srcObject=null;
  if(callState==='active'||callState==='outgoing')wsSend('call-end',{});
  callState='idle';incomingOffer=null;
  setCallStatus('');
  document.getElementById('btn-end-call').style.display='none';
  document.getElementById('btn-video-call').style.display='';
  document.getElementById('btn-audio-call').style.display='';
}

function toggleMic(){
  if(!localStream)return;
  const t=localStream.getAudioTracks()[0];if(!t)return;
  t.enabled=!t.enabled;
  document.getElementById('btn-tog-mic').textContent=t.enabled?'🎙 Mute':'🎙 Unmute';
}
function toggleCam(){
  if(!localStream)return;
  const t=localStream.getVideoTracks()[0];if(!t)return;
  t.enabled=!t.enabled;
  document.getElementById('btn-tog-cam').textContent=t.enabled?'📹 Hide':'📹 Show';
}

function showOverlay(title,sub){
  document.getElementById('call-title').textContent=title;
  document.getElementById('call-sub').textContent=sub;
  document.getElementById('call-overlay').classList.add('active');
  const lv=document.getElementById('local-video');
  const rv=document.getElementById('remote-video');
  lv.style.display=isVideoCall?'block':'none';
  rv.style.display=isVideoCall?'block':'none';
}
function setCallStatus(t){
  const el=document.getElementById('call-status');
  el.textContent=t;el.style.display=t?'block':'none';
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

// ── Boot ──────────────────────────────────────────────────────────────────────
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
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f0f17;color:#e0e0f0;padding:28px;min-height:100vh}
h1{margin-bottom:22px;font-size:1.35rem;color:#7c6af7;display:flex;align-items:center;gap:10px}
h1 img{width:28px;height:28px;border-radius:7px}
h2{font-size:.78rem;font-weight:700;text-transform:uppercase;letter-spacing:.9px;color:#666699;margin:22px 0 8px}
table{width:100%;border-collapse:collapse;margin-bottom:14px}
th,td{padding:8px 12px;border:1px solid #1e1e30;text-align:left;font-size:.82rem}
th{background:#13131e;color:#8888aa;font-weight:600}
tr:hover td{background:#16162a}
button{padding:5px 13px;border-radius:6px;border:none;cursor:pointer;font-size:.78rem;margin:2px;font-weight:500;transition:background .15s}
.bd{background:#6b1d1d;color:#fca5a5}.bd:hover{background:#7f1d1d}
.bc{background:#12472a;color:#86efac}.bc:hover{background:#166534}
.ba{background:#2a2570;color:#a5b4fc}.ba:hover{background:#3730a3}
.br{background:#6a3800;color:#fcd34d}.br:hover{background:#854d0e}
.bx{background:#6b1d1d;color:#fca5a5;padding:8px 20px;margin-top:4px}
input[type=text]{background:#13131e;color:#e0e0f0;border:1px solid #2a2a3e;padding:6px 12px;border-radius:6px;font-size:.82rem;outline:none;transition:border .15s}
input[type=text]:focus{border-color:#7c6af7}
#st{min-height:18px;font-size:.76rem;color:#4ade80;margin-top:6px}
.row{display:flex;gap:8px;align-items:center;margin-top:10px}
</style>
</head>
<body>
<h1><img src="/favicon.svg" alt="">LackChat — Host Dashboard</h1>
<div id="st"></div>
<h2>Rooms</h2>
<table><thead><tr><th>Name</th><th>Created By</th><th>Messages</th><th>Actions</th></tr></thead>
<tbody id="rb"></tbody></table>
<button class="bx" onclick="clearAll()">⚠ Clear All Rooms (keep general)</button>
<h2>Allowed IPs</h2>
<table><thead><tr><th>IP Address</th><th>Actions</th></tr></thead>
<tbody id="ib"></tbody></table>
<div class="row">
  <input type="text" id="nip" placeholder="e.g. 192.168.1.42">
  <button class="ba" onclick="addIP()">+ Add IP</button>
</div>
<script>
function st(m){const e=document.getElementById('st');e.textContent=m;setTimeout(()=>e.textContent='',3000);}
function esc(x){return String(x).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
async function load(){
  const res=await fetch('/api/host/state');
  if(!res.ok){document.body.innerHTML='<p style="color:#f87171;padding:30px;font-family:sans-serif">Access denied — host only (127.0.0.1 / ::1)</p>';return;}
  const d=await res.json();
  const rb=document.getElementById('rb');rb.innerHTML='';
  for(const r of(d.rooms||[])){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(r.name)+'</td><td>'+esc(r.createdBy)+'</td><td>'+r.msgCount+'</td><td>'
      +(r.name!=='general'?'<button class="bd" onclick="delRoom(\''+esc(r.name)+'\')">Delete</button>':'')
      +'<button class="bc" onclick="clrRoom(\''+esc(r.name)+'\')">Clear</button></td>';
    rb.appendChild(tr);
  }
  const ib=document.getElementById('ib');ib.innerHTML='';
  for(const ip of(d.allowedIPs||[])){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(ip)+'</td><td><button class="br" onclick="remIP(\''+esc(ip)+'\')">Remove</button></td>';
    ib.appendChild(tr);
  }
  if(!(d.allowedIPs||[]).length){
    const tr=document.createElement('tr');
    tr.innerHTML='<td colspan="2" style="color:#555577;font-style:italic">No allowed IPs configured</td>';
    ib.appendChild(tr);
  }
}
async function post(url,body){
  const r=await fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  st(r.ok?'✓ Done':'✗ Error '+r.status+' '+r.statusText);
  load();
}
function delRoom(n){if(confirm('Delete room "'+n+'" and all its messages?'))post('/api/host/room/delete',{name:n});}
function clrRoom(n){if(confirm('Clear all messages in "'+n+'"?'))post('/api/host/room/clear',{name:n});}
function clearAll(){if(confirm('Clear ALL rooms?\n\n"general" will be recreated empty.'))post('/api/host/rooms/clearAll',{});}
function addIP(){const ip=document.getElementById('nip').value.trim();if(ip){post('/api/host/allow',{ip});document.getElementById('nip').value='';}}
function remIP(ip){if(confirm('Remove '+ip+'?'))post('/api/host/allow/remove',{ip});}
load();setInterval(load,6000);
</script>
</body>
</html>`

// ─── main ─────────────────────────────────────────────────────────────────────

func main() {
	s := NewServer()

	// Favicon – served locally from embedded SVG constant.
	http.HandleFunc("/favicon.svg", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		fmt.Fprint(w, faviconSVG)
	})

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

	log.Println("LackChat listening on :7878  →  http://localhost:7878")
	log.Println("Host dashboard          →  http://localhost:7878/host")
	log.Printf("Data directory          →  %s/", dataDir)
	if err := http.ListenAndServe(":7878", nil); err != nil {
		log.Fatal(err)
	}
}
