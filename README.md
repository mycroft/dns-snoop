# eBPF based DNS snoop

POC that listens for ingress/egress interface using eBPF, and dump found DNS queries and responses.

This tool only handles DNS queries detected on port 53 (which makes it a bit useless nowadays to be honest). It also support short TCP queries/responses (as long as they fit in a single packet).

## Build & run

```sh
$ make
rm -f *.o dns-snoop bpf_*.go vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
go generate
Compiled /home/mycroft/dev/dns-snoop/bpf_bpfeb.o
Stripped /home/mycroft/dev/dns-snoop/bpf_bpfeb.o
Wrote /home/mycroft/dev/dns-snoop/bpf_bpfeb.go
Compiled /home/mycroft/dev/dns-snoop/bpf_bpfel.o
Stripped /home/mycroft/dev/dns-snoop/bpf_bpfel.o
Wrote /home/mycroft/dev/dns-snoop/bpf_bpfel.go
go build

You can now run: sudo ./dns-snoop lo

$ sudo ./dns-snoop lo
=== Request ===
;; opcode: QUERY, status: NOERROR, id: 1746
;; flags: rd; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.	IN	 HTTPS

=== Response ===
;; opcode: QUERY, status: NOERROR, id: 1746
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;google.com.	IN	 HTTPS

;; ANSWER SECTION:
google.com.	7139	IN	HTTPS	1 . alpn="h2,h3"
```