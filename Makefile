PROJECT=dns-snoop

all: clean $(PROJECT)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(PROJECT): vmlinux.h
	go generate
	go build
	@echo
	@echo "You can now run: sudo ./$(PROJECT) lo"

clean:
	rm -f *.o $(PROJECT) bpf_*.go vmlinux.h

run: $(PROJECT)
	sudo ./$(PROJECT) lo

.PHONY: all clean run
