CLANG := clang
CLANG_INCLUDE := -Iinternal/forwarder/ebpf_xdp/include

EBPF_SOURCE := internal/forwarder/ebpf_xdp/gtp5g_buf_kern.c
EBPF_BINARY := internal/forwarder/ebpf_xdp/gtp5g_buf_kern.elf

all: build_bpf

build_bpf: $(EBPF_BINARY)

clean:
	rm -f $(EBPF_BINARY)

$(EBPF_BINARY): $(EBPF_SOURCE)
	$(CLANG) $(CLANG_INCLUDE) -O2 -target bpf -c $^  -o $@

