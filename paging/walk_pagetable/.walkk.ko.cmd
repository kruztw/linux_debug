cmd_/home/kruztw/Downloads/linux_debug/paging/walk_pagetable/walkk.ko := ld -r -m elf_x86_64  -z max-page-size=0x200000  --build-id  -T ./scripts/module-common.lds -o /home/kruztw/Downloads/linux_debug/paging/walk_pagetable/walkk.ko /home/kruztw/Downloads/linux_debug/paging/walk_pagetable/walkk.o /home/kruztw/Downloads/linux_debug/paging/walk_pagetable/walkk.mod.o;  true