#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>

int is_end(uint64_t entry)
{
    return entry & 0x80;
}

int main(int argc, char *argv[])
{
    uint64_t cr3, pgd, pud, pmd, pte, phyaddr;
    uint64_t vma, tmp;
    int pgd_off, pud_off, pmd_off, pte_off;
    FILE *fd;

    if (argc != 2) {
         puts("usage: ./pagemap_walk <pagemap>");
         exit(-1);
    }

    fd = fopen(argv[1], "r");
    if (fd < 0) {
        puts("open failed\n");
        exit(-1);
    }

    printf("cr3 (hex) : ");
    scanf("%lx", &cr3);

    printf("vma (hex) : ");
    scanf("%lx", &vma);

    vma &= ~(0xfff);

    tmp = vma;
    tmp >>= 12;
    pte_off = (tmp & 0x1ff);

    tmp >>= 9;
    pmd_off = (tmp & 0x1ff)*8;

    tmp >>= 9;
    pud_off = (tmp & 0x1ff)*8;

    tmp >>= 9;
    pgd_off = (tmp & 0x1ff)*8;

    printf("pgd_off = %x ; pud_off = %x ; pmd_off = %x ; pte_off = %x\n", pgd_off, pud_off, pmd_off, pte_off);
    printf("dumping from cr3 PML4: 0x%lx\n", cr3);

    fseek(fd, (long int)(cr3+pgd_off), SEEK_SET);
    fread(&pgd, 8, 1, fd);
    printf("cr3 + pgd_off : 0x%lx => 0x%lx (pgd) \n", cr3 + pgd_off, pgd);

    pgd = ((pgd<<1)>>1)&(~0xfff);
    fseek(fd, (long int)(pgd+pud_off), SEEK_SET);
    fread(&pud, 8, 1, fd);
    printf("pgd + pud_off : 0x%lx => 0x%lx (pud)\n", pgd + pud_off, pud);

    if (is_end(pud)) {
        printf("page size: 1G\n");
        goto out;
    }

    pud = ((pud<<1)>>1)&(~0xfff);
    fseek(fd, (long int)(pud+pmd_off), SEEK_SET);
    fread(&pmd, 8, 1, fd);
    printf("pud + pmd_off : 0x%lx => 0x%lx (pmd)\n", pud + pmd_off, pmd);

    if (is_end(pmd)) {
        printf("page size: 2M\n");
        goto out;
    }

    pmd = ((pmd<<1)>>1)&(~0xfff);
    fseek(fd, (long int)(pmd+pte_off), SEEK_SET);
    fread(&pte, 8, 1, fd);
    printf("pmd + pte_off : 0x%lx => 0x%lx (pte)\n", pmd + pte_off, pte);
    printf("page size: 4K\n");

out:
    return 0;
}
