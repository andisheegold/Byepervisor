#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <ps5/kernel.h>

#include "debug_log.h"
#include "kdlsym.h"
#include "mirror.h"
#include "paging.h"

#define MAX_MIRRORS                         0x100
#define UNUSED(x)                           (void) (x)

int sceKernelUsleep(int usecs);

struct mirrored_page {
    uint64_t user_addr;
    uint64_t kernel_va;
    uint64_t kernel_pa;
    uint64_t orig_pa;
};

struct mirrored_page g_mirrored_pages[MAX_MIRRORS];
int g_mirrored_page_index = 0;

// uint64_t remap_page(uint64_t pmap, uint64_t va, uint64_t new_pa)
// {
//     uint64_t pm_pml4;
//     uint64_t pml4_entry;
//     uint64_t pdp_table;
//     uint64_t pdp_entry;
//     uint64_t pde_table;
//     uint64_t pde_entry;
//     uint64_t pte_table;
//     uint64_t pte_entry;
//     uint64_t orig_pa;

//     SOCK_LOG("remap_page: new_pa = 0x%lx\n", new_pa);

//     // Get pmap->pm_pml4
//     kernel_copyout(pmap + KERNEL_OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
//     if (pm_pml4 == 0) {
//         return 0xFFFFFFFFFFFFFFFFull;
//     }
//     SOCK_LOG("remap_page: pm_pml4=0x%lx\n", pm_pml4);

//     // Get pml4 entry
//     kernel_copyout(pm_pml4 + (((va >> 39) & 0x1FF) * 8), &pml4_entry, sizeof(pml4_entry));
//     SOCK_LOG("remap_page: pml4e = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pml4_entry, PDE_FIELD(pml4_entry, RW), PDE_FIELD(pml4_entry, EXECUTE_DISABLE), PDE_FIELD(pml4_entry, USER), PDE_FIELD(pml4_entry, GLOBAL), PDE_FIELD(pml4_entry, PROTECTION_KEY));
//     pdp_table = get_dmap_addr(pml4_entry & PDE_ADDR_MASK);
//     SOCK_LOG("remap_page: pdp_table=0x%lx (pa=0x%lx)\n", pdp_table, pml4_entry & PDE_ADDR_MASK);

//     // Get page directory pointer entry
//     kernel_copyout(pdp_table + (((va >> 30) & 0x1FF) * 8), &pdp_entry, sizeof(pdp_entry));
//     SOCK_LOG("remap_page: pdpe = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pdp_entry, PDE_FIELD(pdp_entry, RW), PDE_FIELD(pdp_entry, EXECUTE_DISABLE), PDE_FIELD(pdp_entry, USER), PDE_FIELD(pdp_entry, GLOBAL), PDE_FIELD(pdp_entry, PROTECTION_KEY));
//     pde_table = get_dmap_addr(pdp_entry & PDE_ADDR_MASK);
//     SOCK_LOG("remap_page: pde_table=0x%lx (pa=0x%lx)\n", pde_table, pdp_entry & PDE_ADDR_MASK);

//     // Get page directory entry
//     kernel_copyout(pde_table + (((va >> 21) & 0x1FF) * 8), &pde_entry, sizeof(pde_entry));
//     SOCK_LOG("remap_page: pde = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pde_entry, PDE_FIELD(pde_entry, RW), PDE_FIELD(pde_entry, EXECUTE_DISABLE), PDE_FIELD(pde_entry, USER), PDE_FIELD(pde_entry, GLOBAL), PDE_FIELD(pde_entry, PROTECTION_KEY));
//     if (PDE_FIELD(pde_entry, PS) == 1) {
//         SOCK_LOG("[!] page mirroring does not support large pages at this time");
//         return 0xFFFFFFFFFFFFFFFFull;
//     }
//     pte_table = get_dmap_addr(pde_entry & PDE_ADDR_MASK);
//     SOCK_LOG("remap_page: pte_table=0x%lx (pa=0x%lx)\n", pte_table, pde_entry & PDE_ADDR_MASK);

//     // Get page table entry
//     kernel_copyout(pte_table + (((va >> 12) & 0x1FF) * 8), &pte_entry, sizeof(pte_entry));
//     SOCK_LOG("remap_page: pte=0x%lx\n", pte_entry);

//     // Update page addr
//     orig_pa    = pte_entry & PDE_ADDR_MASK;
//     pte_entry &= ~(PDE_ADDR_MASK);
//     pte_entry |= new_pa & PDE_ADDR_MASK;
//     SOCK_LOG("remap_page: updating pte @ 0x%lx: 0x%lx\n", pte_table + ((va >> 12) & 0x1FF), pte_entry);

//     kernel_copyin(&pte_entry, pte_table + (((va >> 12) & 0x1FF) * 8), sizeof(pte_entry));
//     return orig_pa;
// }

// uint64_t update_pte_perms(uint64_t pte_entry, int is_writable, int is_nx, int is_user)
// {
//     if (is_writable)
//         pte_entry |= (PDE_RW_MASK << PDE_RW);
//     else
//         pte_entry &= ~(PDE_RW_MASK << PDE_RW);

//     if (is_nx)
//         pte_entry |= (PDE_EXECUTE_DISABLE_MASK << PDE_EXECUTE_DISABLE);
//     else
//         pte_entry &= ~(PDE_EXECUTE_DISABLE_MASK << PDE_EXECUTE_DISABLE);

//     if (is_user)
//         pte_entry |= (PDE_USER_MASK << PDE_USER);
//     else
//         pte_entry &= ~(PDE_USER_MASK << PDE_USER);

//     return pte_entry;
// }

// uint64_t change_page_perms(uint64_t pmap, uint64_t va, int is_writable, int is_nx, int is_user)
// {
//     uint64_t pm_pml4;
//     uint64_t pml4_entry;
//     uint64_t pdp_table;
//     uint64_t pdp_entry;
//     uint64_t pde_table;
//     uint64_t pde_entry;
//     uint64_t pte_table;
//     uint64_t pte_entry;
//     uint64_t orig_pa;

//     // Get pmap->pm_pml4
//     kernel_copyout(pmap + KERNEL_OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
//     if (pm_pml4 == 0) {
//         return 0xFFFFFFFFFFFFFFFFull;
//     }
//     SOCK_LOG("change_page_perms: pm_pml4=0x%lx\n", pm_pml4);

//     // Get pml4 entry
//     kernel_copyout(pm_pml4 + (((va >> 39) & 0x1FF) * 8), &pml4_entry, sizeof(pml4_entry));
//     SOCK_LOG("change_page_perms: pml4e = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pml4_entry, PDE_FIELD(pml4_entry, RW), PDE_FIELD(pml4_entry, EXECUTE_DISABLE), PDE_FIELD(pml4_entry, USER), PDE_FIELD(pml4_entry, GLOBAL), PDE_FIELD(pml4_entry, PROTECTION_KEY));
//     pdp_table = get_dmap_addr(pml4_entry & PDE_ADDR_MASK);
//     SOCK_LOG("change_page_perms: pdp_table=0x%lx (pa=0x%lx)\n", pdp_table, pml4_entry & PDE_ADDR_MASK);

//     // Get page directory pointer entry
//     kernel_copyout(pdp_table + (((va >> 30) & 0x1FF) * 8), &pdp_entry, sizeof(pdp_entry));
//     SOCK_LOG("change_page_perms: pdpe = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pdp_entry, PDE_FIELD(pdp_entry, RW), PDE_FIELD(pdp_entry, EXECUTE_DISABLE), PDE_FIELD(pdp_entry, USER), PDE_FIELD(pdp_entry, GLOBAL), PDE_FIELD(pdp_entry, PROTECTION_KEY));
//     pde_table = get_dmap_addr(pdp_entry & PDE_ADDR_MASK);
//     SOCK_LOG("change_page_perms: pde_table=0x%lx (pa=0x%lx)\n", pde_table, pdp_entry & PDE_ADDR_MASK);

//     // Get page directory entry
//     kernel_copyout(pde_table + (((va >> 21) & 0x1FF) * 8), &pde_entry, sizeof(pde_entry));
//     SOCK_LOG("change_page_perms: pde = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pde_entry, PDE_FIELD(pde_entry, RW), PDE_FIELD(pde_entry, EXECUTE_DISABLE), PDE_FIELD(pde_entry, USER), PDE_FIELD(pde_entry, GLOBAL), PDE_FIELD(pde_entry, PROTECTION_KEY));
//     if (PDE_FIELD(pde_entry, PS) == 1) {
//         SOCK_LOG("[!] page mirroring does not support large pages at this time");
//         return 0xFFFFFFFFFFFFFFFFull;
//     }
//     pte_table = get_dmap_addr(pde_entry & PDE_ADDR_MASK);
//     SOCK_LOG("change_page_perms: pte_table=0x%lx (pa=0x%lx)\n", pte_table, pde_entry & PDE_ADDR_MASK);

//     // Get page table entry
//     kernel_copyout(pte_table + (((va >> 12) & 0x1FF) * 8), &pte_entry, sizeof(pte_entry));
//     SOCK_LOG("change_page_perms: pte = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pte_entry, PDE_FIELD(pte_entry, RW), PDE_FIELD(pte_entry, EXECUTE_DISABLE), PDE_FIELD(pte_entry, USER), PDE_FIELD(pte_entry, GLOBAL), PDE_FIELD(pte_entry, PROTECTION_KEY));

//     // Update page config
//     orig_pa    = pte_entry & PDE_ADDR_MASK;
//     pte_entry  = update_pte_perms(pte_entry, is_writable, is_nx, is_user);

//     SOCK_LOG("change_page_perms: updating pte = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pte_entry, PDE_FIELD(pte_entry, RW), PDE_FIELD(pte_entry, EXECUTE_DISABLE), PDE_FIELD(pte_entry, USER), PDE_FIELD(pte_entry, GLOBAL), PDE_FIELD(pte_entry, PROTECTION_KEY));

//     kernel_copyin(&pte_entry, pte_table + (((va >> 12) & 0x1FF) * 8), sizeof(pte_entry));
//     return orig_pa;
// }

// uint64_t downgrade_kernel_pd_to_pt(uint64_t kernel_pmap, uint64_t va, uint64_t kernel_pt_addr)
// {
//     uint64_t pm_pml4;
//     uint64_t pml4_entry;
//     uint64_t pdp_table;
//     uint64_t pdp_entry;
//     uint64_t pde_table;
//     uint64_t pde_entry;
//     uint64_t cur_pa;
//     uint64_t new_pte;
//     uint64_t kernel_pt_va;
//     int is_write;
//     int is_user;
//     int is_dirty;
//     int is_global;
//     int is_xotext;
//     int is_ndx;

//     // Get pmap->pm_pml4
//     kernel_copyout(pmap + KERNEL_OFFSET_PMAP_PM_PML4, &pm_pml4, sizeof(pm_pml4));
//     if (pm_pml4 == 0) {
//         return 0xFFFFFFFFFFFFFFFFull;
//     }
//     SOCK_LOG("downgrade_kernel_pd_to_pt: pm_pml4=0x%lx\n", pm_pml4);

//     // Get pml4 entry
//     kernel_copyout(pm_pml4 + (((va >> 39) & 0x1FF) * 8), &pml4_entry, sizeof(pml4_entry));
//     SOCK_LOG("downgrade_kernel_pd_to_pt: pml4e = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pml4_entry, PDE_FIELD(pml4_entry, RW), PDE_FIELD(pml4_entry, EXECUTE_DISABLE), PDE_FIELD(pml4_entry, USER), PDE_FIELD(pml4_entry, GLOBAL), PDE_FIELD(pml4_entry, PROTECTION_KEY));
//     pdp_table = get_dmap_addr(pml4_entry & PDE_ADDR_MASK);
//     SOCK_LOG("downgrade_kernel_pd_to_pt: pdp_table=0x%lx (pa=0x%lx)\n", pdp_table, pml4_entry & PDE_ADDR_MASK);

//     // Get page directory pointer entry
//     kernel_copyout(pdp_table + (((va >> 30) & 0x1FF) * 8), &pdp_entry, sizeof(pdp_entry));
//     SOCK_LOG("downgrade_kernel_pd_to_pt: pdpe = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pdp_entry, PDE_FIELD(pdp_entry, RW), PDE_FIELD(pdp_entry, EXECUTE_DISABLE), PDE_FIELD(pdp_entry, USER), PDE_FIELD(pdp_entry, GLOBAL), PDE_FIELD(pdp_entry, PROTECTION_KEY));
//     pde_table = get_dmap_addr(pdp_entry & PDE_ADDR_MASK);
//     SOCK_LOG("downgrade_kernel_pd_to_pt: pde_table=0x%lx (pa=0x%lx)\n", pde_table, pdp_entry & PDE_ADDR_MASK);

//     // Get page directory entry
//     kernel_copyout(pde_table + (((va >> 21) & 0x1FF) * 8), &pde_entry, sizeof(pde_entry));
//     SOCK_LOG("downgrade_kernel_pd_to_pt: pde = 0x%lx (rw: 0x%lx, nx: 0x%lx, user: 0x%lx, glob: 0x%lx, pk: 0x%lx)\n", 
//         pde_entry, PDE_FIELD(pde_entry, RW), PDE_FIELD(pde_entry, EXECUTE_DISABLE), PDE_FIELD(pde_entry, USER), PDE_FIELD(pde_entry, GLOBAL), PDE_FIELD(pde_entry, PROTECTION_KEY));
//     if (PDE_FIELD(pde_entry, PS) != 1) {
//         SOCK_LOG("downgrade_kernel_pd_to_pt: PDE already points to a page table, exiting");
//         return 0xFFFFFFFFFFFFFFFFull;
//     }

//     // Back up important attributes for PTE construction
//     cur_pa      = pde_entry & PDE_ADDR_MASK;
//     is_write    = PDE_FIELD(pde_entry, RW);
//     is_user     = PDE_FIELD(pde_entry, USER);
//     is_dirty    = PDE_FIELD(pde_entry, DIRTY);
//     is_global   = PDE_FIELD(pde_entry, GLOBAL);
//     is_xotext   = PDE_FIELD(pde_entry, PROTECTION_KEY);
//     is_nx       = PDE_FIELD(pde_entry, EXECUTE_DISABLE);

//     // Construct PTEs
//     for (int i = 0; i < 512; i++) {
//         new_pte  = 0;
//         new_pte |= (is_writable << PDE_RW);
//         new_pte |= (is_user << PDE_USER);
//         new_pte |= (is_dirty << PDE_DIRTY);
//         new_pte |= (is_global << PDE_GLOBAL);
//         new_pte |= (is_xotext << PDE_XOTEXT);
//         new_pte |= (is_nx << PDE_EXECUTE_DISABLE);
//         new_pte &= ~(PDE_ADDR_MASK);
//         new_pte |= (cur_pa & PDE_ADDR_MASK);
//         new_pte |= (1 << PDE_PRESENT);

//         kernel_copyin(&new_pte, kernel_pt_addr + (i * 0x8), sizeof(new_pte));

//         cur_pa += 0x1000;
//     }

//     // Get kernel pagetable PA
//     kernel_pt_va = 

//     pde_entry |= (PDE_RW_MASK << PDE_RW);
//     pde_entry &= ~(PDE_PS_MASK << PDE_PS);
//     pde_entry &= ~(PDE_GLOBAL_MASK << PDE_GLOBAL);
//     pde_entry &= ~(PDE_XOTEXT_MASK << PDE_XOTEXT);
//     pde_entry &= ~(PDE_ADDR_MASK);
//     pde_entry |= ()
// }

void *mirror_page(uint64_t kernel_va)
{
    void *user_mirror;
    uint64_t pmap;
    uint64_t kernel_pa;
    uint64_t orig_pa;
    uint64_t pf_read;

    UNUSED(pf_read);

    // We can only do MAX_MIRRORS mirrors, this should be plenty
    if (g_mirrored_page_index >= MAX_MIRRORS) {
        SOCK_LOG("[!] exceeded mirror limit\n");
        return NULL;
    }

    // Mask virtual address to page alignment and extract physical address
    kernel_va &= 0xFFFFFFFFFFFFF000;
    kernel_pa  = pmap_kextract(kernel_va);

    // Get process pmap
    pmap = get_proc_pmap();
    if (pmap == 0) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to failure to find proc\n", kernel_va);
        return NULL;
    }

    // Map a user page
    user_mirror = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_mirror == MAP_FAILED) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to mmap failure (%s)\n", kernel_va, strerror(errno));
        return NULL;
    }

    // Prefault page
    *(uint64_t *) (user_mirror) = 0x40404040;
    pf_read = *(uint64_t *) (user_mirror);

    sceKernelUsleep(50000);

    orig_pa = remap_page(pmap, (uint64_t) user_mirror, kernel_pa);
    if (orig_pa == 0xFFFFFFFFFFFFFFFFull) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to failure to remap page\n", kernel_va);
        return NULL;
    }

    // Store for later for lookup & restore
    g_mirrored_pages[g_mirrored_page_index].user_addr = (uint64_t) user_mirror;
    g_mirrored_pages[g_mirrored_page_index].kernel_va = kernel_va;
    g_mirrored_pages[g_mirrored_page_index].kernel_pa = kernel_pa;
    g_mirrored_pages[g_mirrored_page_index].orig_pa   = orig_pa;
    g_mirrored_page_index++;

    return user_mirror;
}

void *mirror_page_no_store(uint64_t kernel_va)
{
    void *user_mirror;
    uint64_t pmap;
    uint64_t kernel_pa;
    uint64_t orig_pa;
    uint64_t pf_read;

    UNUSED(pf_read);

    // Mask virtual address to page alignment and extract physical address
    kernel_va &= 0xFFFFFFFFFFFFF000;
    kernel_pa  = pmap_kextract(kernel_va);

    // Get process pmap
    pmap = get_proc_pmap();
    if (pmap == 0) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to failure to find proc\n", kernel_va);
        return NULL;
    }

    // Map a user page
    user_mirror = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_mirror == MAP_FAILED) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to mmap failure (%s)\n", kernel_va, strerror(errno));
        return NULL;
    }

    // Prefault page
    *(uint64_t *) (user_mirror) = 0x40404040;
    pf_read = *(uint64_t *) (user_mirror);

    sceKernelUsleep(50000);

    orig_pa = remap_page(pmap, (uint64_t) user_mirror, kernel_pa);
    if (orig_pa == 0xFFFFFFFFFFFFFFFFull) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to failure to remap page\n", kernel_va);
        return NULL;
    }

    return user_mirror;
}

// TODO: fix this to make it actually.. work
void *mirror_page_range(uint64_t kernel_va, int num_pages)
{
    void *user_mirror;
    uint64_t pmap;
    uint64_t kernel_pa;
    uint64_t orig_pa;
    uint64_t pf_read;

    UNUSED(pf_read);

    // We can only do MAX_MIRRORS mirrors, this should be plenty
    if (g_mirrored_page_index >= MAX_MIRRORS) {
        SOCK_LOG("[!] exceeded mirror limit\n");
        return NULL;
    }

    // Mask virtual address to page alignment and extract physical address
    kernel_va &= 0xFFFFFFFFFFFFF000;
    kernel_pa  = pmap_kextract(kernel_va);

    // Get process pmap
    pmap = get_proc_pmap();
    if (pmap == 0) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to failure to find proc\n", kernel_va);
        return NULL;
    }

    // Map a user region
    user_mirror = mmap(0, num_pages * 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_PREFAULT_READ, -1, 0);
    if (user_mirror == MAP_FAILED) {
        SOCK_LOG("[!] failed to mirror 0x%lx due to mmap failure (%s)\n", kernel_va, strerror(errno));
        return NULL;
    }

    sceKernelUsleep(50000);

    for (int i = 0; i < num_pages; i++) {
        orig_pa = remap_page(pmap, (uint64_t) user_mirror + (i * 0x1000), kernel_pa + (i * 0x1000));
        if (orig_pa == 0xFFFFFFFFFFFFFFFFull) {
            SOCK_LOG("[!] failed to mirror 0x%lx due to failure to remap page\n", kernel_va);
            return NULL;
        }
    }

    // TODO: store for later cleanup

    return user_mirror;
}

void *get_mirrored_addr(uint64_t kernel_va)
{
    uint64_t aligned_kernel_va;
    uint64_t aligned_kernel_pa;
    void *mirrored_addr;

    // Mask virtual address to page alignment and extract physical address
    aligned_kernel_va = kernel_va & 0xFFFFFFFFFFFFF000;
    aligned_kernel_pa = pmap_kextract(aligned_kernel_va);

    // Check if mirror already exists for this PA
    for (int i = 0; i < g_mirrored_page_index; i++) {
        if (g_mirrored_pages[i].kernel_pa == aligned_kernel_pa) {
            // Return existing mirror
            return (void *) (g_mirrored_pages[i].user_addr | (kernel_va & 0xFFF));
        }
    }

    // If one doesn't, create one
    mirrored_addr = mirror_page(aligned_kernel_va);

    return (void *) ((uint64_t) mirrored_addr | (kernel_va & 0xFFF));
}

void reset_mirrors()
{
    uint64_t pmap;
    uint64_t va;
    uint64_t pa;

    pmap = get_proc_pmap();
    if (pmap == 0) {
        SOCK_LOG("[!] failed to reset mirrors due to failure to find proc\n");
        return;
    }

    for (int i = 0; i < g_mirrored_page_index; i++) {
        va = g_mirrored_pages[i].user_addr;
        pa = g_mirrored_pages[i].orig_pa;
        remap_page(pmap, va, pa);
        bzero(&g_mirrored_pages[i], sizeof(struct mirrored_page));
    }

    g_mirrored_page_index = 0;
}