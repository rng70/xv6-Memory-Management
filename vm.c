#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"
#define BUFSIZE PGSIZE/4
#define MAX_POSSIBLE ~0x80000000
// using 0x80000000 introduces "negative" numbers which r a pain in the ass!
#define ADD_TO_AGE 0x40000000
#define DEBUG 0

extern char data[]; // defined by kernel.ld
pde_t *kpgdir;      // for use in scheduler()

int deallocCount = 0;

// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X | STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X | STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
static pte_t *
walkpgdir(pde_t *pgdir, const void *va, int alloc)
{
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if (*pde & PTE_P)
  {
    pgtab = (pte_t *)P2V(PTE_ADDR(*pde));
  }
  else
  {
    if (!alloc || (pgtab = (pte_t *)kalloc()) == 0)
      return 0;
    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

void checkProcAccBit()
{
  int i;
  pte_t *pte1;

  // cprintf("checkAccessedBit\n");
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (myproc()->freepages[i].va != (char *)0xffffffff)
    {
      pte1 = walkpgdir(myproc()->pgdir, (void *)myproc()->freepages[i].va, 0);
      if (!*pte1)
      {
        cprintf("checkAccessedBit: pte1 is empty\n");
        continue;
      }
      cprintf("checkAccessedBit: pte1 & PTE_A == %d\n", (*pte1) & PTE_A);
    }
}


// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char *)PGROUNDDOWN((uint)va);
  last = (char *)PGROUNDDOWN(((uint)va) + size - 1);
  for (;;)
  {
    if ((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if (*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if (a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap
{
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
    {(void *)KERNBASE, 0, EXTMEM, PTE_W},            // I/O space
    {(void *)KERNLINK, V2P(KERNLINK), V2P(data), 0}, // kern text+rodata
    {(void *)data, V2P(data), PHYSTOP, PTE_W},       // kern data+memory
    {(void *)DEVSPACE, DEVSPACE, 0, PTE_W},          // more devices
};

// Set up kernel part of a page table.
pde_t *
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if ((pgdir = (pde_t *)kalloc()) == 0)
    return 0;
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void *)DEVSPACE)
    panic("PHYSTOP too high");
  for (k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if (mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                 (uint)k->phys_start, k->perm) < 0)
    {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void switchkvm(void)
{
  lcr3(V2P(kpgdir)); // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void switchuvm(struct proc *p)
{
  if (p == 0)
    panic("switchuvm: no process");
  if (p->kstack == 0)
    panic("switchuvm: no kstack");
  if (p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts) - 1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort)0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir)); // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if (sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W | PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if ((uint)addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for (i = 0; i < sz; i += PGSIZE)
  {
    if ((pte = walkpgdir(pgdir, addr + i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if (sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if (readi(ip, P2V(pa), offset + i, n) != n)
      return -1;
  }
  return 0;
}

int checkAccBit(char *va)
{
  uint accessed;
  pte_t *pte = walkpgdir(myproc()->pgdir, (void *)va, 0);
  if (!*pte)
    panic("checkAccbit: pte1 is empty");
  accessed = (*pte) & PTE_A;
  (*pte) &= ~PTE_A;
  return accessed;
}

struct freepg *fifoWrite(){
  int i;
  struct freepg *link, *l;
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (myproc()->swappedpages[i].va == (char *)0xffffffff)
      goto foundswappedpageslot;
  }
  panic("writePageToSwapFile: FIFO no slot for swapped page");
foundswappedpageslot:
  link = myproc()->head;
  if (link == 0)
    panic("fifoWrite: myproc()->head is NULL");
  if (link->next == 0)
    panic("fifoWrite: single page in phys mem");
  // find the before-last link in the used pages list
  while (link->next->next != 0)
    link = link->next;
  l = link->next;
  link->next = 0;
  if(DEBUG)
  {
    // cprintf("\naddress between 0x%x and 0x%x was accessed but was on disk.\n", addr, addr+PGSIZE);
    cprintf("FIFO chose to page out page starting at 0x%x \n\n", l->va);
  }
  myproc()->swappedpages[i].va = l->va;
  kfree((char *)PTE_ADDR(P2V_WO(*walkpgdir(myproc()->pgdir, l->va, 0))));

  int num = 0;
  if ((num = writeToSwapFile(myproc(), (char *)PTE_ADDR(l->va), i * PGSIZE, PGSIZE)) == 0)
    return 0;

  // TODO Delete
  cprintf("written %d bytes to swap file, pid:%d, va:0x%x\n", num, myproc()->pid, l->va);
  pte_t *pte1 = walkpgdir(myproc()->pgdir, (void *)l->va, 0);
  if (!*pte1)
    panic("writePageToSwapFile: pte1 is empty");
  // TODO delete
  // pte_t *pte2 = walkpgdir(myproc()->pgdir, addr, 1);
  // if (!*pte2)
  //   panic("writePageToSwapFile: pte2 is empty");
  // *pte2 = PTE_ADDR(*pte1) | PTE_U | PTE_P | PTE_W;
  kfree((char *)PTE_ADDR(P2V_WO(*walkpgdir(myproc()->pgdir, l->va, 0))));
  *pte1 = PTE_W | PTE_U | PTE_PG;

  ++myproc()->totalPagedOutCount;
  ++myproc()->pagesinswapfile;
  // cprintf("writePage:proc->totalPagedOutCount:%d\n", ++proc->totalPagedOutCount);//TODO delete
  // cprintf("writePage:proc->pagesinswapfile:%d\n", ++proc->pagesinswapfile);//TODO delete
  lcr3(V2P(myproc()->pgdir));
  return l;
}

//TODO delelte
struct freepg *scWrite(char *va)
{
  // TODO delete  cprintf("scWrite: ");
  int i;
  struct freepg *mover, *oldTail;
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (myproc()->swappedpages[i].va == (char *)0xffffffff)
      goto foundswappedpageslot;
  }
  panic("writePageToSwapFile: FIFO no slot for swapped page");

foundswappedpageslot:
  // link = myproc()->head;
  if (myproc()->head == 0)
    panic("scWrite: myproc()->head is NULL");
  if (myproc()->head->next == 0)
    panic("scWrite: single page in phys mem");

  mover = myproc()->tail;
  oldTail = myproc()->tail; // to avoid infinite loop if everyone was accessed
  do
  {
    // move mover from tail to head
    myproc()->tail = myproc()->tail->prev;
    myproc()->tail->next = 0;
    mover->prev = 0;
    mover->next = myproc()->head;
    myproc()->head->prev = mover;
    myproc()->head = mover;
    mover = myproc()->tail;
  } while (checkAccBit(myproc()->head->va) && mover != oldTail);

  if (DEBUG)
  {
    // cprintf("address between 0x%x and 0x%x was accessed but was on disk.\n\n", addr, addr+PGSIZE);
    cprintf("SCFIFO chose to page out page starting at 0x%x \n\n", myproc()->head->va);
  }

  // make the swap
  myproc()->swappedpages[i].va = myproc()->head->va;
  int num = 0;
  if ((num = writeToSwapFile(myproc(), (char *)PTE_ADDR(myproc()->head->va), i * PGSIZE, PGSIZE)) == 0)
    return 0;

  pte_t *pte1 = walkpgdir(myproc()->pgdir, (void *)myproc()->head->va, 0);
  if (!*pte1)
    panic("writePageToSwapFile: pte1 is empty");

  kfree((char *)PTE_ADDR(P2V_WO(*walkpgdir(myproc()->pgdir, myproc()->head->va, 0))));
  *pte1 = PTE_W | PTE_U | PTE_PG;
  ++myproc()->totalPagedOutCount;
  ++myproc()->pagesinswapfile;

  // TODO delete   
  cprintf("++myproc()->pagesinswapfile : %d", myproc()->pagesinswapfile);

  lcr3(V2P(myproc()->pgdir));
  myproc()->head->va = va;

  // unnecessary but will do for now
  return myproc()->head;
}

//TODO check
struct freepg *nfuWrite(char *va)
{
  int i, j;
  uint maxIndx = -1, maxAge = 0; // MAX_POSSIBLE;
  struct freepg *chosen;

  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (myproc()->swappedpages[i].va == (char *)0xffffffff)
      goto foundswappedpageslot;
  }
  panic("writePageToSwapFile: FIFO no slot for swapped page");

foundswappedpageslot:
  for (j = 0; j < MAX_PSYC_PAGES; j++)
    if (myproc()->freepages[j].va != (char *)0xffffffff)
    {
      // TODO delete      if(myproc()->freepages[j].age > 0)        cprintf("i=%d, age=%d, || ", j, myproc()->freepages[j].age);
      if (myproc()->freepages[j].age > maxAge)
      { // TODO <= not <
        maxAge = myproc()->freepages[j].age;
        maxIndx = j;
      }
    }

  if (maxIndx == -1)
    panic("nfuSwap: no free page to swap???");
  chosen = &myproc()->freepages[maxIndx];

  if (DEBUG)
  {
    // cprintf("\naddress between 0x%x and 0x%x was accessed but was on disk.\n", addr, addr+PGSIZE);
    cprintf("NFU chose to page out page starting at 0x%x \n\n", chosen->va);
  }

  // TODO delete 
  cprintf("\nchose to write va = )x%x, age = %d \n", chosen->va, chosen->age);

  pte_t *pte1 = walkpgdir(myproc()->pgdir, (void *)chosen->va, 0);
  if (!*pte1)
    panic("writePageToSwapFile: pte1 is empty");

  //  TODO verify: b4 accessing by writing to file,
  //  update accessed bit and age in case it misses a clock tick?
  //  be extra careful not to double add by locking
  acquire(&tickslock);
  // TODO delete cprintf("acquire(&tickslock)\n");
  if ((*pte1) & PTE_A)
  {
    ++chosen->age;
    *pte1 &= ~PTE_A;
    //TODO delete
    cprintf("========\n\nWOW! Matan was right!\n(never saw this actually printed)=======\n\n");
  }
  release(&tickslock);

  // make swap
  myproc()->swappedpages[i].va = chosen->va;
  int num = 0;
  if ((num = writeToSwapFile(myproc(), (char *)PTE_ADDR(chosen->va), i * PGSIZE, PGSIZE)) == 0)
    return 0;

  kfree((char *)PTE_ADDR(P2V_WO(*walkpgdir(myproc()->pgdir, chosen->va, 0))));
  *pte1 = PTE_W | PTE_U | PTE_PG;
  ++myproc()->totalPagedOutCount;
  ++myproc()->pagesinswapfile;

  // TODO delete   
  cprintf("++myproc()->pagesinswapfile : %d", myproc()->pagesinswapfile);

  lcr3(V2P(myproc()->pgdir));
  chosen->va = va;

  // unnecessary but will do for now
  return chosen;
}

// TODO check
struct freepg *writePageToSwapFile(char *va)
{
  
#if FIFO
  return fifoWrite();
#else

#if SCFIFO
  // TODO imlement & delete
  return scWrite(va);
  ;
#else

#if NFU
  // TODO imlement
  return nfuWrite(va);
#endif
#endif
#endif
  return 0;
}

//TODO check
void fifoRecord(char *va){
  int i;
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (myproc()->freepages[i].va == (char *)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", myproc()->pid, myproc()->name);
  panic("recordNewPage: no free pages");
foundrnp:
  myproc()->freepages[i].va = va;
  myproc()->freepages[i].next = myproc()->head;
  myproc()->head = &myproc()->freepages[i];
}

//TODO check & delete
void scRecord(char *va){
  int i;
  // TODO delete 
  cprintf("scRecord!\n");
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (myproc()->freepages[i].va == (char *)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", myproc()->pid, myproc()->name);
  panic("recordNewPage: no free pages");
foundrnp:
  // TODO delete 
  cprintf("found unused page!\n");
  myproc()->freepages[i].va = va;
  myproc()->freepages[i].next = myproc()->head;
  myproc()->freepages[i].prev = 0;
  if (myproc()->head != 0) // old head points back to new head
    myproc()->head->prev = &myproc()->freepages[i];
  else // head == 0 so first link inserted is also the tail
    myproc()->tail = &myproc()->freepages[i];
  myproc()->head = &myproc()->freepages[i];
}

void nfuRecord(char *va)
{
  int i;
  // TODO delete cprintf("nfuRecord!\n");
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (myproc()->freepages[i].va == (char *)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", myproc()->pid, myproc()->name);
  panic("recordNewPage: no free pages");
foundrnp:
  // TODO delete cprintf("found unused page!\n");
  myproc()->freepages[i].va = va;
}

// TODO check 
void recordNewPage(char *va)
{
  
#if FIFO
  fifoRecord(va);
#else

#if SCFIFO
  // TODO implement & delete
  scRecord(va);
#else

#if NFU
  // TODO implement
  nfuRecord(va);
#endif
#endif
#endif
  myproc()->pagesinmem++;
  // TODO delete 
  cprintf("\n++++++++++++++++++ proc->pagesinmem+++++++++++++ : %d\n", myproc()->pagesinmem);
}

//TODO check
void fifoSwap(uint addr){
  int i, j;
  char buf[BUFSIZE];
  pte_t *pte1, *pte2;

  // TODO implement paging policies
  struct freepg *link = myproc()->head;
  struct freepg *l;
  if (link == 0)
    panic("fifoSwap: myproc()->head is NULL");
  if (link->next == 0)
    panic("fifoSwap: single page in phys mem");
  // find the before-last link in the used pages list
  while (link->next->next != 0)
    link = link->next;
  l = link->next;
  link->next = 0;

  if (DEBUG)
  {
    // cprintf("\naddress between 0x%x and 0x%x was accessed but was on disk.\n", addr, addr+PGSIZE);
    cprintf("FIFO chose to page out page starting at 0x%x \n\n", l->va);
  }

  // find the address of the page table entry to copy into the swap file
  pte1 = walkpgdir(myproc()->pgdir, (void *)l->va, 0);
  if (!*pte1)
    panic("swapFile: FIFO pte1 is empty");
  // find a swap file page descriptor slot
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (myproc()->swappedpages[i].va == (char *)PTE_ADDR(addr))
      goto foundswappedslot;
  panic("swappages");
foundswappedslot:
  // update relevant fields in myproc()
  // proc->swappedpages[i].va = (char*)P2V_WO(PTE_ADDR(*pte1)); // WRONG!!!
  myproc()->swappedpages[i].va = l->va;
  // assign the physical page to addr in the relevant page table
  pte2 = walkpgdir(myproc()->pgdir, (void *)addr, 0);
  if (!*pte2)
    panic("swapFile: FIFO pte2 is empty");
  // set page table entry
  *pte2 = PTE_ADDR(*pte1) | PTE_U | PTE_W | PTE_P;
  for (j = 0; j < 4; j++)
  {
    int loc = (i * PGSIZE) + ((PGSIZE / 4) * j);
    // cprintf("i:%d j:%d loc:0x%x\n", i,j,loc);//TODO delete
    int addroffset = ((PGSIZE / 4) * j);
    // int read, written;
    memset(buf, 0, BUFSIZE);
    // copy the new page from the swap file to buf
    //  read =
    readFromSwapFile(myproc(), buf, loc, BUFSIZE);
    // cprintf("read:%d\n", read);//TODO delete
    // copy the old page from the memory to the swap file
    // written =
    writeToSwapFile(myproc(), (char *)(P2V_WO(PTE_ADDR(*pte1)) + addroffset), loc, BUFSIZE);
    // cprintf("written:%d\n", written);//TODO delete
    // copy the new page from buf to the memory
    memmove((void *)(PTE_ADDR(addr) + addroffset), (void *)buf, BUFSIZE);
  }
  // update the page table entry flags, reset the physical page address
  *pte1 = PTE_U | PTE_W | PTE_PG;
  // update l to hold the new va

  l->next = myproc()->head;
  myproc()->head = l;
  l->va = (char *)PTE_ADDR(addr);
}

//TODO delete
void scSwap(uint addr)
{
  int i, j;
  char buf[BUFSIZE];
  pte_t *pte1, *pte2;
  struct freepg *mover, *oldTail;

  if (myproc()->head == 0)
    panic("scSwap: myproc()->head is NULL");
  if (myproc()->head->next == 0)
    panic("scSwap: single page in phys mem");

  mover = myproc()->tail;
  oldTail = myproc()->tail; // to avoid infinite loop if somehow everyone was accessed
  do
  {
    // move mover from tail to head
    myproc()->tail = myproc()->tail->prev;
    myproc()->tail->next = 0;
    mover->prev = 0;
    mover->next = myproc()->head;
    myproc()->head->prev = mover;
    myproc()->head = mover;
    mover = myproc()->tail;
  } while (checkAccBit(myproc()->head->va) && mover != oldTail);

  // find the address of the page table entry to copy into the swap file
  pte1 = walkpgdir(myproc()->pgdir, (void *)myproc()->head->va, 0);
  if (!*pte1)
    panic("swapFile: SCFIFO pte1 is empty");

  // find a swap file page descriptor slot
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (myproc()->swappedpages[i].va == (char *)PTE_ADDR(addr))
      goto foundswappedpageslot;
  }
  panic("scSwap: SCFIFO no slot for swapped page");

foundswappedpageslot:

  myproc()->swappedpages[i].va = myproc()->head->va;
  // assign the physical page to addr in the relevant page table
  pte2 = walkpgdir(myproc()->pgdir, (void *)addr, 0);
  if (!*pte2)
    panic("swapFile: SCFIFO pte2 is empty");
  // set page table entry
  // TODO verify we're not setting PTE_U where we shouldn't be...
  *pte2 = PTE_ADDR(*pte1) | PTE_U | PTE_W | PTE_P; // access bit is zeroed...

  for (j = 0; j < 4; j++)
  {
    int loc = (i * PGSIZE) + ((PGSIZE / 4) * j);
    // cprintf("i:%d j:%d loc:0x%x\n", i,j,loc);//TODO delete
    int addroffset = ((PGSIZE / 4) * j);
    // int read, written;
    memset(buf, 0, BUFSIZE);
    // copy the new page from the swap file to buf
    //  read =
    readFromSwapFile(myproc(), buf, loc, BUFSIZE);
    // cprintf("read:%d\n", read);//TODO delete
    // copy the old page from the memory to the swap file
    // written =
    writeToSwapFile(myproc(), (char *)(P2V_WO(PTE_ADDR(*pte1)) + addroffset), loc, BUFSIZE);
    // cprintf("written:%d\n", written);//TODO delete
    // copy the new page from buf to the memory
    memmove((void *)(PTE_ADDR(addr) + addroffset), (void *)buf, BUFSIZE);
  }
  // update the page table entry flags, reset the physical page address
  *pte1 = PTE_U | PTE_W | PTE_PG;
  // update l to hold the new va
  // l->next = myproc()->head;
  // myproc()->head = l;
  myproc()->head->va = (char *)PTE_ADDR(addr);
}

//TODO check
void nfuSwap(uint addr)
{
  int i, j;
  uint maxIndx = -1, maxAge = 0; //TODO delete MAX_POSSIBLE;
  char buf[BUFSIZE];
  pte_t *pte1, *pte2;
  struct freepg *chosen;

  // TODO delete   cprintf("MAX_POSSIBLE = %d\n", MAX_POSSIBLE);

  for (j = 0; j < MAX_PSYC_PAGES; j++)
    if (myproc()->freepages[j].va != (char *)0xffffffff)
    {
      // TODO delete      if(myproc()->freepages[j].age > 0)      cprintf("i=%d, age=%d, || ", j, myproc()->freepages[j].age);
      if (myproc()->freepages[j].age > maxAge)
      { // TODO should be <= not < just wanted to see different indexes than 14
        maxAge = myproc()->freepages[j].age;
        maxIndx = j;
      }
    }

  if (maxIndx == -1)
    panic("nfuSwap: no free page to swap???");
  chosen = &myproc()->freepages[maxIndx];

  if (DEBUG)
  {
    // cprintf("\naddress between 0x%x and 0x%x was accessed but was on disk.\n", addr, addr+PGSIZE);
    cprintf("NFU chose to page out page starting at 0x%x \n\n", chosen->va);
  }

  // find the address of the page table entry to copy into the swap file
  pte1 = walkpgdir(myproc()->pgdir, (void *)chosen->va, 0);
  if (!*pte1)
    panic("nfuSwap: pte1 is empty");

  //  TODO verify: b4 accessing by writing to file,
  //  update accessed bit and age in case it misses a clock tick?
  //  be extra careful not to double add by locking
  acquire(&tickslock);
  // TODO delete 
  cprintf("acquire(&tickslock)\n");
  if ((*pte1) & PTE_A)
  {
    ++chosen->age;
    *pte1 &= ~PTE_A;
    // TODO delete
    cprintf("========\n\nWOW! Matan was right!\n(never saw this actually printed)=======\n\n");
  }
  release(&tickslock);

  // find a swap file page descriptor slot
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (myproc()->swappedpages[i].va == (char *)PTE_ADDR(addr))
      goto foundswappedpageslot;
  }
  panic("nfuSwap: no slot for swapped page");

foundswappedpageslot:

  myproc()->swappedpages[i].va = chosen->va;
  // assign the physical page to addr in the relevant page table
  pte2 = walkpgdir(myproc()->pgdir, (void *)addr, 0);
  if (!*pte2)
    panic("nfuSwap: pte2 is empty");
  // set page table entry
  // TODO verify we're not setting PTE_U where we shouldn't be...
  *pte2 = PTE_ADDR(*pte1) | PTE_U | PTE_W | PTE_P; // access bit is zeroed...

  for (j = 0; j < 4; j++)
  {
    int loc = (i * PGSIZE) + ((PGSIZE / 4) * j);
    // cprintf("i:%d j:%d loc:0x%x\n", i,j,loc);//TODO delete
    int addroffset = ((PGSIZE / 4) * j);
    // int read, written;
    memset(buf, 0, BUFSIZE);
    // copy the new page from the swap file to buf
    //  read =
    readFromSwapFile(myproc(), buf, loc, BUFSIZE);
    // cprintf("read:%d\n", read);//TODO delete
    // copy the old page from the memory to the swap file
    // written =
    writeToSwapFile(myproc(), (char *)(P2V_WO(PTE_ADDR(*pte1)) + addroffset), loc, BUFSIZE);
    // cprintf("written:%d\n", written);//TODO delete
    // copy the new page from buf to the memory
    memmove((void *)(PTE_ADDR(addr) + addroffset), (void *)buf, BUFSIZE);
  }
  // update the page table entry flags, reset the physical page address
  *pte1 = PTE_U | PTE_W | PTE_PG;
  // update l to hold the new va
  // l->next = myproc()->head;
  // myproc()->head = l;
  chosen->va = (char *)PTE_ADDR(addr);
}

void swapPages(uint addr)
{
  // TODO delet   
  cprintf("reached swapPages!\n");
  if (strcmp(myproc()->name, "init") == 0 || strcmp(myproc()->name, "sh") == 0)
  {
    myproc()->pagesinmem++;
    return;
  }

  scSwap(addr);
#if FIFO
  fifoSwap(addr);
#else
#if SCFIFO
// TODO implement & delete
  scSwap(addr);
#else
#if NFU
// TODO implement
  nfuSwap(addr);
#else
#endif
#endif
#endif
  lcr3(V2P(myproc()->pgdir));
  ++myproc()->totalPagedOutCount;
  cprintf("swapPages:proc->totalPagedOutCount:%d\n", ++myproc()->totalPagedOutCount);//TODO delete
  cprintf("swap pages done\n"); // TODO delete
}

// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  char *mem;
  uint a;

#ifndef NONE
  uint newpage = 1;
  struct freepg *l;
#endif

  if (newsz >= KERNBASE)
    return 0;
  if (newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  for (; a < newsz; a += PGSIZE)
  {
    // TODO delete
    cprintf("allocuvm: %d, pid %d\n", myproc()->pagesinmem, myproc()->pid);
#ifndef NONE
    // TODO delete 
    cprintf("inside #ifndef NONE: checking pages in mem: %d\n", myproc()->pagesinmem);
    //TODO check if we should add another test for init and shel here...
    if (myproc()->pagesinmem >= MAX_PSYC_PAGES)
    {
      // TODO remove l! it doesn't belong here
      if ((l = writePageToSwapFile((char *)a)) == 0)
        panic("allocuvm: error writing page to swap file");

      // TODO : these FIFO specific steps don't belong here!
      // they should move to a FIFO specific functiom!
    #if FIFO
      cprintf("\n\nFIFO???\n\n");
      l->va = (char *)a;
      l->next = myproc()->head;
      myproc()->head = l;
    #endif
      newpage = 0;
    }
#endif
    mem = kalloc();
    if (mem == 0)
    {
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
    #ifndef NONE
    if (newpage)
    {
      // TODO delete 
      cprintf("nepage = 1");
      if(myproc()->pagesinmem >= 11)
      // TODO delete
      cprintf("recorded new page, proc->name: %s, pagesinmem: %d\n", myproc()->name, myproc()->pagesinmem);
      recordNewPage((char *)a);
    }
    #endif
    memset(mem, 0, PGSIZE);
    // TODO delete 
    cprintf("mappages(pgdir, (char*)a, PGSIZE, v2p(mem), PTE_W|PTE_U);\n");
    if (mappages(pgdir, (char *)a, PGSIZE, V2P(mem), PTE_W | PTE_U) < 0)
    {
      cprintf("allocuvm out of memory (2)\n");
      deallocuvm(pgdir, newsz, oldsz);
      kfree(mem);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;
  int i;

  if (newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for (; a < oldsz; a += PGSIZE)
  {
    pte = walkpgdir(pgdir, (char *)a, 0);
    if (!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if ((*pte & PTE_P) != 0)
    {
      pa = PTE_ADDR(*pte);
      if (pa == 0)
        panic("kfree");

      if (myproc()->pgdir == pgdir)
      {
        /*
        The process itself is deallocating pages via sbrk() with a negative
        argument. Update myproc()'s data structure accordingly.
        */
#ifndef NONE
        for (i = 0; i < MAX_PSYC_PAGES; i++)
        {
          if (myproc()->freepages[i].va == (char *)a)
            goto founddeallocuvmPTEP;
        }

        panic("deallocuvm: entry not found in myproc()->freepages");
      founddeallocuvmPTEP:
        myproc()->freepages[i].va = (char *)0xffffffff;
#if FIFO
        if (myproc()->head == &myproc()->freepages[i])
          myproc()->head = myproc()->freepages[i].next;
        else
        {
          struct freepg *l = myproc()->head;
          while (l->next != &myproc()->freepages[i])
            l = l->next;
          l->next = myproc()->freepages[i].next;
        }
        myproc()->freepages[i].next = 0;

#elif SCFIFO //TODO delete
        if (proc->head == &proc->freepages[i])
        {
          proc->head = proc->freepages[i].next;
          if (proc->head != 0)
            proc->head->prev = 0;
          goto doneLooking;
        }
        if (proc->tail == &proc->freepages[i])
        {
          proc->tail = proc->freepages[i].prev;
          if (proc->tail != 0) // should allways be true but lets be extra safe...
            proc->tail->next = 0;
          goto doneLooking;
        }
        struct freepg *l = proc->head;
        while (l->next != 0 && l->next != &proc->freepages[i]){
          l = l->next;
        }
        l->next = proc->freepages[i].next;
        if (proc->freepages[i].next != 0){
          proc->freepages[i].next->prev = l;
        }

      doneLooking:
        cprintf("deallocCount = %d\n", ++deallocCount); //TODO delete
        myproc()->freepages[i].next = 0;
        myproc()->freepages[i].prev = 0;
/* //TODO delete
this messy version is commented out
        if (proc->head == &proc->freepages[i]){
          cprintf("deallocuvm: deleting head\n");
          proc->head = proc->freepages[i].next;
          if(proc->head != 0)
            proc->head->prev = 0;
          goto doneLooking;
        }
        if (proc->tail == &proc->freepages[i]){
          cprintf("deallocuvm: deleting tail\n");
          proc->tail = proc->freepages[i].prev;
          if(proc->tail != 0)// should allways be true but lets be extra safe...
            proc->tail->next = 0;
          goto doneLooking;
        }
        struct freepg *l = proc->head;
        cprintf("deallocuvm: find someone between\n");
        while (l->next != 0 && l->next != &proc->freepages[i]){
          cprintf("deallocuvm: l = l->next\n");
          l = l->next;
        }
        if(l->next == 0)
          cprintf("l->next == 0\n");
        else
          cprintf("deallocuvm: found link to delete in the middle\n");
        l->next = proc->freepages[i].next;
        if (proc->freepages[i].next != 0){
          cprintf("proc->freepages[i].next != 0\n");
          proc->freepages[i].next->prev = l;
        }
*/

/*
  cprintf("first version\n");
  if (proc->head == &proc->freepages[i])
    proc->head = proc->freepages[i].next;
  if (proc->tail == &proc->freepages[i])
    proc->tail = proc->freepages[i].prev;
  else {
    struct freepg *l = proc->head;
    while (l->next != &proc->freepages[i])
      l = l->next;
      l->next = proc->freepages[i].next;
      if (proc->freepages[i].next != 0)
        proc->freepages[i].next->prev = l;
  }
  proc->freepages[i].next = 0;
  proc->freepages[i].prev = 0;
*/
//#if NFU
#elif NFU
        myproc()->freepages[i].age = 0;
#endif
#endif

        myproc()->pagesinmem--;
      }
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
    else if (*pte & PTE_PG && myproc()->pgdir == pgdir)
    {
      /*
      The process itself is deallocating pages via sbrk() with a negative
      argument. Update myproc()'s data structure accordingly.
      */
      for (i = 0; i < MAX_PSYC_PAGES; i++)
      {
        if (myproc()->swappedpages[i].va == (char *)a)
          goto founddeallocuvmPTEPG;
      }
      panic("deallocuvm: entry not found in myproc()->swappedpages");
    founddeallocuvmPTEPG:
      myproc()->swappedpages[i].va = (char *)0xffffffff;
      myproc()->swappedpages[i].age = 0;
      myproc()->swappedpages[i].swaploc = 0;
      myproc()->pagesinswapfile--;
    }
  }
  return newsz;
}

// Free a page table and all the physical memory pages
// in the user part.
void freevm(pde_t *pgdir)
{
  uint i;

  if (pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for (i = 0; i < NPDENTRIES; i++)
  {
    if (pgdir[i] & PTE_P)
    {
      char *v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char *)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if (pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t *
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if ((d = setupkvm()) == 0)
    return 0;
  for (i = 0; i < sz; i += PGSIZE)
  {
    if ((pte = walkpgdir(pgdir, (void *)i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if (!(*pte & PTE_P) && !(*pte & PTE_PG)) // TODO need to check
      panic("copyuvm: page not present");
    if (*pte & PTE_PG) // TODO check
    {
      // cprintf("copyuvm PTR_PG\n"); // TODO delete
      pte = walkpgdir(d, (void *)i, 1);
      *pte = PTE_U | PTE_W | PTE_PG;
      continue;
    }
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if ((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char *)P2V(pa), PGSIZE);
    if (mappages(d, (void *)i, PGSIZE, V2P(mem), flags) < 0)
    {
      kfree(mem);
      goto bad;
    }
  }
  return d;

bad:
  freevm(d);
  return 0;
}

// PAGEBREAK!
//  Map user virtual address to kernel address.
char *
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if ((*pte & PTE_P) == 0)
    return 0;
  if ((*pte & PTE_U) == 0)
    return 0;
  return (char *)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char *)p;
  while (len > 0)
  {
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char *)va0);
    if (pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if (n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

// PAGEBREAK!
//  Blank page.
// PAGEBREAK!
//  Blank page.
// PAGEBREAK!
//  Blank page.
