#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

// using 0x80000000 introduces "negative" numbers which r a pain in the ass !
#define ADD_TO_AGE 0x40000000
#define DEBUG 0

struct
{
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void NFUupdate()
{
  struct proc *p;
  int i;
  // TODO delete uint b4, after, newAge;
  pte_t *pte, *pde, *pgtab;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if ((p->state == RUNNING || p->state == RUNNABLE || p->state == SLEEPING) && (p->pid > 2))
    { // && (strcmp(proc->name, "init") != 0 || strcmp(proc->name, "sh") != 0)) {
      // TODO deletecprintf("NFUupdate: p->name: %s, update pages...\n", p->name);

      for (i = 0; i < MAX_PSYC_PAGES; i++)
      {
        if (p->freepages[i].va != (char*)0xffffffff)
          continue;

        // TODO delete           b4 = p->freepages[i].age;
        ++p->freepages[i].age;
        // TODO delete after = p->freepages[i].age;
        // if(b4sh < after)
        // cprintf("\n\n===== OH NO! proc: %s,  page No. %d,  b4sh: %d < after: %d !!! ====  \n\n", p->name, i, b4sh, after);
        ++p->swappedpages[i].age;
        // only dealing with pages in RAM
        // might mean we have to check access bit b4 moving a page to disk so we don't miss a tick
        pde = &p->pgdir[PDX(p->freepages[i].va)];
        if (*pde & PTE_P)
        {
          pgtab = (pte_t *)P2V(PTE_ADDR(*pde));
          pte = &pgtab[PTX(p->freepages[i].va)];
        }
        else
          pte = 0;
        //*pte = walkpgdir(proc->pgdir, (void*)p->freepages[i].va, 0);
        if (pte)
          // TODO verify if need to add this to where a page is moved to disc
          if ((*pte) & PTE_A)
          {
            p->freepages[i].age = 0;
            // p->freepages[i].age |= ADD_TO_AGE;
            // (*pte) &= ~PTE_A;
            // TODO delete newAge = p->freepages[i].age;
            // if(after > newAge)
            //  cprintf("\n\n===== OH NO! proc: %s,  page No. %d,  atter: %d > new: %d \n\n", p->name, i, after, newAge);
          }
      }
    }
  }
  release(&ptable.lock);
}

void pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int cpuid()
{
  return mycpu() - cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu *
mycpu(void)
{
  int apicid, i;

  if (readeflags() & FL_IF)
    panic("mycpu called with interrupts enabled\n");

  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i)
  {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc *
myproc(void)
{
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

// PAGEBREAK: 32
//  Look in the process table for an UNUSED proc.
//  If found, change state to EMBRYO and initialize
//  state required to run in the kernel.
//  Otherwise return 0.
static struct proc *
allocproc(void)
{
  struct proc *p;
  char *sp;

  acquire(&ptable.lock);

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  p->pid = nextpid++;

  release(&ptable.lock);

  // Allocate kernel stack.
  if ((p->kstack = kalloc()) == 0)
  {
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe *)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint *)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context *)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  // initialize process's page data
  for (int i = 0; i < MAX_PSYC_PAGES; i++)
  {
    p->freepages[i].va = (char *)0xffffffff;
    p->freepages[i].next = 0;
    p->freepages[i].prev = 0; // TODO for scfifo delete
    p->freepages[i].age = 0;
    p->swappedpages[i].age = 0;
    p->swappedpages[i].swaploc = 0;
    p->swappedpages[i].va = (char *)0xffffffff;
  }
  p->pagesinmem = 0;
  p->pagesinswapfile = 0;
  p->totalPageFaultCount = 0;
  p->totalPagedOutCount = 0;
  p->head = 0;
  p->tail = 0; // TODO for scfifo delete

  return p;
}

// PAGEBREAK: 32
//  Set up first user process.
void userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();

  initproc = p;
  if ((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0; // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if (n > 0)
  {
    // TODO delete
    cprintf("growproc:allocuvm pid%d n:%d\n", curproc->pid, n);
    if ((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  else if (n < 0)
  {
    // TODO delete
    cprintf("growproc:deallocuvm\n");
    if ((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
    // TODO delete curproc->pagesinmem -= ((PGROUNDUP(sz) - PGROUNDUP(curproc->sz)) % PGSIZE);
    // TODO update proc->freepages
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int fork(void)
{
  int i, j, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // if(SELECTION==FIFO)
  //   cprintf("\n\n FIFO chosen!\n\n");

  // Allocate process.
  if ((np = allocproc()) == 0)
  {
    return -1;
  }

  // Copy process state from proc.
  // TODO delete
  cprintf("fork:copyuvm proc->pagesNo:%d\n", curproc->pagesinmem);
  if ((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0)
  {
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  // TODO delete
  cprintf("fork:copyuvm proc->pagesNo:%d\n", curproc->pagesinmem);
  np->pagesinmem = curproc->pagesinmem;
  np->pagesinswapfile = curproc->pagesinswapfile;
  // TODO delete
  // np->head = curproc->head;
  // np->tail = curproc->tail; // TODO delete for scFIFO
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for (i = 0; i < NOFILE; i++)
    if (curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  // // initialize process's page data
  // for (i = 0; i < MAX_TOTAL_PAGES; i++) {
  //   np->pages[i].inswapfile = proc->pages[i].inswapfile;
  //   np->pages[i].swaploc = proc->pages[i].swaploc;
  // }
  // np->pagesNo = 0;
  createSwapFile(np);
  char buf[PGSIZE / 2] = "";
  int offset = 0;
  int nread = 0;
  // pid=2 is sh, so the parent, init (pid=1) has no swap file to copy.
  // read the parent's swap file in chunks of size PGDIR/2, otherwise for some
  // reason, you get "panic acquire" if buf is ~4000 bytes
  if (strcmp(curproc->name, "init") != 0 && strcmp(curproc->name, "sh") != 0)
  {
    while ((nread = readFromSwapFile(curproc, buf, offset, PGSIZE / 2)) != 0)
    {
      if (writeToSwapFile(np, buf, offset, nread) == -1)
        panic("fork: error while writing the parent's swap file to the child");
      offset += nread;
    }
  }

  /* TODO no need to do this after all
  np->totalPageFaultCount = curproc->totalPageFaultCount;
  np->totalPagedOutCount = curproc->totalPagedOutCount;

  char *diff = (char *)(&curproc->freepages[0] - &np->freepages[0]);
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    np->freepages[i].va = curproc->freepages[i].va;
    np->freepages[i].next = (struct freepg *)((uint)curproc->freepages[i].next + (uint)diff);
    np->freepages[i].prev = (struct freepg *)((uint)curproc->freepages[i].prev + (uint)diff);
    np->freepages[i].age = curproc->freepages[i].age;
    np->swappedpages[i].age = curproc->swappedpages[i].age;
    np->swappedpages[i].va = curproc->swappedpages[i].va;
    np->swappedpages[i].swaploc = curproc->swappedpages[i].swaploc;
  }
*/

  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    np->freepages[i].va = curproc->freepages[i].va;
    np->freepages[i].age = curproc->freepages[i].age;
    np->swappedpages[i].age = curproc->swappedpages[i].age;
    np->swappedpages[i].va = curproc->swappedpages[i].va;
    np->swappedpages[i].swaploc = curproc->swappedpages[i].swaploc;
  }

  for (i = 0; i < MAX_PSYC_PAGES; i++){
    for (j = 0; j < MAX_PSYC_PAGES; ++j){
      if (np->freepages[j].va == curproc->freepages[i].next->va)
        np->freepages[i].next = &np->freepages[j];
      if (np->freepages[j].va == curproc->freepages[i].prev->va)
        np->freepages[i].prev = &np->freepages[j];
    }
  }

#if FIFO// TODO check
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (curproc->head->va == np->freepages[i].va){
      // TODO delete
      cprintf("\nfork: head copied!\n\n");
      np->head = &np->freepages[i];
    }
    if (curproc->tail->va == np->freepages[i].va)
      np->tail = &np->freepages[i];
  }
#endif
#if SCFIFO // TODO check and delete
  for (i = 0; i < MAX_PSYC_PAGES; i++)
  {
    if (curproc->head->va == np->freepages[i].va)
    {
      // TODO delete       cprintf("\nfork: head copied!\n\n");
      np->head = &np->freepages[i];
    }
    if (curproc->tail->va == np->freepages[i].va)
    {
      np->tail = &np->freepages[i];
      // cprintf("\nfork: head copied!\n\n");
    }
  }
#endif

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if (curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for (fd = 0; fd < NOFILE; fd++)
  {
    if (curproc->ofile[fd])
    {
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  if (removeSwapFile(curproc) != 0)
    panic("exit: error deleting swap file");

#if TRUE
  // sending proc as arg just to share func with procdump
  // TODO implement 
  // printProcMemPageInfo(proc);
  printf(1, "implement printProcMemPageInfo(proc);");
#endif
  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->parent == curproc)
    {
      p->parent = initproc;
      if (p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();

  acquire(&ptable.lock);
  for (;;)
  {
    // Scan through table looking for exited children.
    havekids = 0;
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->parent != curproc)
        continue;
      havekids = 1;
      if (p->state == ZOMBIE)
      {
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        // TODO delete 
        cprintf("freevm(p->pgdir)\n");
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if (!havekids || curproc->killed)
    {
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock); // DOC: wait-sleep
  }
}

// PAGEBREAK: 42
//  Per-CPU process scheduler.
//  Each CPU calls scheduler() after setting itself up.
//  Scheduler never returns.  It loops, doing:
//   - choose a process to run
//   - swtch to start running that process
//   - eventually that process transfers control
//       via swtch back to the scheduler.
void scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;

  for (;;)
  {
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    {
      if (p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);
  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void sched(void)
{
  int intena;
  struct proc *p = myproc();

  if (!holding(&ptable.lock))
    panic("sched ptable.lock");
  if (mycpu()->ncli != 1)
    panic("sched locks");
  if (p->state == RUNNING)
    panic("sched running");
  if (readeflags() & FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void yield(void)
{
  acquire(&ptable.lock); // DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first)
  {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  if (p == 0)
    panic("sleep");

  if (lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if (lk != &ptable.lock)
  {                        // DOC: sleeplock0
    acquire(&ptable.lock); // DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if (lk != &ptable.lock)
  { // DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

// PAGEBREAK!
//  Wake up all processes sleeping on chan.
//  The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if (p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->pid == pid)
    {
      p->killed = 1;
      // Wake process from sleep if necessary.
      if (p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

void printExtendedOutputOnControlP(struct proc *p)
{
  int k, sft, c;
  k = 20;
  sft = 13;
  c = 0;

  cprintf("\nPage tables");
  cprintf("\n\tmemory location of page directory = %d", V2P(p->pgdir));
  /**
   * @brief now iterate over the page table and see
   * if the user have the access to the page table entry
   */
  uint virtual_page_number[NPTENTRIES];
  uint physical_page_number[NPTENTRIES];

  for (int pd_index = 0; pd_index < NPDENTRIES; pd_index++)
  {
    if ((PTE_U & PTE_FLAGS(p->pgdir[pd_index])) && (PTE_A & PTE_FLAGS(p->pgdir[pd_index])))
    {
      // retriving 32 bits of the page table entry of the page directory
      pte_t *pte = (pte_t *)PTE_ADDR(p->pgdir[pd_index]);
      // retriving the upper 20 bits to access the PPN of the PTE
      cprintf("\n\tpdir PTE %d, %d:", pd_index, (((1 << k) - 1) & ((uint)pte >> (uint)(sft - 1))));
      // print the physical memory address of the page table
      cprintf("\n\t\tMemory location of page table = %x", pte);

      /**
       * @brief now iterate over the page table entries
       * to retrive the virtual page number of the page table
       * at second layer
       */
      for (int pt_index = 0; pt_index < NPTENTRIES; pt_index++)
      {
        /**
         * @brief retriving the virtual page number of the page table
         * pointer is actually 'pain in ass'
         * fuck you pointer
         */
        pte_t *pte2 = (pte_t *)((pte_t *)P2V(pte))[pt_index];
        // check accessibility[flags]
        if ((PTE_U & PTE_FLAGS(pte2)) && (PTE_A & PTE_FLAGS(pte2)))
        {
          virtual_page_number[c] = (pd_index << 10) + pt_index;
          physical_page_number[c] = (uint)((((1 << k) - 1) & ((uint)pte2 >> (uint)(sft - 1))));
          c++;
          cprintf("\n\t\tptbl PTE %d, %d, %x", pt_index, (uint)physical_page_number[c - 1], PTE_ADDR(pte2));
        }
      }
    }
  }
  cprintf("\nPage Mappings:");
  for (int i = 0; i < c; i++)
  {
    cprintf("\n%d --> %d", virtual_page_number[i], physical_page_number[i]);
  }
  cprintf("\n");
}

// PAGEBREAK: 36
//  Print a process listing to console.  For debugging.
//  Runs when user types ^P on console.
//  No lock to avoid wedging a stuck machine further.
void procdump(void)
{
  static char *states[] = {
      [UNUSED] "unused",
      [EMBRYO] "embryo",
      [SLEEPING] "sleep ",
      [RUNNABLE] "runble",
      [RUNNING] "run   ",
      [ZOMBIE] "zombie"};
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for (p = ptable.proc; p < &ptable.proc[NPROC]; p++)
  {
    if (p->state == UNUSED)
      continue;
    if (p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if (p->state == SLEEPING)
    {
      getcallerpcs((uint *)p->context->ebp + 2, pc);
      for (i = 0; i < 10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
    printExtendedOutputOnControlP(p);
  }
}
