// TODO CopyRight thing

#include <errno.h>
#include <pthread.h>
#include <pthread_np.h>
#include <setjmp.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <atf-c.h>
#include <libprocstat.h>

// pointer to hold the last address that was faulted on
static void* faultAddress = NULL;
// environment holding the jump back in case of fault
static jmp_buf sigReturnEnv = (jmp_buf) {};

// record address of the last fault that happened.
// if multiple faults happen consecutively, only information about the last one is retained.
static void recordSegfault(int sigNumber, siginfo_t* sigInfo, void* context){
    // signal to compiler we don't need some of the inputs
    (void) (sigNumber);
    (void) (context);
    // record address
    faultAddress = sigInfo->si_addr;
    // return to predetermined point
    longjmp(sigReturnEnv, 1);
}

static const struct sigaction segFaultAction = {
    .sa_sigaction = recordSegfault,
    .sa_flags = SA_RESETHAND | SA_SIGINFO,
    .sa_mask = {0}
};

// install segfault to handle next SIGSEGV signal, returns 0 on installation
// on fault jumps back to this function and returns 1;
static void registerSegFaultHandler(void){
    // reset record
    faultAddress = NULL;
    // set up SegFaultHandler
    int error = sigaction(SIGSEGV, &segFaultAction, NULL);
    ATF_REQUIRE_EQ_MSG(0, error, "segfault handler could not be registered with error: %s", strerror(errno));
    return;
}

// set values in a range of memory to continuous values starting with startOffset and counting up
// set one value per page
static void setRange(void* basePointer, size_t size, size_t startOffset){
    size_t pagesize = getpagesize();
    ATF_REQUIRE_EQ_MSG(0, size % pagesize,
        "Range to set not multiple of pagesize (size_t)");
    ATF_REQUIRE_EQ_MSG(0, size % sizeof(size_t),
        "Range to set not multiple of element size (size_t)");
    ATF_REQUIRE_EQ_MSG(0, pagesize % sizeof(size_t),
        "Pagesize not multiple of element size (size_t)");
    for(size_t index = 0; index < size; index+= pagesize)
        ((size_t*)basePointer)[index/sizeof(size_t)] = index + startOffset;
    return;
}

// check range of memory to be zeros
static void checkRangeZero(void* basePointer, size_t size){
    size_t pagesize = getpagesize();
    ATF_REQUIRE_EQ_MSG(0, size % pagesize,
        "Range to set not multiple of pagesize (size_t)");
    ATF_REQUIRE_EQ_MSG(0, size % sizeof(size_t),
        "Range to set not multiple of element size (size_t)");
    ATF_REQUIRE_EQ_MSG(0, pagesize % sizeof(size_t),
        "Pagesize not multiple of element size (size_t)");
    for(size_t index = 0; index < size; index+=pagesize){
        size_t accessIndex = index/sizeof(size_t);
        ATF_CHECK_EQ_MSG(0, ((size_t*)basePointer)[accessIndex],
            "at index %lu", accessIndex);
    }
    return;
}

// check range of memory to be continuous values counting up from startOffset
static void checkRangeValue(void* basePointer, size_t size, size_t startOffset){
    size_t pagesize = getpagesize();
    ATF_REQUIRE_EQ_MSG(0, size % pagesize,
        "Range to set not multiple of pagesize (size_t)");
    ATF_REQUIRE_EQ_MSG(0, size % sizeof(size_t),
        "Range to set not multiple of element size (size_t)");
    ATF_REQUIRE_EQ_MSG(0, pagesize % sizeof(size_t),
        "Pagesize not multiple of element size (size_t)");
    for(size_t index = 0; index < size; index+=pagesize){
        size_t accessIndex = index/sizeof(size_t);
        ATF_CHECK_EQ_MSG(index+startOffset, ((size_t*)basePointer)[accessIndex],
            "%lu != %lu at index %lu", index+startOffset, ((size_t*)basePointer)[accessIndex], accessIndex);
    }
    return;
}

// check range of memory to produce access faults
static void checkRangeFault(void* basePointer, size_t size){
    size_t pagesize = getpagesize();
    ATF_REQUIRE_EQ_MSG(0, size % pagesize,
        "Range to set not multiple of pagesize (size_t)");
    ATF_REQUIRE_EQ_MSG(0, size % sizeof(size_t),
        "Range to set not multiple of element size (size_t)");
    ATF_REQUIRE_EQ_MSG(0, pagesize % sizeof(size_t),
        "Pagesize not multiple of element size (size_t)");
    for(size_t index = 0; index < size; index+=pagesize){
        size_t accessIndex = index/sizeof(size_t);
        int occured = setjmp(sigReturnEnv);
        if(occured == 0){
            registerSegFaultHandler();
            ((size_t*)basePointer)[accessIndex] = -1;
            // no fault occured
            ATF_CHECK_MSG(0, "No segfault for index %zu", accessIndex);
        } else {
            ATF_CHECK_EQ_MSG(&((size_t*)basePointer)[accessIndex], faultAddress,
                "access segfault after reusable on wrong address");
        }
    }
    return;
}

// check for a range of memory if the expected number of pages are present
// the number of expected pages should include all pages expected resident in any object,
// that partially overlaps with the range [basePointer, basePointer + size)
static int getRSS(void* basePointer, size_t size){
    // get procstat for own process
    struct procstat* procstat = procstat_open_sysctl();
    ATF_REQUIRE(procstat != 0);
    unsigned int count;
    struct kinfo_proc* kp =
        procstat_getprocs(procstat, KERN_PROC_PID, getpid(), &count);
    ATF_REQUIRE(kp != NULL);
    ATF_REQUIRE_EQ_MSG(1, count, "More than once process with PID of test");
    // get vmmap for own process
    struct kinfo_vmentry* vmentry = procstat_getvmmap(procstat, kp, &count);
    ATF_REQUIRE(vmentry != NULL);
    // go through entries that are in the range of [basePointer, basePointer + size]
    // and count total resident pages
    int residentPages = 0;
    uint64_t rangeStart = (uint64_t) basePointer;
    uint64_t rangeEnd = rangeStart + size;
    for(unsigned int entry = 0; entry < count; entry++){
        uint64_t startAddress = vmentry[entry].kve_start;
        uint64_t endAddress = vmentry[entry].kve_end;
        if((startAddress >= rangeStart && startAddress < rangeEnd) || 
            (endAddress > rangeStart && endAddress < rangeEnd)){
            residentPages += vmentry[entry].kve_resident;
        }
    }
    // free structures
    procstat_freevmmap(procstat, vmentry);
    procstat_freeprocs(procstat, kp);
    procstat_close(procstat);
    return residentPages;
}

// define different testing modes
#define ZERO        1
#define RELEASE     2
#define ACTIVE      4
#define SHARED      8
#define UNTOUCHED   16

// Depending on the flag either zero only or release and zero
// call release and zero on test range and check if they behave as expected
// gets two ranges, the base range and a subrange that is to be reused.
// the parts of the range that are not reused should always keep their values and be available
// the reuse range should become temporarily unavailable and be zeroed out at the end.
// expects that objects end at the end of range for purpose of counting resident pages
/* TODO:
    *   Fuzz over allocation sizes
    *   Iterate over different access addresses
    *   Fuzz access addresses
*/
static void testRange(void* basePointer, size_t size, size_t testOffset, size_t testSize, int mode){
    // get offset to end of reusable range
    size_t testEnd = testOffset + testSize;
    // values to check RSS
    int highUsage = size / getpagesize();
    int lowUsage = (size - testSize) / getpagesize();

    // write values to later check
    if((mode & UNTOUCHED) == 0)
        setRange(basePointer, size, 1);
    else {
        setRange(basePointer, testOffset, 1);
        setRange((char*)basePointer+testEnd, size-testEnd, testEnd+1);
    }
    int expectedResident = (mode & UNTOUCHED) ? lowUsage : highUsage;
    ATF_CHECK_EQ(expectedResident, getRSS(basePointer, size));

    if(mode == RELEASE){
        // call to release
        int adviseRelease = madvise((char*)basePointer+testOffset, testSize, MADV_RELEASE);
        ATF_REQUIRE_EQ_MSG(0, adviseRelease, "madvise reusable failed with %s", strerror(errno));
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer, size));
        // access, expected show old value or segfault
        checkRangeValue(basePointer, testOffset, 1);
        checkRangeFault((char*)basePointer+testOffset, testSize);
        checkRangeValue((char*)basePointer+testEnd, size-testEnd, testEnd+1);
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer, size));
    }

    int adviseReuse = madvise((char*)basePointer+testOffset, testSize, MADV_ZERO);
    ATF_REQUIRE_EQ_MSG(0, adviseReuse, "madvise reuse failed with %s", strerror(errno));
    ATF_CHECK_EQ(lowUsage, getRSS(basePointer, size));

    // access again and check that it is zero in the reuse region and still the same outside
    checkRangeValue((char*)basePointer, testOffset, 1);
    checkRangeZero((char*)basePointer+testOffset, testSize);
    checkRangeValue((char*)basePointer+testEnd, size-testEnd, testEnd+1);
    ATF_CHECK_EQ(highUsage, getRSS(basePointer, size));
}

static void testRangeShared(
    void* basePointer1, void* basePointer2, size_t size, size_t testOffset, size_t testSize, int mode){
    // get offset to end of release range
    const size_t testEnd = (testOffset + testSize);
    // values to check RSS
    int highUsage = size / getpagesize();
    int lowUsage = (size - testSize) / getpagesize();

    // write values to later check
    if((mode & UNTOUCHED) == 0)
        setRange(basePointer1, size, 1);
    else {
        setRange(basePointer1, testOffset, 1);
        setRange((char*)basePointer1+testEnd, size-testEnd, testEnd+1);
    }
    int expectedResident = (mode & UNTOUCHED) ? lowUsage : highUsage;
    ATF_CHECK_EQ(expectedResident, getRSS(basePointer1, size));
    ATF_CHECK_EQ(expectedResident, getRSS(basePointer2, size));

    if(mode == RELEASE){
        // call to release
        int adviseRelease = madvise((char*)basePointer1+testOffset, testSize, MADV_RELEASE);
        ATF_REQUIRE_EQ_MSG(0, adviseRelease, "madvise release failed with %s", strerror(errno));
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer1, size));
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer2, size));
        // access, expected show old value or segfault
        checkRangeValue(basePointer1, testOffset, 1);
        checkRangeValue(basePointer2, testOffset, 1);
        checkRangeFault((char*)basePointer1+testOffset, testSize);
        checkRangeFault((char*)basePointer2+testOffset, testSize);
        checkRangeValue((char*)basePointer1+testEnd, size-testEnd, testEnd+1);
        checkRangeValue((char*)basePointer2+testEnd, size-testEnd, testEnd+1);
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer1, size));
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer2, size));
    }

    int adviseZero = madvise((char*)basePointer1+testOffset, testSize, MADV_ZERO);
    ATF_REQUIRE_EQ_MSG(0, adviseZero, "madvise zero failed with %s", strerror(errno));
    // check if resident set size changed as expected
    ATF_CHECK_EQ(lowUsage, getRSS(basePointer1, size));
    ATF_CHECK_EQ(lowUsage, getRSS(basePointer2, size));
    // access again and check that it is zero in the reuse region and still the same outside
    checkRangeValue(basePointer1, testOffset, 1);
    checkRangeValue(basePointer2, testOffset, 1);
    checkRangeZero((char*)basePointer1+testOffset, testSize);
    checkRangeZero((char*)basePointer2+testOffset, testSize);
    checkRangeValue((char*)basePointer1+testEnd, size-testEnd, testEnd+1);
    checkRangeValue((char*)basePointer2+testEnd, size-testEnd, testEnd+1);
    ATF_CHECK_EQ(highUsage, getRSS(basePointer1, size));
    ATF_CHECK_EQ(highUsage, getRSS(basePointer2, size));
}

typedef struct {
    volatile char* const ownSignal;
    pthread_spinlock_t* ownLock;
    volatile char* const partnerSignal;
    pthread_spinlock_t* partnerLock;
} threadSignals_t;

static void signalAndSpin(threadSignals_t threadSignals){
    pthread_spin_lock(threadSignals.partnerLock);
    (*threadSignals.partnerSignal)++;
    pthread_spin_unlock(threadSignals.partnerLock);
    while(*threadSignals.ownSignal <= 0)(void)0;
    pthread_spin_lock(threadSignals.ownLock);
    (*threadSignals.ownSignal)--;
    pthread_spin_unlock(threadSignals.ownLock);
}

typedef struct {
    void* basePointer;
    size_t testSize;
    threadSignals_t signals;
    size_t seed;
    int mode;
}threadArgs_t;

static void testRangeThread(void* basePointer, size_t testSize, threadSignals_t signals, size_t seed, int mode){
    // initial synchronization
    signalAndSpin(signals);
    // values to check RSS
    int highUsage = testSize / getpagesize();
    int lowUsage = 0;
    if(mode & ACTIVE)
        setRange(basePointer, testSize, seed);
    // check if range was set properly
    signalAndSpin(signals);
    checkRangeValue(basePointer, testSize, seed);
    ATF_CHECK_EQ(highUsage, getRSS(basePointer, testSize));
    signalAndSpin(signals);
    if(mode & RELEASE){
        // do sequential checks for in-/active, since they can interfere on the fault handlers
        if(mode & ACTIVE){
            ATF_REQUIRE_EQ_MSG(0, madvise(basePointer, testSize, MADV_RELEASE),
                "madvise release failed with %s", strerror(errno));
            signalAndSpin(signals);
            checkRangeFault(basePointer, testSize);
            ATF_CHECK_EQ(lowUsage, getRSS(basePointer, testSize));
            signalAndSpin(signals);
            signalAndSpin(signals);
        } else {
            signalAndSpin(signals);
            signalAndSpin(signals);
            checkRangeFault(basePointer, testSize);
            ATF_CHECK_EQ(lowUsage, getRSS(basePointer, testSize));
            signalAndSpin(signals);
        }
    }
    if(mode & ACTIVE){
        ATF_REQUIRE_EQ_MSG(0, madvise(basePointer, testSize, MADV_ZERO),
            "madvise zero failed with %s", strerror(errno));
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer, testSize));
    }
    signalAndSpin(signals);
    checkRangeZero(basePointer, testSize);
    ATF_CHECK_EQ(highUsage, getRSS(basePointer, testSize));
}

static void* testThreadStarter(void* args){
    threadArgs_t* threadArgs = (threadArgs_t*) args;
    testRangeThread(
        threadArgs->basePointer,
        threadArgs->testSize,
        threadArgs->signals,
        threadArgs->seed,
        threadArgs->mode
    );
    return NULL;
}

static void testThreadSetCPUs(pthread_t thread){
    // get all available cores
    cpuset_t processMask;
    cpuset_getaffinity(CPU_LEVEL_CPUSET, CPU_WHICH_PID, -1, sizeof(processMask), &processMask);
    int cpuNumber = CPU_COUNT(&processMask);
    ATF_REQUIRE_MSG(cpuNumber >= 2, "Not enough CPUs for useful thread testing");
    // make new sets, first available cpu to main, second to thread
    cpuset_t mainSet;
    cpuset_t threadSet;
    int mainCPU = CPU_FFS(&processMask)-1;
    CPU_SETOF(mainCPU, &mainSet);
    CPU_CLR(mainCPU, &processMask);
    int threadCPU = CPU_FFS(&processMask)-1;
    CPU_SETOF(threadCPU, &threadSet);
    // set new sets
    int errorCheck = pthread_setaffinity_np(thread, sizeof(threadSet), &threadSet);
    ATF_REQUIRE_EQ_MSG(0, errorCheck, "Thread affinity set failed with %s", strerror(errno));
    errorCheck = cpuset_setaffinity(CPU_LEVEL_WHICH, CPU_WHICH_TID, -1, sizeof(mainSet), &mainSet);
    ATF_REQUIRE_EQ_MSG(0, errorCheck, "Main thread affinity set failed with %s", strerror(errno));
}

static void testThreaded(void* basePointer, size_t testSize, int mainFlags, int threadFlags){
    char* signalArray = calloc(2, sizeof(char));
    pthread_spinlock_t* lockArray = calloc(2, sizeof(pthread_spinlock_t));
    ATF_REQUIRE_MSG(lockArray != NULL, "calloc failed");
    ATF_REQUIRE_EQ(0, pthread_spin_init(&lockArray[0], PTHREAD_PROCESS_PRIVATE));
    ATF_REQUIRE_EQ(0, pthread_spin_init(&lockArray[1], PTHREAD_PROCESS_PRIVATE));

    threadSignals_t mainToThread = {
        .ownSignal = &signalArray[0],
        .ownLock = &lockArray[0],
        .partnerSignal = &signalArray[1],
        .partnerLock = &lockArray[1]
    };

    threadSignals_t threadToMain = {
        .ownSignal = &signalArray[1],
        .ownLock = &lockArray[1],
        .partnerSignal = &signalArray[0],
        .partnerLock = &lockArray[0]
    };

    // prepare the threads
    threadArgs_t threadArgs = {
        .basePointer = basePointer,
        .testSize = testSize,
        .signals = threadToMain,
        .seed = 1,
        .mode = threadFlags,
    };

    pthread_t testThread;
    int errorCheck = pthread_create(&testThread, NULL, testThreadStarter, &threadArgs);
    ATF_REQUIRE_EQ_MSG(0, errorCheck, "Thread 1 create failed with %s", strerror(errno));

    // set the cores for the threads
    testThreadSetCPUs(testThread);
    // run tests
    testRangeThread(basePointer, testSize, mainToThread, 1, mainFlags);
    // wait for joins
    errorCheck = pthread_join(testThread, NULL);
    ATF_REQUIRE_EQ_MSG(0, errorCheck, "Join failed with %s", strerror(errno));
}

static void sigChldHandler(int sigNumber, siginfo_t* sigInfo, void* context){
    (void) sigNumber;
    (void) sigInfo;
    (void) context;
    ATF_REQUIRE_MSG(0, "SIGCHLD handler was called");
}

static const struct sigaction sigChildAction = {
    .sa_sigaction = sigChldHandler,
    .sa_flags = SA_SIGINFO,
    .sa_mask = {0}
};

// need to register handler for signal with default action discard for it to be blocked
static void setUpProcessSignalHandling(void){
    int error = sigaction(SIGCHLD, &sigChildAction, NULL);
    ATF_REQUIRE_EQ_MSG(0, error, "sigchld handler could not be registered with error: %s", strerror(errno));
    sigset_t sigset;
    ATF_REQUIRE_EQ_MSG(0, sigemptyset(&sigset), "Failed to set empty signal set");
	ATF_REQUIRE_EQ_MSG(0, sigaddset(&sigset, SIGUSR1), "Failed to add SIGUSR1 to signalset");
    ATF_REQUIRE_EQ_MSG(0, sigaddset(&sigset, SIGCHLD), "Failed to add SIGCHLD to signalset");
	ATF_REQUIRE_EQ_MSG(0, sigprocmask(SIG_BLOCK, &sigset, NULL), "Failed to change procmask");
    return;
}

static int signalAndWait(pid_t partnerId){
    int cleared;
    sigset_t sigset;
    // set signal set to include user signal 1
    ATF_REQUIRE_EQ_MSG(0, sigemptyset(&sigset), "Failed to set empty signal set");
	ATF_REQUIRE_EQ_MSG(0, sigaddset(&sigset, SIGUSR1), "Failed to add SIGUSR1 to signalset");
    // Add in case child quits and so process is not blocked
    ATF_REQUIRE_EQ_MSG(0, sigaddset(&sigset, SIGCHLD), "Failed to add SIGCHLD to signalset");
    // send signal to partner
    ATF_REQUIRE_EQ(0, kill(partnerId, SIGUSR1));
    // wait for signal from partner or go on if there was a pending one
    ATF_REQUIRE_EQ(0, sigwait(&sigset,&cleared));
    // check the correct signal was received
    ATF_CHECK_EQ(cleared, SIGUSR1);
    if(cleared == SIGUSR1)
        return 0;
    else 
        return -1;
}

static void testRangeProcess(void* basePointer, size_t testSize, pid_t partnerId, size_t seed, int mode){
    // values to check RSS
    int highUsage = testSize / getpagesize();
    int lowUsage = 0;

    if(!(mode & SHARED) || (mode & ACTIVE))
        setRange(basePointer, testSize, seed);
    // check if range was set properly
    if(signalAndWait(partnerId) != 0) return;
    checkRangeValue(basePointer, testSize, seed);
    ATF_CHECK_EQ(highUsage, getRSS(basePointer, testSize));
    if(signalAndWait(partnerId) != 0) return;
    if(mode & RELEASE){
        if(mode & ACTIVE)
            ATF_REQUIRE_EQ_MSG(0, madvise(basePointer, testSize, MADV_RELEASE),
                "madvise release failed with %s", strerror(errno));
        if(signalAndWait(partnerId) != 0) return;
        if(mode & SHARED || mode & ACTIVE){
            checkRangeFault(basePointer, testSize);
            ATF_CHECK_EQ(lowUsage, getRSS(basePointer, testSize));
        } else {
            checkRangeValue(basePointer, testSize, seed);
            ATF_CHECK_EQ(highUsage, getRSS(basePointer, testSize));
        }
        if(signalAndWait(partnerId) != 0) return;
    }
    if(mode & ACTIVE){
        ATF_REQUIRE_EQ_MSG(0, madvise(basePointer, testSize, MADV_ZERO),
            "madvise zero failed with %s", strerror(errno));
        ATF_CHECK_EQ(lowUsage, getRSS(basePointer, testSize));
    }
    if(signalAndWait(partnerId) != 0) return;
    if(mode & SHARED || mode & ACTIVE){
        checkRangeZero(basePointer, testSize);
    } else {
        checkRangeValue(basePointer, testSize, seed);
        ATF_CHECK_EQ(highUsage, getRSS(basePointer, testSize));
    }
}

static void testForked(void* basePointer, size_t testSize, int parentMode, int childMode){
    // fork 
    // pid_t partnerId = atf_utils_fork();
    pid_t partnerId = fork();
    int parentSeed = 1;
    int childSeed = 2;
    // if they are in shared give same seed, otherwise use different ones
    if((parentMode | childMode) & SHARED){
        childSeed = parentSeed;
    }
    if(partnerId == 0){
        // child
        partnerId = getppid();
        testRangeProcess(basePointer, testSize, partnerId, childSeed, childMode);
    } else {
        // parent
        testRangeProcess(basePointer, testSize, partnerId, parentSeed, parentMode);
        // atf_utils_wait(partnerId, 0, "save:stdout.txt", "save:stderr.txt");
        int status;
        pid_t exitedPid = wait(&status);
        ATF_CHECK_EQ_MSG(partnerId, exitedPid,
            "Wait returned different child than expected");
    }
}

ATF_TC_WITHOUT_HEAD(madvise__zero_scaling);
ATF_TC_BODY(madvise__zero_scaling, tc){

    const size_t pageSize = getpagesize();
    const size_t maxBaseSize = 1024 * pageSize; // checks scaling up to 4MiB 

    for(size_t mapSize = pageSize;  mapSize <=  maxBaseSize; mapSize = mapSize << 1){
        // mmap space
        void* mappedSpace = mmap(NULL, mapSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
        ATF_REQUIRE_MSG(mappedSpace != MAP_FAILED, "mmap failed with %s", strerror(errno));

        testRange(mappedSpace, mapSize, 0, mapSize, ZERO);

        int unmapResult = munmap(mappedSpace, mapSize);
        ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
    }
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_scaling);
ATF_TC_BODY(madvise__reuse_scaling, tc){

    const size_t pageSize = getpagesize();
    const size_t maxBaseSize = 1024 * pageSize; // checks scaling up to 4MiB 

    for(size_t mapSize = pageSize;  mapSize <=  maxBaseSize; mapSize = mapSize << 1){
        // mmap space
        void* mappedSpace = mmap(NULL, mapSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
        ATF_REQUIRE_MSG(mappedSpace != MAP_FAILED, "mmap failed with %s", strerror(errno));

        testRange(mappedSpace, mapSize, 0, mapSize, RELEASE);

        int unmapResult = munmap(mappedSpace, mapSize);
        ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
    }
}

ATF_TC_WITHOUT_HEAD(madvise__zero_exact_object);
ATF_TC_BODY(madvise__zero_exact_object, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages, split it into 2,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, ZERO);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_exact_object_untouched);
ATF_TC_BODY(madvise__zero_exact_object_untouched, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages, split it into 2,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, UNTOUCHED);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_exact_object);
ATF_TC_BODY(madvise__reuse_exact_object, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages, split it into 2,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, RELEASE);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_exact_object_untouched);
ATF_TC_BODY(madvise__reuse_exact_object_untouched, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages, split it into 2,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, RELEASE | UNTOUCHED);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_inside_object);
ATF_TC_BODY(madvise__zero_inside_object, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));

    // split it into 2,4,2 with the reuse pages in the middle
    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, ZERO);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_inside_object_untouched);
ATF_TC_BODY(madvise__zero_inside_object_untouched, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));

    // split it into 2,4,2 with the reuse pages in the middle
    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, UNTOUCHED);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_inside_object);
ATF_TC_BODY(madvise__reuse_inside_object, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));

    // split it into 2,4,2 with the reuse pages in the middle
    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, RELEASE);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_inside_object_untouched);
ATF_TC_BODY(madvise__reuse_inside_object_untouched, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 8*pageSize;

    // mmap space, get 8 pages
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));

    // split it into 2,4,2 with the reuse pages in the middle
    testRange(testMapping, testSize, 2*pageSize, 4*pageSize, RELEASE | UNTOUCHED);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_accross_object);
ATF_TC_BODY(madvise__zero_accross_object, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 12*pageSize;

    // mmap space, get 12 pages, split it into 2,4,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping1 = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping1 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));
    void* reuseMapping2 = mmap((char*)testMapping + 6*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping2 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    // reuse the two objects in the middle
    testRange(testMapping, testSize, 2*pageSize, 8*pageSize, ZERO);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_accross_object_untouched);
ATF_TC_BODY(madvise__zero_accross_object_untouched, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 12*pageSize;

    // mmap space, get 12 pages, split it into 2,4,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping1 = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping1 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));
    void* reuseMapping2 = mmap((char*)testMapping + 6*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping2 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    // reuse the two objects in the middle
    testRange(testMapping, testSize, 2*pageSize, 8*pageSize, UNTOUCHED);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_accross_object);
ATF_TC_BODY(madvise__reuse_accross_object, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 12*pageSize;

    // mmap space, get 12 pages, split it into 2,4,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping1 = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping1 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));
    void* reuseMapping2 = mmap((char*)testMapping + 6*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping2 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    // reuse the two objects in the middle
    testRange(testMapping, testSize, 2*pageSize, 8*pageSize, RELEASE);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_accross_object_untouched);
ATF_TC_BODY(madvise__reuse_accross_object_untouched, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 12*pageSize;

    // mmap space, get 12 pages, split it into 2,4,4,2 with the reuse pages in the middle
    void* testMapping = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(testMapping != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* reuseMapping1 = mmap((char*)testMapping + 2*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping1 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));
    void* reuseMapping2 = mmap((char*)testMapping + 6*pageSize, 4*pageSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_FIXED, -1, 0);
    ATF_REQUIRE_MSG(reuseMapping2 != MAP_FAILED, "mmap failed to remap region with %s", strerror(errno));

    // reuse the two objects in the middle
    testRange(testMapping, testSize, 2*pageSize, 8*pageSize, RELEASE | UNTOUCHED);

    int unmapResult = munmap(testMapping, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_memfd);
ATF_TC_BODY(madvise__zero_memfd, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 4*pageSize;

    // create file that is backed by anonymous memory to map multiple instances of the same anon memory
    int fileDescriptor = memfd_create("anonFile", 0);
    ATF_REQUIRE_MSG(fileDescriptor != -1, "memfd_create failed with %s", strerror(errno));
    // set the size of the file
    int truncateResult = ftruncate(fileDescriptor, testSize);
    ATF_REQUIRE_EQ_MSG(0, truncateResult, "ftruncate failed with %s", strerror(errno));

    // mmap the anonymous file twice
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_SHARED, fileDescriptor, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_SHARED, fileDescriptor, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    // reuse the two objects in the middle
    testRangeShared(mapping1, mapping2, testSize, 0, testSize, ZERO);

    int unmapResult = munmap(mapping1, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
    unmapResult = munmap(mapping2, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_memfd);
ATF_TC_BODY(madvise__reuse_memfd, tc){

    const size_t pageSize = getpagesize();
    const size_t testSize = 4*pageSize;

    // create file that is backed by anonymous memory to map multiple instances of the same anon memory
    int fileDescriptor = memfd_create("anonFile", 0);
    ATF_REQUIRE_MSG(fileDescriptor != -1, "memfd_create failed with %s", strerror(errno));
    // set the size of the file
    int truncateResult = ftruncate(fileDescriptor, testSize);
    ATF_REQUIRE_EQ_MSG(0, truncateResult, "ftruncate failed with %s", strerror(errno));

    // mmap the anonymous file twice
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_SHARED, fileDescriptor, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_SHARED, fileDescriptor, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    // reuse the two objects in the middle
    testRangeShared(mapping1, mapping2, testSize, 0, testSize, RELEASE);

    int unmapResult = munmap(mapping1, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
    unmapResult = munmap(mapping2, testSize);
    ATF_REQUIRE_EQ_MSG(0, unmapResult, "munmap failed with %s", strerror(errno));
}

ATF_TC_WITHOUT_HEAD(madvise__zero_thread);
ATF_TC_BODY(madvise__zero_thread, tc){
    // map the space that will be tested
    const size_t pageSize = getpagesize();
    const size_t halfSize = 2*pageSize;
    const size_t testSize = 2*halfSize;
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    testThreaded(mapping1, testSize, ACTIVE, ZERO);
    testThreaded(mapping2, testSize, ZERO, ACTIVE);
} 

ATF_TC_WITHOUT_HEAD(madvise__reuse_thread);
ATF_TC_BODY(madvise__reuse_thread, tc){
    // map the space that will be tested
    const size_t pageSize = getpagesize();
    const size_t halfSize = 2*pageSize;
    const size_t testSize = 2*halfSize;
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    testThreaded(mapping1, testSize, ACTIVE | RELEASE, RELEASE);
    testThreaded(mapping2, testSize, RELEASE, ACTIVE | RELEASE);
}

ATF_TC_WITHOUT_HEAD(madvise__zero_fork_private);
ATF_TC_BODY(madvise__zero_fork_private, tc){
    // map the space that will be tested
    const size_t pageSize = getpagesize();
    const size_t testSize = 4*pageSize;
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    setUpProcessSignalHandling();

    testForked(mapping1, testSize, ACTIVE, ZERO);
    testForked(mapping2, testSize, ZERO, ACTIVE);
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_fork_private);
ATF_TC_BODY(madvise__reuse_fork_private, tc){
    // map the space that will be tested
    const size_t pageSize = getpagesize();
    const size_t halfSize = 2*pageSize;
    const size_t testSize = 2*halfSize;
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    setUpProcessSignalHandling();

    testForked(mapping1, testSize, ACTIVE | RELEASE, RELEASE);
    testForked(mapping2, testSize, RELEASE, ACTIVE | RELEASE);
}

ATF_TC_WITHOUT_HEAD(madvise__zero_fork_shared);
ATF_TC_BODY(madvise__zero_fork_shared, tc){
    // map the space that will be tested
    const size_t pageSize = getpagesize();
    const size_t halfSize = 2*pageSize;
    const size_t testSize = 2*halfSize;
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    setUpProcessSignalHandling();

    testForked(mapping1, testSize, ACTIVE | SHARED, SHARED);
    testForked(mapping2, testSize, SHARED, ACTIVE | SHARED);
}

ATF_TC_WITHOUT_HEAD(madvise__reuse_fork_shared);
ATF_TC_BODY(madvise__reuse_fork_shared, tc){
    // map the space that will be tested
    const size_t pageSize = getpagesize();
    const size_t halfSize = 2*pageSize;
    const size_t testSize = 2*halfSize;
    void* mapping1 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    ATF_REQUIRE_MSG(mapping1 != MAP_FAILED, "mmap failed with %s", strerror(errno));
    void* mapping2 = mmap(NULL, testSize, PROT_READ | PROT_WRITE, MAP_ANON | MAP_SHARED, -1, 0);
    ATF_REQUIRE_MSG(mapping2 != MAP_FAILED, "mmap failed with %s", strerror(errno));

    setUpProcessSignalHandling();

    testForked(mapping1, testSize, ACTIVE | SHARED | RELEASE, SHARED | RELEASE);
    testForked(mapping2, testSize, SHARED | RELEASE, ACTIVE | SHARED | RELEASE);
}

ATF_TP_ADD_TCS(tp)
{
    // tests for zero
    // tests for checking that all pages in range are affected
    ATF_TP_ADD_TC(tp, madvise__zero_scaling);
    
    // tests for checking range boundries
    ATF_TP_ADD_TC(tp, madvise__zero_exact_object);
    ATF_TP_ADD_TC(tp, madvise__zero_inside_object);
    ATF_TP_ADD_TC(tp, madvise__zero_accross_object);
    ATF_TP_ADD_TC(tp, madvise__zero_exact_object_untouched);
    ATF_TP_ADD_TC(tp, madvise__zero_inside_object_untouched);
    ATF_TP_ADD_TC(tp, madvise__zero_accross_object_untouched);

    // tests with multiple mappings
    ATF_TP_ADD_TC(tp, madvise__zero_memfd);
    ATF_TP_ADD_TC(tp, madvise__zero_thread);
    ATF_TP_ADD_TC(tp, madvise__zero_fork_private);
    ATF_TP_ADD_TC(tp, madvise__zero_fork_shared);

    // test for realease
    // tests for checking that all pages in range are affected
    ATF_TP_ADD_TC(tp, madvise__reuse_scaling);

    // tests for checking range boundries
    ATF_TP_ADD_TC(tp, madvise__reuse_exact_object);
    ATF_TP_ADD_TC(tp, madvise__reuse_inside_object);
    ATF_TP_ADD_TC(tp, madvise__reuse_accross_object);
    ATF_TP_ADD_TC(tp, madvise__reuse_exact_object_untouched);
    ATF_TP_ADD_TC(tp, madvise__reuse_inside_object_untouched);
    ATF_TP_ADD_TC(tp, madvise__reuse_accross_object_untouched);

    // tests with multiple mappings
    ATF_TP_ADD_TC(tp, madvise__reuse_memfd);
    ATF_TP_ADD_TC(tp, madvise__reuse_thread);
    ATF_TP_ADD_TC(tp, madvise__reuse_fork_private);
    ATF_TP_ADD_TC(tp, madvise__reuse_fork_shared);

    return atf_no_error();
}