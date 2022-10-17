// TODO CopyRight thing
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <vm/vm_param.h>

#include <atf-c.h>

static void checkForSwapEnable(void){
    int error;
    int value;
    size_t valueSize = sizeof(value);
    int mi[2] = {CTL_VM, VM_SWAPPING_ENABLED};
    error = sysctl(mi, 2, &value, &valueSize, NULL, 0);
    ATF_REQUIRE_EQ_MSG(0, error, "Failed to read sysctl to determine if swapping is on");
    ATF_REQUIRE_EQ_MSG(4, valueSize, "Sysctl returned wrong size");
    if(value != 1){
        atf_tc_skip("Swapping currently disabled, skipping swapper tests");
    }
}

static size_t getRamSize(void){
    int error;
    size_t value;
    size_t valueSize = sizeof(value);
    int mi[2] = {CTL_HW, HW_PHYSMEM};
    error = sysctl(mi, 2, &value, &valueSize, NULL, 0);
    ATF_REQUIRE_EQ_MSG(0, error, "Failed to read sysctl to determine if swapping is on");
    ATF_REQUIRE_EQ_MSG(sizeof(value), valueSize, "Sysctl returned wrong size");
    return value;
}

ATF_TC_WITHOUT_HEAD(swap_pager__basic);
ATF_TC_BODY(swap_pager__basic, tc){
    checkForSwapEnable();
    // get RAM size and round up to page alligment
    size_t pageSize = getpagesize();
    size_t ramSize = getRamSize();
    // make sure we ask for more pages than are available
    size_t pageNumber = (ramSize + pageSize - 1) / pageSize + 1024;
    size_t entriesPerPage = pageSize / sizeof(unsigned long);
    size_t mapSize = pageNumber*pageSize;
    // allocate map larger than ram size
    unsigned long* memory = mmap(NULL, mapSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(memory != MAP_FAILED, "Failed to mmap %zu bytes of memory", mapSize);
    // write to all of it once
    for(size_t pageIndex = 0, entryIndex = 0; pageIndex < pageNumber; pageIndex++){
        memory[pageIndex*entriesPerPage + entryIndex] = pageIndex*entriesPerPage + entryIndex;
        entryIndex = (entryIndex + 1) % entriesPerPage;
    }
    // read it back to check it is still there.
    // some of them need to have been paged out, in the mean time
    // so if all are correct the pager basics are working
    for(size_t pageIndex = 0, entryIndex = 0; pageIndex < pageNumber; pageIndex++){
        ATF_CHECK_EQ(pageIndex*entriesPerPage + entryIndex,
            memory[pageIndex*entriesPerPage + entryIndex]);
        entryIndex = (entryIndex + 1) % entriesPerPage;
    }
}

ATF_TC_WITHOUT_HEAD(swap_pager__basic_tags);
ATF_TC_BODY(swap_pager__basic_tags, tc){
    checkForSwapEnable();
    // get RAM size and round up to page alligment
    size_t pageSize = getpagesize();
    size_t ramSize = getRamSize();
    // make sure we ask for more pages than are available
    size_t pageNumber = (ramSize + pageSize - 1) / pageSize + 1024;
    size_t entriesPerPage = pageSize / sizeof(void*);
    size_t mapSize = pageNumber*pageSize;
    // allocate map larger than ram size
    void** memory = mmap(NULL, mapSize, PROT_READ | PROT_WRITE, MAP_ANON, -1, 0);
    ATF_REQUIRE_MSG(memory != MAP_FAILED, "Failed to mmap %zu bytes of memory", mapSize);
    // write to all of it once
    for(size_t pageIndex = 0, entryIndex = 0; pageIndex < pageNumber; pageIndex++){
        memory[pageIndex*entriesPerPage + entryIndex] = memory + pageIndex*entriesPerPage + entryIndex;
        entryIndex = (entryIndex + 1) % entriesPerPage;
    }
    // read it back to check it is still there.
    // some of them need to have been paged out, in the mean time
    // so if all are correct the pager basics are working
    for(size_t pageIndex = 0, entryIndex = 0; pageIndex < pageNumber; pageIndex++){
        ATF_CHECK_EQ(memory + pageIndex*entriesPerPage + entryIndex,
            memory[pageIndex*entriesPerPage + entryIndex]);
        entryIndex = (entryIndex + 1) % entriesPerPage;
    }
}

ATF_TP_ADD_TCS(tp)
{
    // tests basic swap functionallity
    ATF_TP_ADD_TC(tp, swap_pager__basic);
    ATF_TP_ADD_TC(tp, swap_pager__basic_tags);

    return atf_no_error();
}