# $FreeBSD$

PACKAGE=	tests

TESTSDIR=	${TESTSBASE}/sys/vm

LIBADD+=	pthread procstat

ATF_TESTS_C+=	madvise_test \
		mlock_test \
		mmap_test \
		page_fault_signal \
		shared_shadow_inval_test \
		swap_pager_test

.include <bsd.test.mk>