/* This common_kern_user.h is used by kernel side BPF-progs and
 * userspace programs, for sharing common struct's and DEFINEs.
 */
#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

#define no_of_IOT 500
#define CRP_PER_IOT 500

struct crPair {
  uint32_t ch1;
  uint64_t resp1;
  uint32_t ch2;
  uint64_t resp2;
};

struct UAV_CR_DB {
struct crPair crp[CRP_PER_IOT];
};


#endif /* __COMMON_KERN_USER_H */
