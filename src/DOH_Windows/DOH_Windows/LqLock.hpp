#pragma once
/*
* Lanq(Lan Quick)
* Solodov A. N. (hotSAN)
* 2016
*   LqLocker - Block shared object for read or write.
*/

#include <atomic>

#pragma pack(push)
#pragma pack(1)

/*
*   Read/write locker.
*/

template<typename TypeFlag = unsigned>
class LqLocker {
    std::atomic<TypeFlag> Locker;
public:
    inline LqLocker(): Locker(((TypeFlag)1)) {}

    inline bool TryLockRead() {
        TypeFlag v = Locker;
        if(v != ((TypeFlag)0))
            return Locker.compare_exchange_strong(v, v + ((TypeFlag)1));
        return false;
    }
    inline void LockRead() { for(TypeFlag v; ((v = Locker) == ((TypeFlag)0)) || !Locker.compare_exchange_strong(v, v + ((TypeFlag)1)); ); }
    inline void LockReadYield() { for(TypeFlag v; ((v = Locker) == ((TypeFlag)0)) || !Locker.compare_exchange_strong(v, v + ((TypeFlag)1)); LqThreadYield()); }
    inline void UnlockRead() { --Locker; }

    inline bool TryLockWrite() {
        TypeFlag v = ((TypeFlag)1);
        return Locker.compare_exchange_strong(v, ((TypeFlag)0));
    }
    inline void LockWrite() { for(TypeFlag v = ((TypeFlag)1); !Locker.compare_exchange_strong(v, ((TypeFlag)0)); v = ((TypeFlag)1)); }
    inline void LockWriteYield() { for(TypeFlag v = ((TypeFlag)1); !Locker.compare_exchange_strong(v, ((TypeFlag)0)); LqThreadYield(), v = ((TypeFlag)1)); }
    inline void UnlockWrite() { Locker = ((TypeFlag)1); }
    inline void RelockFromWriteToRead() { Locker = ((TypeFlag)2); }

    /* Use only thread owner*/
    inline bool IsLockRead() const { return Locker > ((TypeFlag)1); }
    inline bool IsLockWrite() const { return Locker == ((TypeFlag)0); }
    /* Common unlock. Use for read/write lock */
    inline void Unlock() {
        if(IsLockRead())
            UnlockRead();
        else if(IsLockWrite())
            UnlockWrite();
    }
};

#pragma pack(pop)