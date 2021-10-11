/*
* Lanq(Lan Quick)
* Solodov A. N. (hotSAN)
* 2016
* LqFastAlloc - Fast memory allocator.
*/


#ifndef __LQ_ALLOC_H_1_
#define __LQ_ALLOC_H_1_

#include <malloc.h>
#include <type_traits>
#include <string.h>
#include "LqLock.hpp"



#if /*!defined(_DEBUG) &&*/ defined(LQPLATFORM_WINDOWS)
#include <Windows.h>
#define LqMemAlloc(size) HeapAlloc(GetProcessHeap(), 0, (size))
#define LqMemFree(pointer) HeapFree(GetProcessHeap(), 0, (pointer))
#define LqMemRealloc(pointer, size) (((pointer) == NULL)? LqMemAlloc(size): (((size) == 0)? (LqMemFree(pointer), NULL): HeapReAlloc(GetProcessHeap(), 0, (pointer), (size))))
#else
#define LqMemAlloc(size) malloc(size)
#define LqMemRealloc(pointer, size) realloc(pointer, size)
#define LqMemFree(pointer) free(pointer)
#endif

#pragma pack(push)
#pragma pack(1)


template<size_t SizeElem>
struct __LqFastAllocHelper {
    void*                   StartElement;
    size_t                  Count;
    size_t                  SizeList;
    mutable LqLocker<uintptr_t> Locker;

    __LqFastAllocHelper(): StartElement(nullptr), SizeList(128), Count(0) {}
    ~__LqFastAllocHelper() { for(void* Ptr = StartElement, *Next; Ptr != nullptr; Ptr = Next) Next = *(void**)Ptr, LqMemFree(Ptr); }

    void* Alloc() {
        Locker.LockWrite();
        if(StartElement != nullptr) {
            void* Ret = StartElement;
            StartElement = *(void**)Ret;
            Count--;
            Locker.UnlockWrite();
            return Ret;
        } else {
            Locker.UnlockWrite();
            return LqMemAlloc(SizeElem);
        }
    }
    void Free(void* Data) {
        Locker.LockWrite();
        if(Count >= SizeList) {
            Locker.UnlockWrite();
            LqMemFree(Data);
        } else {
            *(void**)Data = StartElement;
            StartElement = Data;
            Count++;
            Locker.UnlockWrite();
        }
    }
    void ClearList() {
        Locker.LockWrite();
        for(void* Ptr = StartElement, *Next; Ptr != nullptr; Ptr = Next)
            Next = *(void**)Ptr, LqMemFree(Ptr);
        Count = 0;
        Locker.UnlockWrite();
    }
    inline void SetMaxCount(size_t NewVal) { SizeList = NewVal; }
};

template<size_t SizeElem>
struct __LqFastAllocHelper2 {
    static __LqFastAllocHelper<SizeElem> Elem;
};

class LqFastAlloc {
    template<typename Type, size_t Size>
    struct StructSize { Type v[Size]; };
public:
    template<typename Type, typename... _Args>
    inline static typename std::enable_if<!std::is_pod<Type>::value || (sizeof...(_Args) > 0), Type*>::type New(_Args&&... _Ax);

    template<typename Type, typename... _Args>
    inline static typename std::enable_if<std::is_pod<Type>::value && (sizeof...(_Args) == 0), Type*>::type New(_Args&&... _Ax);

    template<typename Type>
    static Type* ReallocCount(Type* Prev, size_t PrevCount, size_t NewCount);

    /*
    Delete memory region with adding in stack regions. Late, this region takes from stack.
    */
    template<typename Type>
    inline static typename std::enable_if<!std::is_same<Type, void>::value && !std::is_pod<Type>::value>::type Delete(Type* Val);

    template<typename Type>
    inline static typename std::enable_if<!std::is_same<Type, void>::value && std::is_pod<Type>::value>::type Delete(Type* Val);

    /*
    Delete memory region without adding in stack.
    !!! Caution! In this case function not call destructor for type. !!!
    */
    inline static void JustDelete(void* Val) { LqMemFree(Val); }

    template<typename Type>
    inline static void Clear();

    /*
    * Set max count for memory region stack.
    */
    template<typename Type>
    inline static void SetMaxCount(size_t NewSize);

    template<typename Type>
    inline static size_t GetMaxCount();
};
#pragma pack(pop)

#endif

#if defined(__METHOD_DECLS__) && !defined(__LQ_ALLOC_H_2_)
#define __LQ_ALLOC_H_2_

template<typename Type, typename... _Args>
inline typename std::enable_if<!std::is_pod<Type>::value || (sizeof...(_Args) > 0), Type*>::type LqFastAlloc::New(_Args&&... _Ax) {
    return new(__LqFastAllocHelper2<(sizeof(Type) > sizeof(void*))? sizeof(Type): sizeof(void*)>::Elem.Alloc()) Type(_Ax...);
}

template<typename Type, typename... _Args>
inline typename std::enable_if<std::is_pod<Type>::value && (sizeof...(_Args) == 0), Type*>::type LqFastAlloc::New(_Args&&... _Ax) {
    return (Type*)__LqFastAllocHelper2<(sizeof(Type) > sizeof(void*)) ? sizeof(Type) : sizeof(void*)>::Elem.Alloc();
}

template<typename Type>
static Type* LqFastAlloc::ReallocCount(Type* Prev, size_t PrevCount, size_t NewCount) {
    Type* NewVal = nullptr;

    switch(NewCount) {
        case 0: lblExit:
    switch(PrevCount) {
        case 0: break;
        case 1: LqFastAlloc::Delete((StructSize<Type, 1>*)Prev);  break;
        case 2: LqFastAlloc::Delete((StructSize<Type, 2>*)Prev);  break;
        case 3: LqFastAlloc::Delete((StructSize<Type, 3>*)Prev);  break;
        case 4: LqFastAlloc::Delete((StructSize<Type, 4>*)Prev);  break;
        case 5: LqFastAlloc::Delete((StructSize<Type, 5>*)Prev);  break;
        case 6: LqFastAlloc::Delete((StructSize<Type, 6>*)Prev);  break;
        case 7: LqFastAlloc::Delete((StructSize<Type, 7>*)Prev);  break;
        case 8: LqFastAlloc::Delete((StructSize<Type, 8>*)Prev);  break;
        default: LqMemFree(Prev); break;
    }
    return NewVal;
        case 1: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 1>>(); break;
        case 2: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 2>>(); break;
        case 3: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 3>>(); break;
        case 4: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 4>>(); break;
        case 5: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 5>>(); break;
        case 6: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 6>>(); break;
        case 7: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 7>>(); break;
        case 8: NewVal = (Type*)LqFastAlloc::New<StructSize<Type, 8>>(); break;
        default: NewVal = (Type*)LqMemAlloc(NewCount * sizeof(Type));
    }
    if(NewVal == nullptr)
        return nullptr;
    memcpy(NewVal, Prev, lq_min(PrevCount, NewCount) * sizeof(Type));
    goto lblExit;
}
/*
Delete memory region with adding in stack regions. Late, this region takes from stack.
*/
template<typename Type>
inline typename std::enable_if<!std::is_same<Type, void>::value && !std::is_pod<Type>::value>::type LqFastAlloc::Delete(Type* Val) {
    Val->~Type();
    __LqFastAllocHelper2<(sizeof(Type) > sizeof(void*)) ? sizeof(Type) : sizeof(void*)>::Elem.Free(Val);
}

template<typename Type>
inline typename std::enable_if<!std::is_same<Type, void>::value && std::is_pod<Type>::value>::type LqFastAlloc::Delete(Type* Val) {
    __LqFastAllocHelper2<(sizeof(Type) > sizeof(void*)) ? sizeof(Type) : sizeof(void*)>::Elem.Free(Val);
}

template<typename Type>
inline void LqFastAlloc::Clear() {
    __LqFastAllocHelper2<(sizeof(Type) > sizeof(void*)) ? sizeof(Type) : sizeof(void*)>::Elem.ClearList();
}

template<typename Type>
inline void LqFastAlloc::SetMaxCount(size_t NewSize) {
    __LqFastAllocHelper2<(sizeof(Type) > sizeof(void*)) ? sizeof(Type) : sizeof(void*)>::Elem.SetMaxCount(NewSize);
}

template<typename Type>
inline size_t LqFastAlloc::GetMaxCount() {
    return __LqFastAllocHelper2<(sizeof(Type) > sizeof(void*)) ? sizeof(Type) : sizeof(void*)>::Elem.SizeList;
}

template<size_t SizeElem>
__LqFastAllocHelper<SizeElem> __LqFastAllocHelper2<SizeElem>::Elem;

#endif

