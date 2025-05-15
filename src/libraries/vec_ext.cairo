use starknet::storage::VecTrait;
use starknet::storage::{
    Mutable, MutableVecTrait, StoragePath, StoragePointerWriteAccess,
    StorableStoragePointerReadAccess, Vec, PendingStoragePath,
};
use starknet::syscalls::storage_write_syscall;
use starknet::SyscallResultTrait;

/// Trait that encapsulates deletion logic from arbitrary index.
///
/// If element is not at the end of list swaps the element at last index to target and pops the last
/// element.
/// Does not preserve the order of the list.
pub trait VecDeleteTrait<T> {
    type ElementType;
    fn pop_swap(self: T, index: u64, base_address: felt252);
}

pub impl VecDeleteImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecDeleteTrait<StoragePath<Mutable<Vec<T>>>> {
    type ElementType = T;
    fn pop_swap(self: StoragePath<Mutable<Vec<T>>>, index: u64, base_address: felt252) {
        let len = self.len();
        assert!(index < len, "Index out of bounds");
        if index != len - 1 {
            let last_element = self.pop(base_address);
            self.at(index).write(last_element);
        } else {
            self.pop(base_address);
        }
    }
}

/// Trait that converts `Vec` into an `Array`.
pub trait VecToArrayTrait<T> {
    type ElementType;

    fn to_array(self: T) -> Array<Self::ElementType>;
}

pub trait VecPopTrait<T> {
    type ElementType;
    fn pop(self: T, base_address: felt252) -> Self::ElementType;
}

/// Trait that encapsulates the logic that clears the all elements in a `Vec`.
pub trait VecClearTrait<T> {
    fn clear(self: T, base_address: felt252);
}

impl VecClearImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecClearTrait<StoragePath<Mutable<Vec<T>>>> {
    fn clear(self: StoragePath<Mutable<Vec<T>>>, base_address: felt252) {
        let len = self.len();
        for _ in 0..len {
            self.pop(base_address);
        }
    }
}


impl VecPopTraitImpl<T, +starknet::Store<T>> of VecPopTrait<StoragePath<Mutable<Vec<T>>>> {
    type ElementType = T;

    fn pop(self: StoragePath<Mutable<Vec<T>>>, base_address: felt252) -> Self::ElementType {
        let len = self.len();
        assert!(len > 0, "Vector is empty");

        let new_len = (len - 1).into();
        let res = storage_write_syscall(0, base_address.try_into().unwrap(), new_len);
        SyscallResultTrait::unwrap_syscall(res);

        let last_element = self.at(len - 1).read();
        last_element
    }
}

impl VecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<StoragePath<Vec<T>>> {
    type ElementType = T;
    fn to_array(self: StoragePath<Vec<T>>) -> Array<Self::ElementType> {
        let mut arr = array![];
        let len = self.len();
        for i in 0..len {
            arr.append(self.at(i).read());
        };
        return arr;
    }
}

pub impl MutableVecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<StoragePath<Mutable<Vec<T>>>> {
    type ElementType = T;
    fn to_array(self: StoragePath<Mutable<Vec<T>>>) -> Array<Self::ElementType> {
        let mut arr = array![];
        let len = self.len();
        for i in 0..len {
            arr.append(self.at(i).read());
        };
        return arr;
    }
}


impl PathableVecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<PendingStoragePath<Vec<T>>> {
    type ElementType = T;
    fn to_array(self: PendingStoragePath<Vec<T>>) -> Array<Self::ElementType> {
        let mut arr = array![];
        let len = self.len();
        for i in 0..len {
            arr.append(self.at(i).read());
        };
        return arr;
    }
}

impl PathableMutableVecToArrayImpl<
    T, +Drop<T>, +Copy<T>, +starknet::Store<T>,
> of VecToArrayTrait<PendingStoragePath<Mutable<Vec<T>>>> {
    type ElementType = T;
    fn to_array(self: PendingStoragePath<Mutable<Vec<T>>>) -> Array<Self::ElementType> {
        let mut arr = array![];
        let len = self.len();
        for i in 0..len {
            arr.append(self.at(i).read());
        };
        return arr;
    }
}

