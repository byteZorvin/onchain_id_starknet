use core::num::traits::Zero;
use starknet::storage::{
    StoragePath, StoragePointerReadAccess, StoragePointerWriteAccess, Mutable, Map, StoragePathEntry
};

#[starknet::storage_node]
pub struct StorageArray {
    vec: Map<u64, felt252>,
    len: u64
}

pub trait StorageArrayTrait<T> {
    type ElementType;
    fn get(self: T, index: u64) -> Option<StoragePath<Self::ElementType>>;
    fn at(self: T, index: u64) -> StoragePath<Self::ElementType>;
    fn len(self: T) -> u64;
}

pub impl StorageArrayImpl of StorageArrayTrait<StoragePath<StorageArray>> {
    type ElementType = felt252;
    fn get(self: StoragePath<StorageArray>, index: u64) -> Option<StoragePath<Self::ElementType>> {
        let vec_len = self.len.read();
        if index < vec_len {
            return Option::Some(self.vec.entry(index));
        }
        Option::None
    }

    fn at(self: StoragePath<StorageArray>, index: u64) -> StoragePath<Self::ElementType> {
        assert!(index < self.len.read(), "Index out of bounds");
        self.vec.entry(index)
    }

    fn len(self: StoragePath<StorageArray>) -> u64 {
        self.len.read()
    }
}

pub trait MutableStorageArrayTrait<T> {
    type ElementType;
    fn get(self: T, index: u64) -> Option<StoragePath<Mutable<Self::ElementType>>>;
    fn at(self: T, index: u64) -> StoragePath<Mutable<Self::ElementType>>;
    fn len(self: T) -> u64;
    fn append(self: T) -> StoragePath<Mutable<Self::ElementType>>;
    fn delete(self: T, index: u64);
}

pub impl MutableStorageArrayImpl of MutableStorageArrayTrait<StoragePath<Mutable<StorageArray>>> {
    type ElementType = felt252;
    fn delete(self: StoragePath<Mutable<StorageArray>>, index: u64) {
        let len = self.len.read();
        assert!(index < len, "Index out of bounds");
        let last_element_storage_path = self.vec.entry(len - 1);
        if index != len - 1 {
            let last_element = last_element_storage_path.read();
            self.vec.entry(index).write(last_element);
        }
        last_element_storage_path.write(Zero::zero());
        self.len.write(len - 1);
    }

    fn append(self: StoragePath<Mutable<StorageArray>>) -> StoragePath<Mutable<Self::ElementType>> {
        let len = self.len.read();
        self.len.write(len + 1);
        self.vec.entry(len)
    }

    fn get(
        self: StoragePath<Mutable<StorageArray>>, index: u64
    ) -> Option<StoragePath<Mutable<Self::ElementType>>> {
        let vec_len = self.len.read();
        if index < vec_len {
            return Option::Some(self.vec.entry(index));
        }
        Option::None
    }

    fn at(
        self: StoragePath<Mutable<StorageArray>>, index: u64
    ) -> StoragePath<Mutable<Self::ElementType>> {
        assert!(index < self.len.read(), "Index out of bounds");
        self.vec.entry(index)
    }

    fn len(self: StoragePath<Mutable<StorageArray>>) -> u64 {
        self.len.read()
    }
}

pub impl StorageArrayIndexView of core::ops::IndexView<StoragePath<StorageArray>, u64> {
    type Target = StoragePath<felt252>;
    fn index(self: @StoragePath<StorageArray>, index: u64) -> Self::Target {
        (*self).at(index)
    }
}

pub impl MutableStorageArrayIndexView of core::ops::IndexView<
    StoragePath<Mutable<StorageArray>>, u64
> {
    type Target = StoragePath<Mutable<felt252>>;
    fn index(self: @StoragePath<Mutable<StorageArray>>, index: u64) -> Self::Target {
        (*self).at(index)
    }
}

pub impl Felt252VecToFelt252Array of Into<StoragePath<StorageArray>, Array<felt252>> {
    fn into(self: StoragePath<StorageArray>) -> Array<felt252> {
        let mut array = array![];
        for i in 0..self.len() {
            array.append(self[i].read());
        };
        array
    }
}
