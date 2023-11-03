/// Like `@sizeOf()` without padding.
pub fn sizeOfUnpad(comptime T: type) usize {
    const size_t = @bitSizeOf(T);
    const size_u8 = @bitSizeOf(u8);
    return size_t / size_u8 + size_t % size_u8;
}
