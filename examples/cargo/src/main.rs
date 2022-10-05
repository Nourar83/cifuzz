mod explore_me;
use explore_me::explore_me;

mod my_fuzz_test;

fn main() {
    explore_me(1, 1, "A");
    explore_me(2147483647, 1, "A");
    explore_me(2147483647, 2147483647, "A");
    explore_me(2000000000, 2000000123, "A");
    explore_me(2000000000, 2000000123, "FUZZING");
}
